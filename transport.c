/*
 * $Id:$
 *
 * Copyright (C) 2005 Nils Ohlmeier
 *
 * This file belongs to sipsak, a free sip testing tool.
 *
 * sipsak is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * sipsak is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include "sipsak.h"

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif /* TIME_WITH_SYS_TIME */
#ifdef HAVE_UNISTD_H
# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif
# include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_SYS_POLL_H
# include <sys/poll.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#include "transport.h"
#include "shoot.h"

#ifdef RAW_SUPPORT
# ifdef HAVE_NETINET_IN_SYSTM_H 
#  include <netinet/in_systm.h>
# endif
# ifdef HAVE_NETINET_IP_H
#  include <netinet/ip.h>
# endif
# ifdef HAVE_NETINET_IP_ICMP_H
#  include <netinet/ip_icmp.h>
# endif
# ifdef HAVE_NETINET_UDP_H
#  define __FAVOR_BSD
#  include <netinet/udp.h>
# endif
#endif /* RAW_SUPPORT */

#ifdef WITH_TLS_TRANSP
# ifdef USE_GNUTLS
#  include <stdio.h>
#  include <stdlib.h>
#  include <string.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <gnutls/gnutls.h>
#  include <gnutls/x509.h>

   // needed for anonymous auth
   //const int kx_prio[] = { GNUTLS_KX_ANON_DH, 0 };
   const int cert_type_priority[2] = { GNUTLS_CRT_X509, 0 };
# else
#  ifdef USE_OPENSSL
#   define _BSD_SOURCE 1
#   include <assert.h>
#   include <errno.h>
#   include <limits.h>
#   include <stdio.h>
#   include <stdlib.h>
#   include <string.h>
#   include <time.h>
#   include <ctype.h>
#   include <openssl/bio.h>
#   include <openssl/crypto.h>
#   include <openssl/evp.h>
#   include <openssl/x509.h>
#   include <openssl/x509v3.h>
#   include <openssl/ssl.h>
#   include <openssl/engine.h>
#   include <openssl/err.h>
#   include <openssl/rand.h>
#  endif
# endif
#endif /* WITH_TLS_TRANSP */

#include "exit_code.h"
#include "helper.h"
#include "header_f.h"

#ifdef RAW_SUPPORT
int rawsock;
#endif

#ifdef WITH_TLS_TRANSP
# ifdef USE_GNUTLS
void check_alert(gnutls_session_t session, int ret) {
	int last_alert;

	if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED ||
			ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
		last_alert = gnutls_alert_get(session);
		printf("Received TLS alert: '%d': %s\n", last_alert,
			gnutls_alert_get_name(last_alert));
	}
}

/* all the available CRLs */
gnutls_x509_crl_t *crl_list;
int crl_list_size;

/* all the available  trusted CAs */
gnutls_x509_crt_t *ca_list;
int ca_list_size;

/* verifies a certificate against an other certificate which is supposed to 
 * be it's issuer. Also checks the crl_list of the certificate is revoked.
 */
static void verify_cert2(gnutls_x509_crt_t crt, gnutls_x509_crt_t issuer,
			gnutls_x509_crl_t *crl_list, int crl_list_size) {
	unsigned int output;
	time_t now = time(0);
	size_t name_size;
	char name[64];

	/* print information about the certificates to be checked */
	name_size = sizeof(name);
	gnutls_x509_crt_get_dn(crt, name, &name_size);

	printf("Certificate: %s\n", name);

	name_size = sizeof(name);
	gnutls_x509_crt_get_issuer_dn(crt, name, &name_size);

	printf("Issued by: %s\n", name);

	/* Get the DN of the issuer cert. */
	name_size = sizeof(name);
	gnutls_x509_crt_get_dn(issuer, name, &name_size);

	printf("Checking against: %s\n", name);

	/* Do the actual verification */
	gnutls_x509_crt_verify(crt, &issuer, 1, 0, &output);

	if (output & GNUTLS_CERT_INVALID) {
		printf("Certificate not trusted!!!");
		if (output & GNUTLS_CERT_SIGNER_NOT_FOUND) {
			printf(": no issuer was found\n");
		}
		if (output & GNUTLS_CERT_SIGNER_NOT_CA) {
			printf(": issuer is not a CA\n");
		}
	}
	else {
		printf("Certificate trusted'n");
	}

	/* Now check the expiration dates */
	if (gnutls_x509_crt_get_activation_time(crt) > now) {
		printf("Certificate not yet activated!\n");
	}
	if (gnutls_x509_crt_get_expiration_time(crt) < now) {
		printf("Certificate expired!\n");
	}
	/* Check if the certificate is revoked */
	if (gnutls_x509_crt_check_revocation(crt, crl_list, crl_list_size) == 1) {
		printf("Certificate is revoked!\n");
	}
}

/* Verifies a certificate against our trusted CA list. Also checks the crl_list
 * if the certificate is revoked
 */
static void verify_last_cert(gnutls_x509_crt_t crt, gnutls_x509_crt_t *ca_list,
			int ca_list_size, gnutls_x509_crl_t *crl_list, int crl_list_size) {
	unsigned int output;
	time_t now = time(0);
	size_t name_size;
	char name[64];

	/* Print information about the certificates to be checked */
	name_size = sizeof(name);
	gnutls_x509_crt_get_dn(crt, name, &name_size);
	printf("Certificate: %s\n", name);

	name_size = sizeof(name);
	gnutls_x509_crt_get_issuer_dn(crt, name, &name_size);
	printf("Issued by: %s\n", name);

	/* Do the actual verification */
	gnutls_x509_crt_verify(crt, ca_list, ca_list_size, 
			GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT, &output);
	if (output & GNUTLS_CERT_INVALID) {
		printf("Certificate not truested!\n");
		if (output & GNUTLS_CERT_SIGNER_NOT_CA) {
			printf(": Issuer is not a CA\n");
		}
	}
	else {
		printf("Certificate trusted\n");
	}

	/* Now check the expiration dates */
	if (gnutls_x509_crt_get_activation_time(crt) > now) {
		printf("Certificate now yet activated!\n");
	}
	if (gnutls_x509_crt_get_expiration_time(crt) < now) {
		printf("Certificate expired!\n");
	}
	/* Check of the vertificate is revoked */
	if (gnutls_x509_crt_check_revocation(crt, crl_list, crl_list_size) == 1) {
		printf("Certificate is revoked!\n");
	}
}

/* this function will try yo verify the peer's certificate chain, ans
 * also check if the hostname matches, and the activation and expiration dates.
 */
void verify_certificate_chain(gnutls_session_t session, const char *hostname,
			const gnutls_datum_t *cert_chain, int cert_chain_length) {
	int i;
	gnutls_x509_crt_t *cert;

	cert = malloc(sizeof(*cert) * cert_chain_length);
	if (!cert) {
		printf("gnutla: failed to allocate memory for cert chain verification'n");
		return;
	}

	/* import all the certificates in the chain to native certificate format */
	for (i = 0; i < cert_chain_length; i++) {
		gnutls_x509_crt_init(&cert[i]);
		gnutls_x509_crt_import(cert[i], &cert_chain[i], GNUTLS_X509_FMT_DER);
	}

	/* if the last certificate in the chain is seld signed ignore it.
	 * that is because we want to check against our trusted certificate list
	 */
	if (gnutls_x509_crt_check_issuer(cert[cert_chain_length - 1],
				cert[cert_chain_length -1]) > 0 && cert_chain_length > 0) {
		cert_chain_length--;
	}
	/* now verify the certificates against ther issuers in the chain */
	for (i = 1; i < cert_chain_length; i++) {
		verify_cert2(cert[i - 1], cert[i], crl_list, crl_list_size);
	}
	/* here we must verify the last certificate in the chain against our 
	 * trusted CA list
	 */
	verify_last_cert(cert[cert_chain_length - 1], ca_list, ca_list_size, 
			crl_list, crl_list_size);
	/* check if the name in the first certificate matches our destination */
	if (!gnutls_x509_crt_check_hostname(cert[0], hostname)) {
		printf("The certificate's owner does not match hostname '%s'\n", 
				hostname);
	}

	for (i = 0; i < cert_chain_length; i++) {
		gnutls_x509_crt_deinit(cert[i]);
	}
	return;
}

int verify_certificate_simple(gnutls_session_t session, const char *hostname) {
	unsigned int status, cert_list_size;
	const gnutls_datum_t *cert_list;
	int ret;
	gnutls_x509_crt_t cert;

	// this verification function usese the trusted CAs in the credentials
	// stucture. so you must have installed on or more CA certificates.
	ret = gnutls_certificate_verify_peers2(session, &status);

	if (ret < 0) {
		printf("gnutls verify peer failed.\n");
		return -1;
	}
	ret = 0;

	if (status & GNUTLS_CERT_INVALID) {
		ret |= -2;
		printf("The certificate is not trustworthy\n");
		if (status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
			printf("The certificate hasn't got a known issuer.\n");
			ret |= -4;
		}
		if (status & GNUTLS_CERT_SIGNER_NOT_CA) {
			printf("The certificate issuer is not a CA\n");
			ret |= -8;
		}
	}
	if (status & GNUTLS_CERT_REVOKED) {
		printf("The certificate has beend revoked.\n");
		ret = -16;
	}
	if (ret != 0 && ignore_ca_fail == 0) {
		return ret;
	}

	// from here on it works only with X509 certs
	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509){
		printf("The server certificate is not X509.\n");
		return -32;;
	}
	if (gnutls_x509_crt_init(&cert) < 0) {
		printf("gnutls crt init failed.\n");
		return -64;
	}

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
	if (cert_list == NULL) {
		printf("gnutls did not found a server certificate.\n");
		return -128;
	}

	// this not a real world check as only the first cert is checked!
	if (gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER)) {
		printf("gnutls failed to parse server certificate.\n");
		return -256;
	}

	// beware here we do not check for errors
	if (gnutls_x509_crt_get_expiration_time(cert) < time(0)) {
		printf("The server certificate is expired.\n");
		return -512;
	}
	if (gnutls_x509_crt_get_activation_time(cert) > time(0)) {
		printf("The server certificate is not yet activated.\n");
		return -1024;
	}
	if (!gnutls_x509_crt_check_hostname(cert, hostname)) {
		printf("The server certificate's owner does not match hostname '%s'\n", 
			hostname);
		return -2048;
	}

	gnutls_x509_crt_deinit(cert);

	return ret;
}

static const char *bin2hex(const void *bin, size_t bin_size) {
	static char printable[110];
	const unsigned char *_bin = bin;
	char *print;
	size_t i;

	if (bin_size > 50) {
		bin_size = 50;
	}

	print = printable;
	for (i=0; i < bin_size; i++) {
		sprintf(print, "%.2x ", _bin[i]);
		print += 2;
	}

	return printable;
}

void print_x509_certificate_info(gnutls_session_t session) {
	char serial[40];
	char dn[128];
	size_t size;
	unsigned int algo, bits;
	time_t expiration_time, activation_time;
	const gnutls_datum_t *cert_list;
	unsigned int cert_list_size = 0;
	gnutls_x509_crt_t cert;

	// check if we got a X.509 cert
	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
		printf("TLS session did not received a X.509 certificate\n");
		return;
	}

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
	printf("Peer provided %d certificate(s)\n", cert_list_size);

	if (cert_list_size > 0) {
		// print only informations about the first cert
		gnutls_x509_crt_init(&cert);
		gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER);
		printf("Certificate info:\n");
		activation_time = gnutls_x509_crt_get_activation_time(cert);
		printf("\tCertificate is valid since: %s", ctime(&activation_time));
		expiration_time = gnutls_x509_crt_get_expiration_time(cert);
		printf("\tCertificate expires: %s", ctime(&expiration_time));
		// print the serial number of the certificate
		size = sizeof(serial);
		gnutls_x509_crt_get_serial(cert, serial, &size);
		printf("\tCertificate serail number: %s\n", bin2hex(serial, size));
		// extract public key algorithm
		algo = gnutls_x509_crt_get_pk_algorithm(cert, &bits);
		printf("\tCertificate public key algorithm: %s\n", gnutls_pk_algorithm_get_name(algo));
		// print version of x509 cert
		printf("\tCertificate version: #%d\n", gnutls_x509_crt_get_version(cert));
		// print name of the certificate
		size = sizeof(dn);
		gnutls_x509_crt_get_dn(cert, dn, &size);
		printf("\tDN: %s\n", dn);
		// print subject alt name of the certificate
		size = sizeof(dn);
		if (gnutls_x509_crt_get_subject_alt_name(cert, 0, dn, &size, NULL) == 0) {
			printf("\tSubject Alt Name: %s\n", dn);
		}
		// print the algorithm which was used for signing the cert
		algo = gnutls_x509_crt_get_signature_algorithm(cert);
		printf("\tCA's signature algorithm: %s\n", gnutls_pk_algorithm_get_name(algo));
		// print the name of the CA
		size = sizeof(dn);
		if (gnutls_x509_crt_get_issuer_dn(cert, dn, &size) == 0) {
			printf("\tCA's DN: %s\n", dn);
		}
		// print the CA status flags if present
		if (gnutls_x509_crt_get_ca_status(cert, &algo) > 0 && algo != 0) {
			printf("\tCA status flag is set\n");
		}
		// print the fingerprint of the cert
		size = sizeof(dn);
		// FIXME
		if (gnutls_x509_crt_get_fingerprint(cert, GNUTLS_MAC_SHA1, dn, &size) == 0) {
			printf("\tFingerprint of the certificate: %s\n", dn);
		}


		gnutls_x509_crt_deinit(cert);
	}
}

void gnutls_session_info(gnutls_session_t session) {
	const char *tmp;
	gnutls_credentials_type_t cred;
	gnutls_kx_algorithm_t kx;

	// print the key exchange algorithm name
	kx = gnutls_kx_get(session);
	tmp = gnutls_kx_get_name(kx);
	printf("Key Echange: %s\n", tmp);

	// check the authentication type
	cred = gnutls_auth_get_type(session);
	switch(cred) {
		case GNUTLS_CRD_SRP:
			printf("SRP session with username %s\n",
				gnutls_srp_server_get_username(session));
			break;
		case GNUTLS_CRD_ANON:
			printf("Anonymous DH using prime of %d bits\n", 
				gnutls_dh_get_prime_bits(session));
			break;
		case GNUTLS_CRD_CERTIFICATE:
			// check if we have been using ephemeral DH
			if (kx == GNUTLS_KX_DHE_RSA || kx == GNUTLS_KX_DHE_DSS) {
				printf("Emphemeral DH using prime of %d bits\n",
					gnutls_dh_get_prime_bits(session));
			}
			// print certificate informations if available
			print_x509_certificate_info(session);
			break;
		default:
			printf("UNKNOWN GNUTLS authentication type!!!\n");
	}

	// print protocols name
	tmp = gnutls_protocol_get_name(gnutls_protocol_get_version(session));
	printf("Protocol: %s\n", tmp);

	// print certificate type
	tmp = gnutls_certificate_type_get_name(gnutls_certificate_type_get(session));
	printf("Certificate Type: %s\n", tmp);

	// print the compression algorithm
	tmp = gnutls_compression_get_name(gnutls_compression_get(session));
	printf("Compression: %s\n", tmp);

	// print name of the cipher
	tmp = gnutls_cipher_get_name(gnutls_cipher_get(session));
	printf("Cipher: %s\n", tmp);

	// print the MAC algorithm
	tmp = gnutls_mac_get_name(gnutls_mac_get(session));
	printf("MAC: %s\n", tmp);
}
# else
#  ifdef USE_OPENSSL
void set_tls_options() {
#if OPENSSL_VERSION_NUMBER >= 0x0009070000 /* 0.9.7 */
	SSL_CTX_set_options(ctx, SSL_OP_ALL |
							SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
							SSL_OP_CIPHER_SERVER_PREFERENCE);
#else
	SSL_CTX_set_options(ctx, SSL_OP_ALL);
#endif
}

void create_tls_ctx() {
	SSL_METHOD *method = NULL;

	method = TLSv1_method();
	ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		perror("create_tls_ctx: failed to create TLS ctx");
		exit_code(2, __PRETTY_FUNCTION__, "failed to create TLS ctx");
	}
	/*if (!SSL_CTX_use_certificate_chain_file(ctx, cert_file)) {
		perror("create_tls_ctx: failed to load certificate file");
		exit_code(2);
	}
	if (SSL_CTX_load_verify_locations(ctx, ca_file, 0) != 1) {
		perror("create_tls_ctx: failed to load CA cert");
		exit_code(2);
	}
	SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(ca_file));
	if (SSL_CTX_get_client_CA_list(ctx) == 0) {
		perror("create_tls_ctx: failed to set client CA list");
		exit_code(2);
	}*/
	SSL_CTX_set_cipher_list(ctx, 0);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
	SSL_CTX_set_verify_depth(ctx, 5);
	set_tls_options();
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_session_id_context(ctx, 0, 0);
}

void tls_dump_cert_info(char* s, X509* cert) {
	char *subj, *issuer;

	subj = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
	issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

	printf("%s subject: '%s'\n", s ? s: "", subj);
	printf("%s issuer: '%s'\n", s ? s : "", issuer);
	OPENSSL_free(subj);
	OPENSSL_free(issuer);
}
#  endif /* USE_OPENSSL */
# endif /* USE_GNUTLS */
#endif /* WITH_TLS_TRANSP */

void create_sockets(struct sipsak_con_data *cd) {
	socklen_t slen;

	memset(&(cd->adr), 0, sizeof(struct sockaddr_in));
	cd->adr.sin_family = AF_INET;
	cd->adr.sin_addr.s_addr = htonl( INADDR_ANY);
	cd->adr.sin_port = htons((short)lport);

	if (transport == SIP_UDP_TRANSPORT) {
		/* create the un-connected socket */
		if (!symmetric) {
			cd->usock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (cd->usock==-1) {
				perror("unconnected UDP socket creation failed");
				exit_code(2, __PRETTY_FUNCTION__, "failed to create unconnected UDP socket");
			}
			if (bind(cd->usock, (struct sockaddr *) &(cd->adr), sizeof(struct sockaddr_in) )==-1) {
				perror("unconnected UDP socket binding failed");
				exit_code(2, __PRETTY_FUNCTION__, "failed to bind unconnected UDP socket");
			}
		}


#ifdef RAW_SUPPORT
		/* try to create the raw socket */
		rawsock = (int)socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (rawsock==-1) {
			if (verbose>1)
				fprintf(stderr, "warning: need raw socket (root privileges) to receive all ICMP errors\n");
#endif
			/* create the connected socket as a primitve alternative to the 
			   raw socket*/
			cd->csock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (cd->csock==-1) {
				perror("connected UDP socket creation failed");
				exit_code(2, __PRETTY_FUNCTION__, "failed to create connected UDP socket");
			}

			if (!symmetric)
				cd->adr.sin_port = htons((short)0);
			if (bind(cd->csock, (struct sockaddr *) &(cd->adr), sizeof(struct sockaddr_in) )==-1) {
				perror("connected UDP socket binding failed");
				exit_code(2, __PRETTY_FUNCTION__, "failed to bind connected UDP socket");
			}
#ifdef RAW_SUPPORT
		}
		else if (symmetric) {
			cd->csock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (cd->csock==-1) {
				perror("connected UDP socket creation failed");
				exit_code(2, __PRETTY_FUNCTION__, "failed to create connected UDP socket");
			}
			if (bind(cd->csock, (struct sockaddr *) &(cd->adr), sizeof(struct sockaddr_in) )==-1) {
				perror("connected UDP socket binding failed");
				exit_code(2, __PRETTY_FUNCTION__, "failed to bind connected UDP socket");
			}
		}
#endif
	}
	else {
		cd->csock = (int)socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (cd->csock==-1) {
			perror("TCP socket creation failed");
			exit_code(2, __PRETTY_FUNCTION__, "failed to create TCP socket");
		}
		if (bind(cd->csock, (struct sockaddr *) &(cd->adr), sizeof(struct sockaddr_in) )==-1) {
			perror("TCP socket binding failed");
			exit_code(2, __PRETTY_FUNCTION__, "failed to bind TCP socket");
		}
#ifdef WITH_TLS_TRANSP
		if (transport == SIP_TLS_TRANSPORT) {
#ifdef USE_GNUTLS
			// initialixe the TLS session
			gnutls_init(&tls_session, GNUTLS_CLIENT);
			//gnutls_kx_set_priority(tls_session, kx_prio);
			//gnutls_credentials_set(tls_session, GNUTLS_CRD_ANON, anoncred);
			// use default priorities
			gnutls_set_default_priority(tls_session);
			gnutls_certificate_type_set_priority(tls_session, cert_type_priority);
			// put the X509 credentials to the session
			gnutls_credentials_set(tls_session, GNUTLS_CRD_CERTIFICATE, xcred);
			// add the FD to the session
			gnutls_transport_set_ptr(tls_session, (gnutls_transport_ptr_t) cd->csock);
#else /* USE_GNUTLS */
# ifdef USE_OPENSSL
			create_tls_ctx();
			ssl = SSL_new(ctx);
			if (ssl == NULL) {
				perror("TLS failed to create SSL object");
				exit_code(2, __PRETTY_FUNCTION__, "failed to create SSL object");
			}
			if (SSL_set_fd(ssl, cd->csock) != 1) {
				perror("TLS failed to add socket to SSL object");
				exit_code(2, __PRETTY_FUNCTION__, "failed to add socket to SSL object");
			}
# endif /* USE_OPENSSL */
#endif /* USE_GNUTLS */
			dbg("initialized tls socket %i\n", cd->csock);
		}
#endif /* WITH_TLS_TRANSP */
	}

	/* for the via line we need our listening port number */
	if (lport==0){
		memset(&(cd->adr), 0, sizeof(struct sockaddr_in));
		slen=sizeof(struct sockaddr_in);
		if (symmetric || transport != SIP_UDP_TRANSPORT)
			getsockname(cd->csock, (struct sockaddr *) &(cd->adr), &slen);
		else
			getsockname(cd->usock, (struct sockaddr *) &(cd->adr), &slen);
		lport=ntohs(cd->adr.sin_port);
	}
}

void close_sockets(struct sipsak_con_data *cd) {
	if (transport == SIP_UDP_TRANSPORT) {
	}
	else {
#ifdef WITH_TLS_TRANSP
		if (transport == SIP_TLS_TRANSPORT) {
# ifdef USE_GNUTLS
			gnutls_bye(tls_session, GNUTLS_SHUT_RDWR);
# else /* USE_GNUTLS */
#  ifdef USE_OPENSSL
#  endif /* USE_OPENSSL */
# endif /* USE_GNUTLS */
		}
#endif /* WITH_TLS_TRANSP */
		shutdown(cd->csock, SHUT_RDWR);
	}
	dbg("sockets closed\n");
}

void send_message(char* mes, struct sipsak_con_data *cd,
			struct sipsak_counter *sc, struct sipsak_sr_time *srt) {
	struct timezone tz;
	int ret;

	if (cd->dontsend == 0) {
		if (verbose > 2) {
			printf("\nrequest:\n%s", mes);
		}
		/* lets fire the request to the server and store when we did */
		if (cd->csock == -1) {
			dbg("\nusing un-connected socket for sending\n");
			ret = sendto(cd->usock, mes, strlen(mes), 0, (struct sockaddr *) &(cd->adr), sizeof(struct sockaddr));
		}
		else {
			dbg("\nusing connected socket for sending\n");
#ifdef WITH_TLS_TRANSP
			if (transport == SIP_TLS_TRANSPORT) {
# ifdef USE_GNUTLS
				ret = gnutls_record_send(tls_session, mes, strlen(mes));
# else /* USE_GNUTLS */
#  ifdef USE_OPENSSL
#  endif /* USE_OPENSSL */
# endif /* USE_GNUTLS */
			}
			else {
#endif /* TLS_TRANSP */
				ret = send(cd->csock, mes, strlen(mes), 0);
#ifdef WITH_TLS_TRANSP
			}
#endif /* TLS_TRANSP */
		}
		(void)gettimeofday(&(srt->sendtime), &tz);
		if (ret==-1) {
			if (verbose)
				printf("\n");
			perror("send failure");
			exit_code(2, __PRETTY_FUNCTION__, "send failure");
		}
#ifdef HAVE_INET_NTOP
		if (verbose > 2) {
			printf("\nsend to: %s:%s:%i\n", transport_str, target_dot, rport);
    }
#endif
		sc->send_counter++;
	}
	else {
		cd->dontsend = 0;
	}
}

void check_socket_error(int socket, int size) {
	struct pollfd sockerr;
	int ret = 0;

	/* lets see if we at least received an icmp error */
	sockerr.fd=socket;
	sockerr.events=POLLERR;
	ret = poll(&sockerr, 1, 10);
	if (ret==1) {
		if (sockerr.revents && POLLERR) {
			recvfrom(socket, recv, size, 0, NULL, 0);
			if (verbose)
				printf("\n");
			perror("send failure");
			if (randtrash == 1) {
				printf ("last message before send failure:\n%s\n", req);
				log_message(req);
			}
			exit_code(3, __PRETTY_FUNCTION__, "send failure");
		}
	}
}

int check_for_message(char *recv, int size, struct sipsak_con_data *cd,
			struct sipsak_sr_time *srt, struct sipsak_counter *count,
			struct sipsak_delay *sd) {
	fd_set	fd;
	struct timezone tz;
	struct timeval tv;
	double senddiff;
	int ret = 0;

	if (cd->dontrecv == 0) {
		/* set the timeout and wait for a response */
		tv.tv_sec = sd->retryAfter/1000;
		tv.tv_usec = (sd->retryAfter % 1000) * 1000;

		FD_ZERO(&fd);
		if (cd->usock != -1)
			FD_SET(cd->usock, &fd); 
		if (cd->csock != -1)
			FD_SET(cd->csock, &fd); 
#ifdef RAW_SUPPORT
		if (rawsock != -1)
			FD_SET(rawsock, &fd); 
#endif

		ret = select(FD_SETSIZE, &fd, NULL, NULL, &tv);
		(void)gettimeofday(&(srt->recvtime), &tz);
	}
	else {
		cd->dontrecv = 0;
	}

	/* store the time of our first send */
	if (count->send_counter==1) {
		memcpy(&(srt->firstsendt), &(srt->sendtime), sizeof(struct timeval));
	}
	if (sd->retryAfter == timer_t1) {
		memcpy(&(srt->starttime), &(srt->sendtime), sizeof(struct timeval));
	}
	if (ret == 0)
	{
		/* lets see if we at least received an icmp error */
		if (cd->csock == -1) 
			check_socket_error(cd->usock, size);
		else
			check_socket_error(cd->csock, size);
		/* printout that we did not received anything */
		if (verbose > 0) {
			if (trace == 1) {
				printf("%i: timeout after %i ms\n", namebeg, sd->retryAfter);
			}
			else if (usrloc == 1||invite == 1||message == 1) {
				printf("timeout after %i ms\n", sd->retryAfter);
			}
			else {
				printf("** timeout after %i ms**\n", sd->retryAfter);
			}
		}
		if (randtrash == 1) {
			printf("did not get a response on this request:\n%s\n", req);
			if (cseq_counter < nameend) {
				if (count->randretrys == 2) {
					printf("sended the following message three "
							"times without getting a response:\n%s\n"
							"give up further retransmissions...\n", req);
					log_message(req);
					exit_code(3, __PRETTY_FUNCTION__, "too many retransmissions, giving up...");
				}
				else {
					printf("resending it without additional "
							"random changes...\n\n");
					(count->randretrys)++;
				}
			}
		}
		senddiff = deltaT(&(srt->starttime), &(srt->recvtime));
		if (senddiff > (float)timer_final) {
			if (timing == 0) {
				if (verbose>0)
					printf("*** giving up, no final response after %.3f ms\n", senddiff);
				log_message(req);
				exit_code(3, __PRETTY_FUNCTION__, "timeout (no final response)");
			}
			else {
				timing--;
				count->run++;
				sd->all_delay += senddiff;
				sd->big_delay = senddiff;
				new_transaction(req, rep);
				sd->retryAfter = timer_t1;
				if (timing == 0) {
					printf("%.3f/%.3f/%.3f ms\n", sd->small_delay, sd->all_delay / count->run, sd->big_delay);
					log_message(req);
					exit_code(3, __PRETTY_FUNCTION__, "timeout (no final response)");
				}
			}
		}
		else {
			/* set retry time according to RFC3261 */
			if ((inv_trans) || (sd->retryAfter *2 < timer_t2)) {
				sd->retryAfter = sd->retryAfter * 2;
			}
			else {
				sd->retryAfter = timer_t2;
			}
		}
		(count->retrans_s_c)++;
		if (srt->delaytime.tv_sec == 0)
			memcpy(&(srt->delaytime), &(srt->sendtime), sizeof(struct timeval));
		/* if we did not exit until here lets try another send */
		return -1;
	}
	else if ( ret == -1 ) {
		perror("select error");
		exit_code(2, __PRETTY_FUNCTION__, "internal select error");
	}
	else if (((cd->usock != -1) && FD_ISSET(cd->usock, &fd)) || ((cd->csock != -1) && FD_ISSET(cd->csock, &fd))) {
		if ((cd->usock != -1) && FD_ISSET(cd->usock, &fd))
			ret = cd->usock;
		else if ((cd->csock != -1) && FD_ISSET(cd->csock, &fd))
			ret = cd->csock;
		else {
			printf("unable to determine the socket which received something\n");
			exit_code(2, __PRETTY_FUNCTION__, "failed to determine receiving socket");
		}
		/* no timeout, no error ... something has happened :-) */
	 	if (trace == 0 && usrloc ==0 && invite == 0 && message == 0 && randtrash == 0 && (verbose > 1))
			printf ("\nmessage received");
	}
#ifdef RAW_SUPPORT
	else if ((rawsock != -1) && FD_ISSET(rawsock, &fd)) {
		if (verbose > 1)
			printf("\nreceived ICMP message");
		ret = rawsock;
	}
#endif
	else {
		printf("\nselect returned succesfuly, nothing received\n");
		return -1;
	}
	return ret;
}

int complete_mes(char *mes, int size) {
	int cl = 0, headers = 0, len = 0;
	char *tmp = NULL;

	cl = get_cl(mes);
	dbg("CL: %i\n", cl);
	if (cl < 0){
		if (verbose > 0)
			printf("missing CL header; waiting for more bytes...\n");
		return 0;
	}
	tmp = get_body(mes);
	dbg("body: '%s'\n", tmp);
	headers = tmp - mes;
	dbg("length: %i, headers: %i\n", size, headers);
	len = headers + cl;
	if (len == size) {
		if (verbose > 0)
			printf("message is complete\n");
		return 1;
	}
	else if (len > size) {
		if (verbose > 0)
			printf("waiting for more bytes...\n");
		return 0;
	}
	else {
		/* we received more then the sender claims to sent
		 * for now we treat this as a complete message
		 * FIXME: should we store the extra bytes in a buffer and
		 *        truncate the message at the calculated length !? */
		if (verbose > 0)
			printf("received too much bytes...\n");
		return 1;
	}
}

int recv_message(char *buf, int size, int inv_trans, 
			struct sipsak_delay *sd, struct sipsak_sr_time *srt,
			struct sipsak_counter *count, struct sipsak_con_data *cd,
			struct sipsak_regexp *reg) {
	int ret = 0;
	int sock = 0;
	double tmp_delay;
#ifdef HAVE_INET_NTOP
	struct sockaddr_in peer_adr;
	socklen_t psize = sizeof(peer_adr);
#endif
#ifdef RAW_SUPPORT
	struct sockaddr_in faddr;
	struct ip 		*r_ip_hdr, *s_ip_hdr;
	struct icmp 	*icmp_hdr;
	struct udphdr 	*udp_hdr;
	size_t r_ip_len, s_ip_len, icmp_len;
	int srcport, dstport;
	unsigned int flen;
#endif

	if (cd->buf_tmp) {
		buf = cd->buf_tmp;
		size = size - cd->buf_tmp_size;
	}
	sock = check_for_message(buf, size, cd, srt, count, sd);
	if (sock <= 1) {
		return -1;
	}
#ifdef RAW_SUPPORT
	if (sock != rawsock) {
#else
	else {
#endif
		check_socket_error(sock, size);
#ifdef WITH_TLS_TRANSP
		if (transport == SIP_TLS_TRANSPORT) {
# ifdef USE_GNUTLS
			ret = gnutls_record_recv(tls_session, buf, size);
# else /* USE_GNUTLS */
#  ifdef USE_OPENSSL
#  endif /* USE_OPENSSL */
# endif /* USE_GNUTLS */
		}
		else {
#endif /* TLS_TRANSP */
			ret = recvfrom(sock, buf, size, 0, NULL, 0);
#ifdef WITH_TLS_TRANSP
		}
#endif /* TLS_TRANSP */
	}
#ifdef RAW_SUPPORT
	else {
		/* lets check if the ICMP message matches with our 
		   sent packet */
		flen = sizeof(faddr);
		memset(&faddr, 0, sizeof(struct sockaddr));
		ret = recvfrom(rawsock, buf, size, 0, (struct sockaddr *)&faddr, &flen);
		if (ret == -1) {
			perror("error while trying to read from icmp raw socket");
			exit_code(2, __PRETTY_FUNCTION__, "failed to read from ICMP RAW socket");
		}
		r_ip_hdr = (struct ip *) buf;
		r_ip_len = r_ip_hdr->ip_hl << 2;

		icmp_hdr = (struct icmp *) (buf + r_ip_len);
		icmp_len = ret - r_ip_len;

		if (icmp_len < 8) {
			if (verbose > 1)
				printf(": ignoring (ICMP header length below 8 bytes)\n");
			return -2;
		}
		else if (icmp_len < 36) {
			if (verbose > 1)
				printf(": ignoring (ICMP message too short to contain IP and UDP header)\n");
			return -2;
		}
		s_ip_hdr = (struct ip *) ((char *)icmp_hdr + 8);
		s_ip_len = s_ip_hdr->ip_hl << 2;
		if (s_ip_hdr->ip_p == IPPROTO_UDP) {
			udp_hdr = (struct udphdr *) ((char *)s_ip_hdr + s_ip_len);
			srcport = ntohs(udp_hdr->uh_sport);
			dstport = ntohs(udp_hdr->uh_dport);
			dbg("\nlport: %i, rport: %i\n", lport, rport);
			if ((srcport == lport) && (dstport == rport)) {
				printf(" (type: %u, code: %u)", icmp_hdr->icmp_type, icmp_hdr->icmp_code);
#ifdef HAVE_INET_NTOP
				if (inet_ntop(AF_INET, &faddr.sin_addr, &source_dot[0], INET_ADDRSTRLEN) != NULL)
					printf(": from %s\n", source_dot);
				else
					printf("\n");
#else
				printf("\n");
#endif // HAVE_INET_NTOP
				log_message(req);
				exit_code(3, __PRETTY_FUNCTION__, "received ICMP error");
			}
			else {
				if (verbose > 2)
					printf(": ignoring (ICMP message does not match used ports)\n");
				return -2;
			}
		}
		else {
			if (verbose > 1)
				printf(": ignoring (ICMP data is not a UDP packet)\n");
			return -2;
		}
	}
#endif // RAW_SUPPORT
	if (ret > 0) {
		*(buf+ ret) = '\0';
		if (transport != SIP_UDP_TRANSPORT) {
			if (verbose > 0)
				printf("\nchecking message for completness...\n");
			if (complete_mes(buf, ret) == 1) {
				cd->buf_tmp = NULL;
				ret += cd->buf_tmp_size;
				cd->buf_tmp_size = 0;
			}
			else {
				if (cd->buf_tmp) {
					cd->buf_tmp += ret;
					cd->buf_tmp_size += ret;
				}
				else {
					cd->buf_tmp = buf + ret;
					cd->buf_tmp_size = ret;
				}
				cd->dontsend = 1;
				ret = -1;
			}
		}
		/* store the biggest delay if one occured */
		if (srt->delaytime.tv_sec != 0) {
			tmp_delay = deltaT(&(srt->delaytime), &(srt->recvtime));
			if (tmp_delay > sd->big_delay)
				sd->big_delay = tmp_delay;
			if ((sd->small_delay == 0) || (tmp_delay < sd->small_delay))
				sd->small_delay = tmp_delay;
			srt->delaytime.tv_sec = 0;
			srt->delaytime.tv_usec = 0;
		}
		if (timing > 0) {
			tmp_delay = deltaT(&(srt->sendtime), &(srt->recvtime));
			if (tmp_delay > sd->big_delay)
				sd->big_delay = tmp_delay;
			if ((sd->small_delay == 0) || (tmp_delay < sd->small_delay))
				sd->small_delay = tmp_delay;
			sd->all_delay += tmp_delay;
		}
#ifdef HAVE_INET_NTOP
		if ((verbose > 2) && (getpeername(sock, (struct sockaddr *)&peer_adr, &psize) == 0) && (inet_ntop(peer_adr.sin_family, &peer_adr.sin_addr, &source_dot[0], INET_ADDRSTRLEN) != NULL)) {
			printf("\nreceived from: %s:%s:%i\n", transport_str, 
						source_dot, ntohs(peer_adr.sin_port));
		}
		else if (verbose > 1 && trace == 0 && usrloc == 0)
			printf(":\n");
#else
		if (trace == 0 && usrloc == 0)
			printf(":\n");
#endif // HAVE_INET_NTOP
		if (!inv_trans && ret > 0 && (regexec(&(reg->proexp), buf, 0, 0, 0) != REG_NOERROR)) {
			sd->retryAfter = timer_t1;
		}
	}
	else {
		check_socket_error(sock, size);
		printf("\nnothing received, select returned error\n");
		exit_code(2, __PRETTY_FUNCTION__, "nothing received, select returned error");
	}
	return ret;
}

/* clears the given sockaddr, fills it with the given data and if a
 * socket is given connects the socket to the new target */
int set_target(struct sockaddr_in *adr, unsigned long target, int port, int socket, int connected) {
#ifdef WITH_TLS_TRANSP
	int ret;
# ifdef USE_OPENSSL
	int err;
	X509* cert;
# endif /* USE_OPENSSL */
#endif /* WITH_TLS_TRANSP */

	if (socket != -1 && transport != SIP_UDP_TRANSPORT && connected) {
		if (shutdown(socket, SHUT_RDWR) != 0) {
			perror("error while shutting down socket");
		}
	}

	memset(adr, 0, sizeof(struct sockaddr_in));
	adr->sin_addr.s_addr = target;
	adr->sin_port = htons((short)port);
	adr->sin_family = AF_INET;

#ifdef HAVE_INET_NTOP
	inet_ntop(adr->sin_family, &adr->sin_addr, &target_dot[0], INET_ADDRSTRLEN);
#endif

	if (socket != -1) {
		if (connect(socket, (struct sockaddr *)adr, sizeof(struct sockaddr_in)) == -1) {
			perror("connecting socket failed");
			exit_code(2, __PRETTY_FUNCTION__, "connecting socket failed");
		}
#ifdef WITH_TLS_TRANSP
		if (transport == SIP_TLS_TRANSPORT) {
# ifdef USE_GNUTLS
			ret = gnutls_handshake(tls_session);
			if (ret < 0) {
				dbg("TLS Handshake FAILED!!!\n");
				gnutls_perror(ret);
				exit_code(3, __PRETTY_FUNCTION__, "TLS handshake failed");
			}
			else if (verbose > 2) {
				dbg(" TLS Handshake was completed!\n");
				gnutls_session_info(tls_session);
				if (verify_certificate_simple(tls_session, domainname) != 0) {
					if (ignore_ca_fail == 1) {
						if (verbose) {
							printf("WARN: Ignoring verification failures of the server certificate\n");
						}
					} else {
						if (verbose > 1) {
							printf("TLS server certificate verification can be ignored with option --tls-ignore-cert-failure.\n");
						}
						exit_code(3, __PRETTY_FUNCTION__, "failure during TLS server certificate verification");
					}
				}
				//verify_certificate_chain(tls_session, domainname, cert_chain, cert_chain_length);
			}
# else /* USE_GNUTLS */
#  ifdef USE_OPENSSL
			ret = SSL_connect(ssl);
			if (ret == 1) {
				dbg("TLS connect successful\n");
				if (verbose > 2) {
					printf("TLS connect: new connection using %s %s %d\n",
						SSL_get_cipher_version(ssl), SSL_get_cipher_name(ssl),
						SSL_get_cipher_bits(ssl, 0));
				}
				cert = SSL_get_peer_certificate(ssl);
				if (cert != 0) {
					tls_dump_cert_info("TLS connect: server certificate", cert);
					if (SSL_get_verify_result(ssl) != X509_V_OK) {
						perror("TLS connect: server certifcate verification failed!!!\n");
						exit_code(3, __PRETTY_FUNCTION__, "TLS server certificate verification falied");
					}
					X509_free(cert);
				}
				else {
					perror("TLS connect: server did not present a certificate\n");
					exit_code(3, __PRETTY_FUNCTION__, "missing TLS server certificate");
				}
			}
			else {
				err = SSL_get_error(ssl, ret);
				switch (err) {
					case SSL_ERROR_ZERO_RETURN:
						perror("TLS handshakre failed cleanly'n");
						break;
					case SSL_ERROR_WANT_READ:
						perror("Need to get more data to finish TLS connect\n");
						break;
					case SSL_ERROR_WANT_WRITE:
						perror("Need to send more data to finish TLS connect\n");
						break;
#if OPENSSL_VERSION_NUMBER >= 0x00907000L /* 0.9.7 */
					case SSL_ERROR_WANT_CONNECT:
						perror("Need to retry connect\n");
						break;
					case SSL_ERROR_WANT_ACCEPT:
						perror("Need to retry accept'n");
						break;
#endif /* 0.9.7 */
					case SSL_ERROR_WANT_X509_LOOKUP:
						perror("Application callback asked to be called again\n");
						break;
					case SSL_ERROR_SYSCALL:
						printf("TLS connect: %d\n", err);
						if (!err) {
							if (ret == 0) {
								perror("Unexpected EOF occured while performing TLS connect\n");
							}
							else {
								printf("IO error: (%d) %s\n", errno, strerror(errno));
							}
						}
						break;
					default:
						printf("TLS error: %d\n", err);
				}
				exit_code(2, __PRETTY_FUNCTION__, "generic SSL error");
			}
#  endif /* USE_OPENSSL */
# endif /* USE_GNUTLS */
		}
#endif /* WITH_TLS_TRANSP */
	}
	return 1;
}
