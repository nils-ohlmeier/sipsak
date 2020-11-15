/*
 * Copyright (C) 2002-2004 Fhg Fokus
 * Copyright (C) 2004-2005 Nils Ohlmeier
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

#ifndef SIPSAK_H
#define SIPSAK_H

#if HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_REGEX_H
# include <regex.h>
#endif
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifndef INET_ADDRSTRLEN
# define INET_ADDRSTRLEN 16
#endif
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif

#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif
#ifndef INT_MAX
# define INT_MAX 2147483648
#endif

#ifdef HAVE_STRCASESTR
# define __USE_GNU
# define STRCASESTR(s1,s2) strcasestr(s1,s2)
#else
# define STRCASESTR(s1,s2) strstr(s1,s2)
#endif
#ifdef HAVE_STRNCASECMP
# define STRNCASECMP(s1,s2,s3) strncasecmp(s1,s2,s3)
#else
# define STRNCASECMP(s1,s2,s3) strncmp(s1,s2,s3)
#endif
#ifdef HAVE_STRING_H
# include <string.h>
#endif

#ifdef HAVE_GNUTLS
# define USE_GNUTLS
# ifndef SIPSAK_NO_TLS
#  define WITH_TLS_TRANSP 1
# endif
# include <gnutls/gnutls.h>
#else
# ifdef HAVE_OPENSSL_MD5_H
#  ifdef HAVE_CRYPTO_WITH_MD5
#   define HAVE_FULL_OPENSSL
#   define HAVE_EXTERNAL_MD5
#   define USE_OPENSSL
#   include <openssl/ssl.h>
#  endif
# endif
#endif

#ifdef HAVE_OPENSSL_SHA_H
# ifdef HAVE_CRYPTO_WITH_SHA1
#  define HAVE_OPENSSL_SHA1
# endif
#endif

#ifdef SIPSAK_PRINT_DBG
# define DEBUG 1
#endif

#ifndef REG_NOERROR
# define REG_NOERROR 0
#endif

#ifdef HAVE_SYS_PARAM_H
# ifdef MAXHOSTNAMELEN
#  define FQDN_SIZE   MAXHOSTNAMELEN + 1
# else
#  define FQDN_SIZE   100
# endif
#else
# define FQDN_SIZE   100
#endif

#ifdef HAVE_CONFIG_H
# define SIP_T1 DEFAULT_TIMEOUT
#else
# define SIP_T1 500
#endif

#define SIP_T2 8*SIP_T1

#define SIPSAK_VERSION PACKAGE_VERSION
#define UA_VAL_STR "sipsak " SIPSAK_VERSION
#define BUFSIZE		4096

#define SIPSAK_MAX_PASSWD_LEN 20

#define REQ_REG 1
#define REQ_REM 2
#define REQ_INV 3
#define REQ_MES 4
#define REQ_OPT 5
#define REQ_FLOOD 6
#define REQ_RAND 7

#define SIP_TLS_TRANSPORT 1
#define SIP_TCP_TRANSPORT 2
#define SIP_UDP_TRANSPORT 3

#define TRANSPORT_TLS_STR "TLS"
#define TRANSPORT_TCP_STR "TCP"
#define TRANSPORT_UDP_STR "UDP"
#define TRANSPORT_STR_LEN 3

#define VIA_SIP_STR "Via: SIP/2.0/"
#define VIA_SIP_STR_LEN (sizeof(VIA_SIP_STR) - 1)

#define SIP20_STR " SIP/2.0\r\n"
#define SIP20_STR_LEN (sizeof(SIP20_STR) - 1)

#define SIP200_STR "SIP/2.0 200 OK\r\n"
#define SIP200_STR_LEN (sizeof(SIP200_STR) - 1)

#define INV_STR "INVITE"
#define INV_STR_LEN (sizeof(INV_STR) - 1)

#define REG_STR "REGISTER"
#define REG_STR_LEN (sizeof(REG_STR) - 1)

#define OPT_STR "OPTIONS"
#define OPT_STR_LEN (sizeof(OPT_STR) - 1)

#define MES_STR "MESSAGE"
#define MES_STR_LEN (sizeof(MES_STR) - 1)

#define ACK_STR "ACK"
#define ACK_STR_LEN (sizeof(ACK_STR) - 1)

#define FROM_STR "From: "
#define FROM_STR_LEN (sizeof(FROM_STR) - 1)
#define FROM_SHORT_STR "\nf: "
#define FROM_SHORT_STR_LEN (sizeof(FROM_SHORT_STR) - 1)

#define TO_STR "To: "
#define TO_STR_LEN (sizeof(TO_STR) - 1)
#define TO_SHORT_STR "\nt: "
#define TO_SHORT_STR_LEN (sizeof(TO_SHORT_STR) - 1)

#define VIA_STR "Via: "
#define VIA_STR_LEN (sizeof(VIA_STR) - 1)
#define VIA_SHORT_STR "\nv: "
#define VIA_SHORT_STR_LEN (sizeof(VIA_SHORT_STR) - 1)

#define CALL_STR "Call-ID: "
#define CALL_STR_LEN (sizeof(CALL_STR) - 1)
#define CALL_SHORT_STR "\ni: "
#define CALL_SHORT_STR_LEN (sizeof(CALL_SHORT_STR) - 1)

#define MAX_FRW_STR "Max-Forwards: "
#define MAX_FRW_STR_LEN (sizeof(MAX_FRW_STR) - 1)

#define CSEQ_STR "CSeq: "
#define CSEQ_STR_LEN (sizeof(CSEQ_STR) - 1)

#define CONT_STR "Contact: "
#define CONT_STR_LEN (sizeof(CONT_STR) - 1)
#define CONT_SHORT_STR "\nm: "
#define CONT_SHORT_STR_LEN (sizeof(CONT_SHORT_STR) - 1)

#define CON_TYP_STR "Content-Type: "
#define CON_TYP_STR_LEN (sizeof(CON_TYP_STR) - 1)
#define CON_TYP_SHORT_STR "\nc: "
#define CON_TYP_SHORT_STR_LEN (sizeof(CON_TYP_SHORT_STR) - 1)

#define CON_DIS_STR "Content-Disposition: "
#define CON_DIS_STR_LEN (sizeof(CON_DIS_STR) - 1)

#define TXT_PLA_STR "text/plain"
#define TXT_PLA_STR_LEN (sizeof(TXT_PLA_STR) - 1)

#define ACP_STR "Accept: "
#define ACP_STR_LEN (sizeof(ACP_STR) - 1)

#define CON_LEN_STR "Content-Length: "
#define CON_LEN_STR_LEN (sizeof(CON_LEN_STR) - 1)
#define CON_LEN_SHORT_STR "\nl: "
#define CON_LEN_SHORT_STR_LEN (sizeof(CON_LEN_SHORT_STR) - 1)

#define RR_STR "Record-Route: "
#define RR_STR_LEN (sizeof(RR_STR) -  1)

#define ROUTE_STR "Route: "
#define ROUTE_STR_LEN (sizeof(ROUTE_STR) - 1)

#define SIPSAK_MES_STR "test message from SIPsak for user "
#define SIPSAK_MES_STR_LEN (sizeof(SIPSAK_MES_STR) - 1)

#define EXP_STR "Expires: "
#define EXP_STR_LEN (sizeof(EXP_STR) - 1)

#define CON_EXP_STR "expires="
#define CON_EXP_STR_LEN (sizeof(CON_EXP_STR) - 1)

#define WWWAUTH_STR "WWW-Authenticate: "
#define WWWAUTH_STR_LEN (sizeof(WWWAUTH_STR) - 1)

#define PROXYAUTH_STR "Proxy-Authenticate: "
#define PROXYAUTH_STR_LEN (sizeof(PROXYAUTH_STR) - 1)

#define AUTH_STR "Authorization: Digest "
#define AUTH_STR_LEN (sizeof(AUTH_STR) - 1)

#define PROXYAUZ_STR "Proxy-Authorization: Digest "
#define PROXYAUZ_STR_LEN (sizeof(PROXYAUZ_STR) - 1)

#define ALGO_STR "algorithm="
#define ALGO_STR_LEN (sizeof(ALGO_STR) - 1)

#define MD5_STR "MD5, "
#define MD5_STR_LEN (sizeof(MD5_STR) - 1)

#define SHA1_STR "SHA1, "
#define SHA1_STR_LEN (sizeof(SHA1_STR) - 1)

#define SHA256_STR "SHA-256, "
#define SHA256_STR_LEN (sizeof(SHA256_STR) - 1)

#define REALM_STR "realm="
#define REALM_STR_LEN (sizeof(REALM_STR) - 1)

#define OPAQUE_STR "opaque="
#define OPAQUE_STR_LEN (sizeof(OPAQUEE_STR) - 1)

#define NONCE_STR "nonce="
#define NONCE_STR_LEN (sizeof(NONCE_STR) - 1)

#define RESPONSE_STR "response="
#define RESPONSE_STR_LEN (sizeof(RESPONSE_STR) - 1)

#define QOP_STR "qop="
#define QOP_STR_LEN (sizeof(QOP_STR) - 1)

#define QOPAUTH_STR "auth"
#define QOPAUTH_STR_LEN (sizeof(QOPAUTH_STR) - 1)

#define NC_STR "nc="
#define NC_STR_LEN (sizeof(NC_STR) - 1)

#define EMPTY_STR ""
#define EMPTY_STR_LEN (sizeof(EMPTY_STR) - 1)

#define UA_STR "User-Agent: "
#define UA_STR_LEN (sizeof(UA_STR) - 1)

#define SUB_STR "Subject: "
#define SUB_STR_LEN (sizeof(SUB_STR) - 1)

#define SIP100_STR "SIP/2.0 100"
#define SIP100_STR_LEN (sizeof(SIP100_STR) - 1)

#define TRANSPORT_PARAMETER_STR ";transport="
#define TRANSPORT_PARAMETER_STR_LEN (sizeof(TRANSPORT_PARAMETER_STR) - 1)

#define USRLOC_EXP_DEF 15
#define FLOOD_METH "OPTIONS"

#define SIPSAK_HASHLEN_MD5 16
#define SIPSAK_HASHHEXLEN_MD5 2 * SIPSAK_HASHLEN_MD5
#ifdef HAVE_OPENSSL_SHA1
# define SIPSAK_HASHLEN_SHA1 20
# define SIPSAK_HASHHEXLEN_SHA1 2 * SIPSAK_HASHLEN_SHA1
# define SIPSAK_HASHLEN_SHA256 32
# define SIPSAK_HASHHEXLEN_SHA256 2 * SIPSAK_HASHLEN_SHA256
# define SIPSAK_HASHLEN SIPSAK_HASHLEN_SHA256
#else
# define SIPSAK_HASHLEN SIPSAK_HASHLEN_MD5
#endif
#define SIPSAK_HASHHEXLEN 2 * SIPSAK_HASHLEN

extern int verbose;

enum sipsak_modes { SM_UNDEFINED, SM_USRLOC, SM_USRLOC_INVITE, SM_USRLOC_MESSAGE, SM_INVITE, SM_MESSAGE, SM_FLOOD, SM_TRACE, SM_RANDTRASH };

struct sipsak_options {
  int timing;
  int namebeg;
  int nameend;
  int empty_contact;
  int redirects;
  int timer_final;
  int file_b;
  int replace_b;
  int via_ins;
  int lport;
  int rport;
  int fix_crlf;
  int maxforw;
  int numeric;
  int sleep_ms;
  int outbound_proxy;
  int processes;
  int randtrash;
  int trashchar;
  int uri_b;
  int symmetric;
  int warning_ext;
  int nagios_warn;
  int expires_t;
  int rand_rem;
  int timer_t1;
#ifdef WITH_TLS_TRANSP
  int ignore_ca_fail;
#endif
  enum sipsak_modes mode;
  char *password;
  char *mes_body;
  char *from_uri;
  char *contact_uri;
  char *replace_str;
  char *hostname;
  char *headers;
  char *authhash;
  char *local_ip;
  char *con_dis;
  char *username;
  char *domainname;
  char *auth_username;
#ifdef WITH_TLS_TRANSP
  char *cert_file;
  char *ca_file;
#endif
  unsigned int transport;
  unsigned long address;
  regex_t *regex;
};

#endif
