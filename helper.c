/*
 * $Id$
 *
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
#include "sipsak.h"

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif
#ifdef HAVE_UNISTD_H
# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif
# include <unistd.h>
#endif
#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif
#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_RULI_H
# include <ruli.h>
#endif
#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif
#ifdef HAVE_CARES_H
# ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h>
# endif
# include <ares.h>
# ifndef NS_RRFIXEDSZ
#  define NS_RRFIXEDSZ 10
#  define NS_QFIXEDSZ  4
#  define NS_HFIXEDSZ  12
# endif
 int caport;
 unsigned long caadr;
 char *ca_tmpname;
 ares_channel channel;

#endif // HAVE_CARES_H

#include "helper.h"
#include "exit_code.h"

/* returns 1 if the string an IP address otherwise zero */
int is_ip(char *str) {
	int i = 0;
	int dotcount = 0;

	/*try understanding if this is a valid ip address
	we are skipping the values of the octets specified here.
	for instance, this code will allow 952.0.320.567 through*/
	while (*str != '\0')
	{
		for (i = 0; i < 3; i++, str++)
			if (isdigit((int)*str) == 0)
				break;
		if (*str != '.')
			break;
		str++;
		dotcount++;
	}

	/* three dots with upto three digits in before, between and after ? */
	if (dotcount == 3 && i > 0 && i <= 3)
		return 1;
	else
		return 0;
}

/* take either a dot.decimal string of ip address or a 
domain name and returns a NETWORK ordered long int containing
the address. i chose to internally represent the address as long for speedier
comparisions.

any changes to getaddress have to be patched back to the net library.
contact: farhan@hotfoon.com

  returns zero if there is an error.
  this is convenient as 0 means 'this' host and the traffic of
  a badly behaving dns system remains inside (you send to 0.0.0.0)
*/

unsigned long getaddress(char *host) {
	struct hostent* pent;
	long l, *lp;

	if (is_ip(host))
		return inet_addr(host);

	/* try the system's own resolution mechanism for dns lookup:
	 required only for domain names.
	 inspite of what the rfc2543 :D Using SRV DNS Records recommends,
	 we are leaving it to the operating system to do the name caching.

	 this is an important implementational issue especially in the light
	 dynamic dns servers like dynip.com or dyndns.com where a dial
	 ip address is dynamically assigned a sub domain like farhan.dynip.com

	 although expensive, this is a must to allow OS to take
	 the decision to expire the DNS records as it deems fit.
	*/
	pent = gethostbyname(host);
	if (!pent) {
		printf("'%s' is unresolveable\n", host);
		exit_code(2);
	}
	lp = (long *) (pent->h_addr);
	l = *lp;
	return l;
}

#ifdef HAVE_CARES_H
static const unsigned char *parse_rr(const unsigned char *aptr, const unsigned char *abuf, int alen) {
	char *name;
	long len;
	int status, type, dnsclass, dlen;
	struct in_addr addr;

#ifdef DEBUG
	printf("ca_tmpname: %s\n", ca_tmpname);
#endif
	status = ares_expand_name(aptr, abuf, alen, &name, &len);
	if (status != ARES_SUCCESS) {
		printf("error: failed to expand query name\n");
		exit_code(2);
	}
	aptr += len;
	if (aptr + NS_RRFIXEDSZ > abuf + alen) {
		printf("error: not enough data in DNS answer 1\n");
		free(name);
		return NULL;
	}
	type = DNS_RR_TYPE(aptr);
	dnsclass = DNS_RR_CLASS(aptr);
	dlen = DNS_RR_LEN(aptr);
	aptr += NS_RRFIXEDSZ;
	if (aptr + dlen > abuf + alen) {
		printf("error: not enough data in DNS answer 2\n");
		free(name);
		return NULL;
	}
	if (dnsclass != CARES_CLASS_C_IN) {
		printf("error: unsupported dnsclass (%i) in DNS answer\n", dnsclass);
		free(name);
		return NULL;
	}
	if ((ca_tmpname == NULL && type != CARES_TYPE_SRV) ||
		(ca_tmpname != NULL && 
		 	(type != CARES_TYPE_A && type != CARES_TYPE_CNAME))) {
		printf("error: unsupported DNS response type (%i)\n", type);
		free(name);
		return NULL;
	}
	if (type == CARES_TYPE_SRV) {
		free(name);
		caport = DNS__16BIT(aptr + 4);
#ifdef DEBUG
		printf("caport: %i\n", caport);
#endif
		status = ares_expand_name(aptr + 6, abuf, alen, &name, &len);
		if (status != ARES_SUCCESS) {
			printf("error: failed to expand SRV name\n");
			return NULL;
		}
#ifdef DEBUG
		printf("SRV name: %s\n", name);
#endif
		if (is_ip(name)) {
			caadr = inet_addr(name);
			free(name);
		}
		else {
			ca_tmpname = name;
		}
	}
	else if (type == CARES_TYPE_CNAME) {
		if (STRNCASECMP(ca_tmpname, name, strlen(ca_tmpname)) == 0) {
			ca_tmpname = malloc(strlen(name));
			if (ca_tmpname == NULL) {
				printf("error: failed to allocate memory\n");
				exit_code(2);
			}
			strcpy(ca_tmpname, name);
		}
		free(name);
	}
	else if (type == CARES_TYPE_A) {
		if (dlen == 4 && STRNCASECMP(ca_tmpname, name, strlen(ca_tmpname)) == 0) {
			memcpy(&addr, aptr, sizeof(struct in_addr));
			caadr = addr.s_addr;
		}
		free(name);
	}
	return aptr + dlen;
}

static const unsigned char *skip_rr(const unsigned char *aptr, const unsigned char *abuf, int alen) {
	int status, dlen;
	long len;
	char *name;

#ifdef DEBUG
	printf("skipping rr section...\n");
#endif
	status = ares_expand_name(aptr, abuf, alen, &name, &len);
	aptr += len;
	dlen = DNS_RR_LEN(aptr);
	aptr += NS_RRFIXEDSZ;
	aptr += dlen;
	free(name);
	return aptr;
}

static const unsigned char *skip_query(const unsigned char *aptr, const unsigned char *abuf, int alen) {
	int status;
	long len;
	char *name;

#ifdef DEBUG
	printf("skipping query section...\n");
#endif
	status = ares_expand_name(aptr, abuf, alen, &name, &len);
	aptr += len;
	aptr += NS_QFIXEDSZ;
	free(name);
	return aptr;
}

static void cares_callback(void *arg, int status, unsigned char *abuf, int alen) {
	int i;
	unsigned int ancount, nscount, arcount;
	const unsigned char *aptr;

#ifdef DEBUG
	printf("cares_callback: status=%i, alen=%i\n", status, alen);
#endif
	if (status != ARES_SUCCESS) {
		printf("ares failed: %s\n", ares_strerror(status));
		return;
	}

	ancount = DNS_HEADER_ANCOUNT(abuf);
	nscount = DNS_HEADER_NSCOUNT(abuf);
	arcount = DNS_HEADER_ARCOUNT(abuf);
	
#ifdef DEBUG
	printf("ancount: %i, nscount: %i, arcount: %i\n", ancount, nscount, arcount);
#endif

	/* safety check */
	if (alen < NS_HFIXEDSZ)
		return;
	aptr = abuf + NS_HFIXEDSZ;

	aptr = skip_query(aptr, abuf, alen);

	for (i = 0; i < ancount && caadr == 0; i++) {
		if (ca_tmpname == NULL)
			aptr = parse_rr(aptr, abuf, alen);
		else
			aptr = skip_rr(aptr, abuf, alen);
	}
	if (caadr == 0) {
		for (i = 0; i < nscount; i++) {
			aptr = skip_rr(aptr, abuf, alen);
		}
		for (i = 0; i < arcount && caadr == 0; i++) {
			aptr = parse_rr(aptr, abuf, alen);
		}
	}
}

inline unsigned long srv_ares(char *host, int *port, char *srv) {
	int nfds, count, srvh_len;
	char *srvh;
	fd_set read_fds, write_fds;
	struct timeval *tvp, tv;

	caport = 0;
	caadr = 0;
	ca_tmpname = NULL;
#ifdef DEBUG
	printf("!!! ARES query !!!\n");
#endif

	srvh_len = strlen(host) + strlen(srv) + 2;
	srvh = malloc(srvh_len);
	if (srvh == NULL) {
		printf("error: failed to allocate memory (%i) for ares query\n", srvh_len);
		exit_code(2);
	}
	memset(srvh, 0, srvh_len);
	strncpy(srvh, srv, strlen(srv));
	memcpy(srvh + strlen(srv), ".", 1);
	strcpy(srvh + strlen(srv) + 1, host);
#ifdef DEBUG
	printf("hostname: '%s', len: %i\n", srvh, srvh_len);
#endif

	ares_query(channel, srvh, CARES_CLASS_C_IN, CARES_TYPE_SRV, cares_callback, (char *) NULL);
#ifdef DEBUG
	printf("after ares_query\n");
#endif
	/* wait for query to complete */
	while (1) {
		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		nfds = ares_fds(channel, &read_fds, &write_fds);
		if (nfds == 0)
			break;
		tvp = ares_timeout(channel, NULL, &tv);
		count = select(nfds, &read_fds, &write_fds, NULL, tvp);
		if (count < 0 && errno != EINVAL) {
			perror("ares select");
			exit_code(2);
		}
		ares_process(channel, &read_fds, &write_fds);
	}
#ifdef DEBUG
	printf("end of while\n");
#endif
	*port = caport;
	if (caadr == 0 && ca_tmpname != NULL) {
		caadr = getaddress(ca_tmpname);
	}
	if (ca_tmpname != NULL)
		free(ca_tmpname);
	return caadr;
}
#endif // HAVE_CARES_H

#ifdef HAVE_RULI_H
inline unsigned long srv_ruli(char *host, int *port, char *srv) {
	int srv_code;
	int ruli_opts = RULI_RES_OPT_SEARCH | RULI_RES_OPT_SRV_NOINET6 | RULI_RES_OPT_SRV_NOSORT6 | RULI_RES_OPT_SRV_NOFALL;
#ifdef RULI_RES_OPT_SRV_CNAME
	ruli_opts |= RULI_RES_OPT_SRV_CNAME;
#endif

	ruli_sync_t *sync_query = ruli_sync_query(srv, host, *port, ruli_opts);

	/* sync query failure? */
	if (!sync_query) {
		printf("DNS SRV lookup failed for: %s\n", host);
		exit_code(2);
	}

	srv_code = ruli_sync_srv_code(sync_query);
	/* timeout? */
	if (srv_code == RULI_SRV_CODE_ALARM) {
		printf("Timeout during DNS SRV lookup for: %s\n", host);
		ruli_sync_delete(sync_query);
		exit_code(2);
	}
	/* service provided? */
	else if (srv_code == RULI_SRV_CODE_UNAVAILABLE) {
		printf("SRV service not provided for: %s\n", host);
		ruli_sync_delete(sync_query);
		exit_code(2);
	}
	else if (srv_code) {
		int rcode = ruli_sync_rcode(sync_query);
		if (verbose > 1)
			printf("SRV query failed for: %s, srv_code=%d, rcode=%d\n", host, srv_code, rcode);
		ruli_sync_delete(sync_query);
		return 0;
	}

	ruli_list_t *srv_list = ruli_sync_srv_list(sync_query);

	int srv_list_size = ruli_list_size(srv_list);

	if (srv_list_size < 1) {
		if (verbose > 1)
			printf("No SRV record: %s.%s\n", srv, host);
		return 0;
	}

	ruli_srv_entry_t *entry = (ruli_srv_entry_t *) ruli_list_get(srv_list, 0);
	ruli_list_t *addr_list = &entry->addr_list;
	int addr_list_size = ruli_list_size(addr_list);

	if (addr_list_size < 1) {
		printf("missing addresses in SRV lookup for: %s\n", host);
		ruli_sync_delete(sync_query);
		exit_code(2);
	}

	*port = entry->port;
	ruli_addr_t *addr = (ruli_addr_t *) ruli_list_get(addr_list, 0);
	return addr->addr.ipv4.s_addr;
}
#endif // HAVE_RULI_H

unsigned long getsrvaddress(char *host, int *port, char *srv) {
#ifdef HAVE_RULI_H
	return srv_ruli(host, port, srv);
#else
# ifdef HAVE_CARES_H // HAVE_RULI_H
	return srv_ares(host, port, srv);
# else // HAVE_CARES_H
	return 0;
# endif
#endif
}

/* Finds the SRV records for the given host. It returns the target IP
 * address and fills the port and transport if a suitable SRV record
 * exists. Otherwise it returns 0. The function follows 3263: first
 * TLS, then TCP and finally UDP. */
unsigned long getsrvadr(char *host, int *port, unsigned int *transport) {
	unsigned long adr = 0;

#ifdef HAVE_SRV
	int srvport = 5060;

#ifdef HAVE_CARES_H
	int status;
	int optmask = ARES_OPT_FLAGS;
	struct ares_options options;

	options.flags = ARES_FLAG_NOCHECKRESP;
	options.servers = NULL;
	options.nservers = 0;

	status = ares_init_options(&channel, &options, optmask);
	if (status != ARES_SUCCESS) {
		printf("error: failed to initialize ares\n");
		exit_code(2);
	}
#endif

#ifdef WITH_TLS_TRANSP
	adr = getsrvaddress(host, &srvport, SRV_SIP_TLS);
	if (adr != 0) {
		*transport = SIP_TLS_TRANSPORT;
		if (verbose > 1)
			printf("using SRV record: %s.%s:%i\n", SRV_SIP_TLS, host, srvport);
		printf("TLS transport not yet supported\n");
		exit_code(2);
	}
	else {
#endif
		adr = getsrvaddress(host, &srvport, SRV_SIP_TCP);
		if (adr != 0) {
			*transport = SIP_TCP_TRANSPORT;
			if (verbose > 1)
				printf("using SRV record: %s.%s:%i\n", SRV_SIP_TCP, host, srvport);
		}
		else {
			adr = getsrvaddress(host, &srvport, SRV_SIP_UDP);
			if (adr != 0) {
				*transport = SIP_UDP_TRANSPORT;
				if (verbose > 1)
					printf("using SRV record: %s.%s:%i\n", SRV_SIP_UDP, host, srvport);
			}
		}
#ifdef WITH_TLS_TRANSP
	}
#endif

#ifdef HAVE_CARES_H
	ares_destroy(channel);
#endif

	*port = srvport;
#endif // HAVE_SRV
	return adr;
}

/* because the full qualified domain name is needed by many other
   functions it will be determined by this function.
*/
void get_fqdn(){
	char hname[100], dname[100], hlp[18];
	size_t namelen=100;
	struct hostent* he;
	struct utsname un;

	memset(&hname, 0, sizeof(hname));
	memset(&dname, 0, sizeof(dname));
	memset(&hlp, 0, sizeof(hlp));

	if (hostname) {
		strncpy(fqdn, hostname, FQDN_SIZE);
		strncpy(hname, hostname, 100);
	}
	else {
		if ((uname(&un))==0) {
			strncpy(hname, un.nodename, 100);
		}
		else {
			if (gethostname(&hname[0], namelen) < 0) {
				fprintf(stderr, "error: cannot determine hostname\n");
				exit_code(2);
			}
		}
#ifdef HAVE_GETDOMAINNAME
		/* a hostname with dots should be a domainname */
		if ((strchr(hname, '.'))==NULL) {
			if (getdomainname(&dname[0], namelen) < 0) {
				fprintf(stderr, "error: cannot determine domainname\n");
				exit_code(2);
			}
			if (strcmp(&dname[0],"(none)")!=0)
				snprintf(fqdn, FQDN_SIZE, "%s.%s", hname, dname);
		}
		else {
			strncpy(fqdn, hname, FQDN_SIZE);
		}
#endif
	}

	he=gethostbyname(hname);
	if (he) {
		if (numeric == 1) {
			snprintf(hlp, 15, "%s", inet_ntoa(*(struct in_addr *) he->h_addr_list[0]));
			strncpy(fqdn, hlp, FQDN_SIZE);
		}
		else {
			if ((strchr(he->h_name, '.'))!=NULL && (strchr(hname, '.'))==NULL) {
				strncpy(fqdn, he->h_name, FQDN_SIZE);
			}
			else {
				strncpy(fqdn, hname, FQDN_SIZE);
			}
		}
	}
	else {
		fprintf(stderr, "error: cannot resolve local hostname: %s\n", hname);
		exit_code(2);
	}
	if ((strchr(fqdn, '.'))==NULL) {
		if (hostname) {
			fprintf(stderr, "warning: %s is not resolvable... continouing anyway\n", fqdn);
			strncpy(fqdn, hostname, FQDN_SIZE);
		}
		else {
			fprintf(stderr, "error: this FQDN or IP is not valid: %s\n", fqdn);
			exit_code(2);
		}
	}

	if (verbose > 2)
		printf("fqdnhostname: %s\n", fqdn);
}

/* this function searches for search in mess and replaces it with
   replacement */
void replace_string(char *mess, char *search, char *replacement){
	char *backup, *insert;

	insert=STRCASESTR(mess, search);
	if (insert==NULL){
		if (verbose > 2)
			fprintf(stderr, "warning: could not find this '%s' replacement string in "
					"message\n", search);
	}
	else {
		while (insert){
			backup=str_alloc(strlen(insert)+1);
			strcpy(backup, insert+strlen(search));
			strcpy(insert, replacement);
			strcpy(insert+strlen(replacement), backup);
			free(backup);
			insert=STRCASESTR(mess, search);
		}
	}
}

/* insert \r in front of all \n if it is not present allready */
void insert_cr(char *mes){
	char *lf, *pos, *backup;

	pos = mes;
	lf = strchr(pos, '\n');
	while ((lf != NULL) && (*(--lf) != '\r')) {
		backup=str_alloc(strlen(lf)+2);
		strcpy(backup, lf+1);
		*(lf+1) = '\r';
		strcpy(lf+2, backup);
		free(backup);
		pos = lf+3;
		lf = strchr(pos, '\n');
	}
	lf = STRCASESTR(mes, "\r\n\r\n");
	if (lf == NULL) {
		lf = mes + strlen(mes);
		sprintf(lf, "\r\n");
	}
}

/* sipmly swappes the content of the two buffers */
void swap_buffers(char *fst, char *snd) {
	char *tmp;

	if (fst == snd)
		return;
	tmp = str_alloc(strlen(fst)+1);
	strcpy(tmp, fst);
	strcpy(fst, snd);
	strcpy(snd, tmp);
	free(tmp);
}

void swap_ptr(char **fst, char **snd)
{
	char *tmp;

	tmp = *fst;
	*fst = *snd;
	*snd = tmp;
}

/* trashes one character in buff randomly */
void trash_random(char *message)
{
	int r;
	float t;
	char *position;

	t=(float)rand()/RAND_MAX;
	r=(int)(t * (float)strlen(message));
	position=message+r;
	r=(int)(t*(float)255);
	*position=(char)r;
	if (verbose > 2)
		printf("request:\n%s\n", message);
}

/* this function is taken from traceroute-1.4_p12 
   which is distributed under the GPL and it returns
   the difference between to timeval structs */
double deltaT(struct timeval *t1p, struct timeval *t2p)
{
	register double dt;

	dt = (double)(t2p->tv_sec - t1p->tv_sec) * 1000.0 +
			(double)(t2p->tv_usec - t1p->tv_usec) / 1000.0;
	return (dt);
}

/* returns one if the string contains only numbers otherwise zero */
int is_number(char *number)
{
	int digit = 1;
	while (digit && (*number != '\0')) {
		digit = isdigit(*number);
		number++;
	}
	return digit;
}

/* tries to convert the given string into an integer. it strips
 * white-spaces and exits if an error happens */
int str_to_int(char *num)
{
	int ret;

#ifdef HAVE_STRTOL
	errno = 0;
	ret = strtol(num, NULL, 10);
	if (errno == EINVAL || errno == ERANGE) {
		printf("%s\n", num);
		perror("integer converting error");
		exit_code(2);
	}
#else
	char backup;
	int len = strlen(num);
	char *start = num;
	char *end = num + len;

	while (!isdigit(*start) && isspace(*start) && start < end)
		start++;
	end = start;
	end++;
	while (end < num + len && *end != '\0' && !isspace(*end))
		end++;
	backup = *end;
	*end = '\0';
	if (!is_number(start)) {
		fprintf(stderr, "error: string is not a number: %s\n", start);
		exit_code(2);
	}
	ret = atoi(start);
	*end = backup;
	if (ret <= 0) {
		fprintf(stderr, "error: failed to convert string to integer: %s\n", num);
		exit_code(2);
	}
#endif
	return ret;
}

/* reads into the given buffer from standard input until the EOF
 * character or the given size of the buffer is exceeded */
int read_stdin(char *buf, int size)
{
	int i, j;

	for(i = 0; i < size - 1; i++) {
		j = getchar();
		if (j == EOF) {
			*(buf + i) = '\0';
			return i;
		}
		else {
			*(buf + i) = j;
		}
	}
	*(buf + i) = '\0';
	if (verbose)
		fprintf(stderr, "warning: readin buffer size exceeded\n");
	return i;
}

/* tries to allocate the given size of memory and sets it all to zero.
 * if the allocation fails it exits */
void *str_alloc(size_t size)
{
	char *ptr;
#ifdef HAVE_CALLOC
	ptr = calloc(1, size);
#else
	ptr = malloc(size);
#endif
	if (ptr == NULL) {
		fprintf(stderr, "error: memory allocation failed\n");
		exit_code(255);
	}
#ifndef HAVE_CALLOC
	memset(ptr, 0, size);
#endif
	return ptr;
}
