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

#include "helper.h"
#include "exit_code.h"

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
	int i=0;
	int dotcount=0;
	char *p = host;
	struct hostent* pent;
	long l, *lp;

	/*try understanding if this is a valid ip address
	we are skipping the values of the octets specified here.
	for instance, this code will allow 952.0.320.567 through*/
	while (*p != '\0')
	{
		for (i = 0; i < 3; i++, p++)
			if (isdigit((int)*p) == 0)
				break;
		if (*p != '.')
			break;
		p++;
		dotcount++;
	}

	/* three dots with upto three digits in before, between and after ? */
	if (dotcount == 3 && i > 0 && i <= 3)
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

unsigned long getsrvaddress(char *host, int *port) {
#ifdef HAVE_RULI_H
	int srv_code;

	ruli_sync_t *sync_query = ruli_sync_query("_sip._udp", host, -1, RULI_RES_OPT_SEARCH | RULI_RES_OPT_SRV_NOINET6 | RULI_RES_OPT_SRV_NOSORT6);

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
		printf("Empty SRV list for: %s\n", host);
		exit_code(2);
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
#else
	return 0;
#endif // HAVE_RULI_H
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
				printf("error: cannot determine hostname\n");
				exit_code(2);
			}
		}
#ifdef HAVE_GETDOMAINNAME
		/* a hostname with dots should be a domainname */
		if ((strchr(hname, '.'))==NULL) {
			if (getdomainname(&dname[0], namelen) < 0) {
				printf("error: cannot determine domainname\n");
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
		printf("error: cannot resolve hostname: %s\n", hname);
		exit_code(2);
	}
	if ((strchr(fqdn, '.'))==NULL) {
		if (hostname) {
			printf("WARNING: %s is not resolvable... continouing anyway\n", fqdn);
			strncpy(fqdn, hostname, FQDN_SIZE);
		}
		else {
			printf("error: this FQDN or IP is not valid: %s\n", fqdn);
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
			printf("warning: could not find this '%s' replacement string in "
					"message\n", search);
	}
	else {
		while (insert){
			backup=malloc(strlen(insert)+1);
			if (!backup) {
				printf("failed to allocate memory\n");
				exit_code(255);
			}
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
		backup=malloc(strlen(lf)+2);
		if (!backup) {
			printf("failed to allocate memory\n");
			exit_code(255);
		}
		strcpy(backup, lf+1);
		//strncpy(lf, "\r", 1);
		*(lf+1) = '\r';
		strcpy(lf+2, backup);
		free(backup);
		pos = lf+3;
		lf = strchr(pos, '\n');
	}
}

/* sipmly swappes the content of the two buffers */
void swap_buffers(char *fst, char *snd) {
	char *tmp;

	if (fst == snd)
		return;
	tmp = malloc(strlen(fst)+1);
	if (!tmp) {
		printf("failed to allocate memory\n");
		exit_code(255);
	}
	memset(tmp, 0, strlen(fst)+1);
	strcpy(tmp, fst);
	strcpy(fst, snd);
	strcpy(snd, tmp);
	free(tmp);
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

int str_to_int(char *num)
{
	int ret;

#ifdef HAVE_STRTOL
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
		printf("error: string is not a number: %s\n", start);
		exit_code(2);
	}
	ret = atoi(start);
	*end = backup;
	if (ret <= 0) {
		printf("error: failed to convert string to integer: %s\n", num);
		exit_code(2);
	}
#endif
	return ret;
}
