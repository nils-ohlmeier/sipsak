/*
 * $Id: helper.c,v 1.3 2003/11/30 20:59:49 calrissian Exp $
 *
 * Copyright (C) 2002-2003 Fhg Fokus
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

#include <stdlib.h>
#include <netdb.h>
#include <sys/utsname.h>
/*
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
*/

#include "helper.h"
#include "sipsak.h"

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

long getaddress(char *host)
{
	int i=0;
	int dotcount=0;
	char *p = host;
	struct hostent* pent;
	long l, *lp;

	/*try understanding if this is a valid ip address
	we are skipping the values of the octets specified here.
	for instance, this code will allow 952.0.320.567 through*/
	while (*p)
	{
		for (i = 0; i < 3; i++, p++)
			if (!isdigit(*p))
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
		perror("gethostbyname error");
		exit(2);
	}
	lp = (long *) (pent->h_addr);
	l = *lp;
	return l;
}

/* because the full qualified domain name is needed by many other
   functions it will be determined by this function.
*/
void get_fqdn(){
	char hname[100], dname[100], hlp[18];
	size_t namelen=100;
	struct hostent* he;
	struct utsname un;
	int i;
	unsigned char *addrp;
	char *fqdnp;

	if (hostname) {
		strcpy(fqdn, hostname);
		strcpy(hname, hostname);
	}
	else {
		if ((uname(&un))==0) {
			strcpy(hname, un.nodename);
		}
		else {
			if (gethostname(&hname[0], namelen) < 0) {
				printf("error: cannot determine hostname\n");
				exit(2);
			}
		}
		/* a hostname with dots should be a domainname */
		if ((strchr(hname, '.'))==NULL) {
			if (getdomainname(&dname[0], namelen) < 0) {
				printf("error: cannot determine domainname\n");
				exit(2);
			}
			if (strcmp(&dname[0],"(none)")!=0)
				sprintf(fqdn, "%s.%s", hname, dname);
		}
		else {
			strcpy(fqdn, hname);
		}
	}

	he=gethostbyname(hname);
	if (he) {
		if (numeric) {
			addrp = he->h_addr_list[0];
			hlp[0]=fqdn[0]='\0';
			fqdnp = &fqdn[0];
			for (i = 0; i < 3; i++) {
				sprintf(hlp, "%i.", addrp[i]);
				fqdnp = strcat(fqdn, hlp);
			}
			sprintf(hlp, "%i", addrp[3]);
			fqdnp = strcat(fqdn, hlp);
		}
		else {
			strcpy(fqdn, he->h_name);
		}
	}
	else {
		printf("error: cannot resolve hostname: %s\n", hname);
		exit(2);
	}
	if ((strchr(fqdn, '.'))==NULL) {
		printf("error: this FQDN or IP is not valid: %s\n", fqdn);
		exit(2);
	}

	if (verbose > 2)
		printf("fqdnhostname: %s\n", fqdn);
}

/* this function searches for search in mess and replaces it with
   replacement */
void replace_string(char *mess, char *search, char *replacement){
	char *backup, *insert;

	insert=strstr(mess, search);
	if (insert==NULL){
		if (verbose > 2)
			printf("warning: could not find this '%s' replacement string in "
					"message\n", search);
	}
	else {
		while (insert){
			backup=malloc(strlen(insert)+1);
			strcpy(backup, insert+strlen(search));
			strcpy(insert, replacement);
			strcpy(insert+strlen(replacement), backup);
			free(backup);
			insert=strstr(mess, search);
		}
	}
}

/* trashes one character in buff randomly */
void trash_random(char *message)
{
	int r;
	float t;
	char *position;

	t=(float)rand()/RAND_MAX;
	r=t * (float)strlen(message);
	position=message+r;
	r=t*(float)255;
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

