/*
 * $Id: sipsak.c,v 1.33 2003/01/17 04:54:45 calrissian Exp $
 *
 * Copyright (C) 2002 Fhg Fokus
 *
 * This file is sipsak, a free sip testing tool.
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

/* sipsak written by nils ohlmeier (develop@ohlmeier.de).
   based up on a modifyed version of shoot.
*/

/* changes by jiri@iptel.org; now messages can be really received;
   status code returned is 2 for some local errors , 0 for success
   and 1 for remote error -- ICMP/timeout; can be used to test if
   a server is alive; 1xx messages are now ignored; windows support
   dropped
*/

/*
shot written by ashhar farhan, is not bound by any licensing at all.
you are free to use this code as you deem fit. just dont blame the author
for any problems you may have using it.
bouquets and brickbats to farhan@hotfoon.com
*/

/* TO-DO:
   - multiple contacts in USRLOC mode
   - endless randtrash mode with logfile
   - support for short notation
   - support for IPv6
*/

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/utsname.h>

#include <regex.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>

#ifdef AUTH
#include <openssl/md5.h>
#endif

#define SIPSAK_VERSION "v0.7.7"
#define RESIZE		1024
#define BUFSIZE		4096
#define FQDN_SIZE   200
#define REQ_INV 1
#define REQ_REG 2
#define REQ_OPT 3
#define REQ_FLOOD 4
#define REQ_RAND 5
#define REQ_REM 6
#define VIA_STR "Via: SIP/2.0/UDP "
#define VIA_STR_LEN 17
#define MAX_FRW_STR "Max-Forwards: "
#define MAX_FRW_STR_LEN 14
#define SIP20_STR " SIP/2.0\r\n"
#define SIP20_STR_LEN 10
#define SIP200_STR "SIP/2.0 200 OK\r\n"
#define SIP200_STR_LEN 16
#define REG_STR "REGISTER"
#define REG_STR_LEN 8
#define OPT_STR "OPTIONS"
#define OPT_STR_LEN 7
#define MES_STR "MESSAGE"
#define MES_STR_LEN 7
#define FROM_STR "From: "
#define FROM_STR_LEN 6
#define TO_STR "To: "
#define TO_STR_LEN 4
#define CALL_STR "Call-ID: "
#define CALL_STR_LEN 9
#define CSEQ_STR "CSeq: "
#define CSEQ_STR_LEN 6
#define CONT_STR "Contact: "
#define CONT_STR_LEN 9
#define CON_TXT_STR "Content-Type: text/plain\r\n"
#define CON_TXT_STR_LEN 26
#define CON_LEN_STR "Content-Length: "
#define CON_LEN_STR_LEN 16
#define SIPSAK_MES_STR "USRLOC test message from SIPsak for user "
#define SIPSAK_MES_STR_LEN 41
#define EXP_STR "Expires: "
#define EXP_STR_LEN 9
#define CON_EXP_STR "expires="
#define CONEXP_STR_LEN 8
#define USRLOC_EXP_DEF 15
#define FLOOD_METH "OPTIONS"
#define USRLOC_REMOVE_PERCENT 0.1
#define WWWAUTH_STR "WWW-Authenticate: "
#define WWWAUTH_STR_LEN 18
#define AUTH_STR "Authorization: Digest "
#define AUTH_STR_LEN 22
#define REALM_STR "realm="
#define REALM_STR_LEN 6
#define OPAQUE_STR "opaque="
#define NONCE_STR "nonce="
#define NONCE_STR_LEN 6
#define RESPONSE_STR "response="
#define RESPONSE_STR_LEN 9
#define QOP_STR "qop="
#define QOP_STR_LEN 4
#define QOPAUTH_STR "\"auth\""
#define NC_STR "nc="
#define UA_STR "User-Agent: "

#define HASHHEXLEN 2*MD5_DIGEST_LENGTH

/* lots of global variables. ugly but makes life easier. */
long address;
int verbose, nameend, namebeg, expires_t, flood, warning_ext;
int maxforw, lport, rport, randtrash, trashchar, numeric, nonce_count;
int file_b, uri_b, trace, via_ins, usrloc, redirects, rand_rem, replace_b;
char *username, *domainname, *password, *replace_str;
char fqdn[FQDN_SIZE], messusern[FQDN_SIZE];
char message[BUFSIZE], mes_reply[BUFSIZE];

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
	int i, dotcount=0;
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
		perror("no gethostbyname");
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

/* add a Via Header Field in the message. */
void add_via(char *mes)
{
	char *via_line, *via, *via2, *backup; 

	/* first build our own Via-header-line */
	via_line = malloc(VIA_STR_LEN+strlen(fqdn)+9);
	sprintf(via_line, "%s%s:%i\r\n", VIA_STR, fqdn, lport);
	if (verbose > 2)
		printf("our Via-Line: %s\n", via_line);

	if (strlen(mes)+strlen(via_line)>= BUFSIZE){
		printf("can't add our Via Header Line because file is too big\n");
		exit(2);
	}
	via=strstr(mes, "\nVia");
	via2=strstr(mes, "\nv:");
	if (via==NULL && via2==NULL ){
		/* We doesn't find a Via so we insert our via
		   direct after the first line. */
		via=strchr(mes,'\n');
		via++;
	}
	else if (via!=NULL && via2!=NULL && via2<via){
		/* the short via is above the long version */
		via = via2;
	}
	else if (via==NULL && via2!=NULL){
		/* their is only a short via */
		via = via2;
	}
	via=via+1;
	/* finnaly make a backup, insert our via and append the backup */
	backup=malloc(strlen(via)+1);
	strncpy(backup, via, strlen(via)+1);
	strncpy(via, via_line, strlen(via_line));
	strncpy(via+strlen(via_line), backup, strlen(backup)+1);
	free(via_line);
	free(backup);
	if (verbose > 1)
		printf("New message with Via-Line:\n%s\n", mes);
}

/* copy the via lines from the message to the message 
   reply for correct routing of our reply.
*/
void cpy_vias(char *reply){
	char *first_via, *middle_via, *last_via, *backup;

	/* lets see if we find any via */
	if ((first_via=strstr(reply, "Via:"))==NULL &&
		(first_via=strstr(reply, "\nv:"))==NULL ){
		printf("error: the received message doesn't contain a Via header\n");
		exit(3);
	}
	last_via=first_via+4;
	middle_via=last_via;
	/* proceed additional via lines */
	while ((middle_via=strstr(last_via, "Via:"))!=NULL &&
		   (middle_via=strstr(last_via, "\nv:"))!=NULL )
		last_via=middle_via+4;
	last_via=strchr(last_via, '\n');
	middle_via=strchr(mes_reply, '\n')+1;
	/* make a backup, insert the vias after the first line and append 
	   backup
	*/
	backup=malloc(strlen(middle_via)+1);
	strcpy(backup, middle_via);
	strncpy(middle_via, first_via, last_via-first_via+1);
	strcpy(middle_via+(last_via-first_via+1), backup);
	free(backup);
	if (verbose > 2)
		printf("message reply with vias included:\n%s\n", mes_reply);
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

/* create a valid sip header for the different modes */
void create_msg(char *buff, int action){
	unsigned int c;
	char *usern;

	c=rand();
	switch (action){
		case REQ_REG:
			if (verbose > 2)
				printf("username: %s\ndomainname: %s\n", username, domainname);
			usern=malloc(strlen(username)+10);
			if (nameend>0) {
				sprintf(messusern, "%s sip:%s%i", MES_STR, username, namebeg);
				sprintf(usern, "%s%i", username, namebeg);
			}
			else {
				sprintf(messusern, "%s sip:%s", MES_STR, username);
				sprintf(usern, "%s", username);
			}
			/* build the register, message and the 200 we need in for 
			   USRLOC on one function call*/
			sprintf(buff, "%s sip:%s%s%s%s:%i\r\n%s<sip:%s@%s>\r\n"
				"%s<sip:%s@%s>\r\n%s%u@%s\r\n%s%i %s\r\n%s<sip:%s@%s:%i>\r\n"
				"%s%i\r\n%ssipsak %s\r\n\r\n", REG_STR, domainname, SIP20_STR, 
				VIA_STR, fqdn, lport, FROM_STR, usern, domainname, TO_STR, 
				usern, domainname, CALL_STR, c, fqdn, CSEQ_STR, 3*namebeg+1, 
				REG_STR, CONT_STR, usern, fqdn, lport, EXP_STR, expires_t, 
				UA_STR, SIPSAK_VERSION);
			c=rand();
			sprintf(message, "%s sip:%s@%s%s%s%s:%i\r\n%s<sip:sipsak@%s:%i>\r\n"
				"%s<sip:%s@%s>\r\n%s%u@%s\r\n%s%i %s\r\n%s%s%i\r\n%ssipsak %s"
				"\r\n\r\n%s%s%i.", MES_STR, usern, domainname, SIP20_STR, 
				VIA_STR, fqdn, lport, FROM_STR, fqdn, lport, TO_STR, usern, 
				domainname, CALL_STR, c, fqdn, CSEQ_STR, 3*namebeg+2, MES_STR, 
				CON_TXT_STR, CON_LEN_STR, SIPSAK_MES_STR_LEN+strlen(usern), 
				UA_STR, SIPSAK_VERSION,	SIPSAK_MES_STR, username, namebeg);
			sprintf(mes_reply, "%s%s<sip:sipsak@%s:%i>\r\n%s<sip:%s@%s>\r\n"
				"%s%u@%s\r\n%s%i %s\r\n%s 0\r\n%ssipsak %s\r\n\r\n", 
				SIP200_STR, FROM_STR, fqdn, lport, TO_STR, usern, domainname, 
				CALL_STR, c, fqdn, CSEQ_STR, 3*namebeg+2, MES_STR, CON_LEN_STR,
				UA_STR, SIPSAK_VERSION);
			if (verbose > 2) {
				printf("message:\n%s\n", message);
				printf("message reply:\n%s\n", mes_reply);
			}
			free(usern);
			break;
		case REQ_OPT:
			sprintf(buff, "%s sip:%s@%s%s%s<sip:sipsak@%s:%i>\r\n"
				"%s<sip:%s@%s>\r\n%s%u@%s\r\n%s%i %s\r\n"
				"%s<sip:sipsak@%s:%i>\r\n%ssipsak %s\r\n\r\n", OPT_STR, 
				username, domainname, SIP20_STR, FROM_STR, fqdn, lport, TO_STR,
				username, domainname, CALL_STR, c, fqdn, CSEQ_STR, namebeg, 
				OPT_STR, CONT_STR, fqdn, lport, UA_STR, SIPSAK_VERSION);
			break;
		case REQ_FLOOD:
			sprintf(buff, "%s sip:%s%s%s%s:9\r\n%s<sip:sipsak@%s:9>\r\n"
				"%s<sip:%s>\r\n%s%u@%s\r\n%s%i %s\r\n%s<sipsak@%s:9>\r\n%s"
				"sipsak %s\r\n\r\n", FLOOD_METH, domainname, SIP20_STR, 
				VIA_STR, fqdn, FROM_STR, fqdn, TO_STR, domainname, CALL_STR, c,
				fqdn, CSEQ_STR, namebeg, FLOOD_METH, CONT_STR, fqdn, UA_STR, 
				SIPSAK_VERSION);
			break;
		case REQ_RAND:
			sprintf(buff, "%s sip:%s%s%s%s:%i\r\n%s<sip:sipsak@%s:%i>\r\n"
				"%s<sip:%s>\r\n%s%u@%s\r\n%s%i %s\r\n%s<sipsak@%s:%i>\r\n%s"
				"sipsak %s\r\n\r\n", OPT_STR, domainname, SIP20_STR, VIA_STR, 
				fqdn, lport, FROM_STR, fqdn, lport, TO_STR, domainname, 
				CALL_STR, c, fqdn, CSEQ_STR, namebeg, OPT_STR, CONT_STR, fqdn,
				lport, UA_STR, SIPSAK_VERSION);
			break;
		case REQ_REM:
			usern=malloc(strlen(username)+10);
			sprintf(usern, "%s%i", username, namebeg);
			sprintf(buff, "%s sip:%s%s%s%s:%i\r\n%s<sip:%s@%s>\r\n"
				"%s<sip:%s@%s>\r\n%s%u@%s\r\n%s%i %s\r\n%s<sip:%s@%s:%i>;%s0"
				"\r\n%s%i\r\n%ssipsak %s\r\n\r\n", REG_STR, domainname, 
				SIP20_STR, VIA_STR, fqdn, lport, FROM_STR, usern, domainname,
				TO_STR, usern, domainname, CALL_STR, c, fqdn, CSEQ_STR, 
				3*namebeg+3, REG_STR, CONT_STR, usern, fqdn, lport, 
				CON_EXP_STR, EXP_STR, expires_t, UA_STR, SIPSAK_VERSION);
			break;
		default:
			printf("error: unknown request type to create\n");
			exit(2);
			break;
	}
	if (verbose > 2)
		printf("request:\n%s", buff);
}

/* check for the existence of a Max-Forwards header field. if its 
   present it sets it to the given value, if not it will be inserted.*/
void set_maxforw(char *mes){
	char *max, *backup, *crlf;

	if ((max=strstr(mes, "Max-Forwards:"))==NULL){
		/* no max-forwards found so insert it after the first line*/
		max=strchr(mes,'\n');
		max++;
		backup=malloc(strlen(max)+1);
		strncpy(backup, max, strlen(max)+1);
		sprintf(max, "%s%i\r\n", MAX_FRW_STR, maxforw);
		max=strchr(max,'\n');
		max++;
		strncpy(max, backup, strlen(backup)+1);
		free(backup);
		if (verbose > 1)
			printf("Max-Forwards %i inserted into header\n", maxforw);
		if (verbose > 2)
			printf("New message with inserted Max-Forwards:\n%s\n", mes);
	}
	else{
		/* found max-forwards => overwrite the value with maxforw*/
		crlf=strchr(max,'\n');
		crlf++;
		backup=malloc(strlen(crlf)+1);
		strncpy(backup, crlf, strlen(crlf)+1);
		crlf=max + MAX_FRW_STR_LEN;
		sprintf(crlf, "%i\r\n", maxforw);
		crlf=strchr(max,'\n');
		crlf++;
		strncpy(crlf, backup, strlen(backup)+1);
		crlf=crlf+strlen(backup);
		free(backup);
		if (verbose > 1)
			printf("Max-Forwards set to %i\n", maxforw);
		if (verbose > 2)
			printf("New message with changed Max-Forwards:\n%s\n", mes);
	}
}

/* replaces the uri in first line of mes with the other uri */
void uri_replace(char *mes, char *uri)
{
	char *foo, *backup;

	foo=strchr(mes, '\n');
	foo++;
	backup=malloc(strlen(foo)+1);
	strncpy(backup, foo, strlen(foo)+1);
	foo=strstr(mes, "sip");
	strncpy(foo, uri, strlen(uri));
	strncpy(foo+strlen(uri), SIP20_STR, SIP20_STR_LEN);
	strncpy(foo+strlen(uri)+SIP20_STR_LEN, backup, strlen(backup)+1);
	free(backup);
	if (verbose > 2)
		printf("Message with modified uri:\n%s\n", mes);
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

/* tryes to find the warning header filed and prints out the IP */
void warning_extract(char *message)
{
	char *warning, *end, *mid, *server;
	int srvsize;

	warning=strstr(message, "Warning:");
	if (warning) {
		end=strchr(warning, '"');
		end--;
		warning=strchr(warning, '3');
		warning=warning+4;
		mid=strchr(warning, ':');
		if (mid) end=mid;
		srvsize=end - warning + 1;
		server=malloc(srvsize);
		memset(server, 0, srvsize);
		server=strncpy(server, warning, srvsize - 1);
		printf("%s ", server);
	}
	else {
		if (verbose) printf("'no Warning header found' ");
		else printf("?? ");
	}
}

#ifdef AUTH
/* converts a hash into hex output
   taken from the RFC 2617 */
void cvt_hex(char *_b, char *_h)
{
        unsigned short i;
        unsigned char j;

        for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
                j = (_b[i] >> 4) & 0xf;
                if (j <= 9) {
                        _h[i * 2] = (j + '0');
                } else {
                        _h[i * 2] = (j + 'a' - 10);
                }
                j = _b[i] & 0xf;
                if (j <= 9) {
                        _h[i * 2 + 1] = (j + '0');
                } else {
                        _h[i * 2 + 1] = (j + 'a' - 10);
                }
        };
        _h[HASHHEXLEN] = '\0';
}

/* check for, create and insert a auth header into the message */
void insert_auth(char *message, char *authreq)
{
	char *auth, *begin, *end, *insert, *backup, *realm, *usern, *nonce, 
		*method, *uri, *ha1_tmp, *ha2_tmp, *resp_tmp, *qop_tmp;
	char ha1[MD5_DIGEST_LENGTH], ha2[MD5_DIGEST_LENGTH], 
		resp[MD5_DIGEST_LENGTH]; 
	char ha1_hex[HASHHEXLEN], ha2_hex[HASHHEXLEN], resp_hex[HASHHEXLEN];
	int cnonce, qop_auth=0;

	/* prevent double auth insertion */
	if ((begin=strstr(message, AUTH_STR))!=NULL) {
		printf("\nrequest:\n%s\nresponse:\n%s\nerror: authorization failed\n  "
			"     request already contains Authorization, but received 401, "
			"see above\n", message, authreq);
		exit(2);
	}
	/* make a backup of all except the request line because for 
	   simplicity we insert the auth header direct behind the request line */
	insert=strchr(message, '\n');
	insert++;
	backup=malloc(strlen(insert)+1);
	strncpy(backup, insert, strlen(insert)+1);

	begin=strstr(authreq, WWWAUTH_STR);
	if (begin) {
		/* make a copy of the auth header to prevent that our searches
		   hit content of other header fields */
		end=strchr(begin, '\n');
		auth=malloc((end-begin)+1);
		strncpy(auth, begin, (end-begin));
		*(auth+(end-begin))='\0';
		/* we support Digest nad MD5 only */
		if ((begin=strstr(auth, "Basic"))!=NULL) {
			printf("%s\nerror: authentication method Basic is deprecated since"
				" RFC 3261 and not supported by sipsak\n", authreq);
			exit(3);
		}
		if ((begin=strstr(auth, "Digest"))==NULL) {
			printf("%s\nerror: couldn't find authentication method Digest in "
				"the 402 response above\n", authreq);
			exit(3);
		}
		if ((begin=strstr(auth, "algorithm="))!=NULL) {
			begin+=10;
			if ((strncmp(begin, "MD5", 3))!=0) {
				printf("%s\nerror: unsupported authentication algorithm\n", 
					authreq);
				exit(2);
			}
		}
		/* we need the username at some points */
		usern=malloc(strlen(username)+10);
		if (nameend>0)
			sprintf(usern, "%s%i", username, namebeg);
		else
			sprintf(usern, "%s", username);
		/* extract the method from teh original request */
		end=strchr(message, ' ');
		method=malloc(end-message+1);
		strncpy(method, message, (end-message));
		*(method+(end-message))='\0';
		/* extract the uri also */
		begin=end++;
		begin++;
		end=strchr(end, ' ');
		uri=malloc(end-begin+1);
		strncpy(uri, begin, (end-begin));
		*(uri+(end-begin))='\0';

		/* lets start with some basic stuff... username, uri and algorithm */
		sprintf(insert, AUTH_STR);
		insert=insert+AUTH_STR_LEN;
		sprintf(insert, "username=\"%s\", ", usern);
		insert+=strlen(insert);
		sprintf(insert, "uri=\"%s\", ", uri);
		insert+=strlen(insert);
		sprintf(insert, "algorithm=MD5, ");
		insert+=15;
		/* search for the realm, copy it to request and extract it for hash*/
		if ((begin=strstr(auth, REALM_STR))!=NULL) {
			end=strchr(begin, ',');
			strncpy(insert, begin, end-begin+1);
			insert=insert+(end-begin+1);
			sprintf(insert, " ");
			insert++;
			begin+=REALM_STR_LEN+1;
			end--;
			realm=malloc(end-begin+1);
			strncpy(realm, begin, (end-begin));
			*(realm+(end-begin))='\0';
		}
		else {
			printf("%s\nerror: realm not found in 401 above\n", authreq);
			exit(3);
		}
		/* copy opaque if needed */
		if ((begin=strstr(auth, OPAQUE_STR))!=NULL) {
			end=strchr(begin, ',');
			strncpy(insert, begin, end-begin+1);
			insert=insert+(end-begin+1);
			sprintf(insert, " ");
			insert++;
		}
		/* lets see if qop=auth is uspported */
		if ((begin=strstr(auth, QOP_STR))!=NULL) {
			if (strstr(begin, QOPAUTH_STR)==NULL) {
				printf("\nresponse\n%s\nerror: qop \"auth\" not supported by"
					" server\n", authreq);
				exit(3);
			}
			qop_auth=1;
		}
		/* search, copy and extract the nonce */
		if ((begin=strstr(auth, NONCE_STR))!=NULL) {
			end=strchr(begin, ',');
			strncpy(insert, begin, end-begin+1);
			insert=insert+(end-begin+1);
			sprintf(insert, " ");
			insert++;
			begin+=NONCE_STR_LEN+1;
			end--;
			nonce=malloc(end-begin+1);
			strncpy(nonce, begin, (end-begin));
			*(nonce+(end-begin))='\0';
		}
		else {
			printf("%s\nerror: nonce not found in 401 above\n", authreq);
			exit(3);
		}
		/* if qop is supported we need som additional header */
		if (qop_auth) {
			sprintf(insert, "%s%s, ", QOP_STR, QOPAUTH_STR);
			insert+=strlen(insert);
			nonce_count++;
			sprintf(insert, "%s%x, ", NC_STR, nonce_count);
			insert+=strlen(insert);
			cnonce=rand();
			sprintf(insert, "cnonce=\"%x\", ", cnonce);
			insert+=strlen(insert);
			/* hopefully 100 is enough */
			qop_tmp=malloc(100);
			sprintf(qop_tmp, "%x:%x:auth:", nonce_count, cnonce);
		}
		/* if no password is given we try it with the username */
		if (!password)
			password=usern;
		ha1_tmp=malloc(strlen(usern)+strlen(realm)+strlen(password)+3);
		if (qop_auth)
			resp_tmp=malloc(2*HASHHEXLEN+strlen(nonce)+strlen(qop_tmp)+3);
		else
			resp_tmp=malloc(2*HASHHEXLEN+strlen(nonce)+3);
		sprintf(ha1_tmp, "%s:%s:%s", usern, realm, password);
		MD5(ha1_tmp, strlen(ha1_tmp), ha1);
		cvt_hex(ha1, ha1_hex);
		/* later ha1_hex is empty.. why th f***.. let's do it here */
		sprintf(resp_tmp, "%s:%s:", ha1_hex, nonce);
		if (qop_auth)
			sprintf(resp_tmp+strlen(resp_tmp), "%s", qop_tmp);
		ha2_tmp=malloc(strlen(method)+strlen(uri)+2);
		sprintf(ha2_tmp, "%s:%s", method, uri);
		MD5(ha2_tmp, strlen(ha2_tmp), ha2);
		cvt_hex(ha2, ha2_hex);
		sprintf(resp_tmp+strlen(resp_tmp), "%s", ha2_hex);
		MD5(resp_tmp, strlen(resp_tmp), resp);
		cvt_hex(resp, resp_hex);
		sprintf(insert, RESPONSE_STR);
		insert+=RESPONSE_STR_LEN;
		sprintf(insert, "\"%s\"\r\n", resp_hex);
		insert+=strlen(insert);
		/* the auth header is complete, reinsert the rest of the request */
		strncpy(insert, backup, strlen(backup));
	}
	else {
		printf("%s\nerror: couldn't find WWW-Authentication header in the "
			"401 response above\n",	authreq);
		exit(3);
	}
	if (verbose>1) 
		printf("authorizing\n");
	/* hopefully we free all here */
	free(backup); free(auth); free(usern); free(method); free(uri); 
	free(realm); free(nonce); free(ha1_tmp); free(ha2_tmp); free(resp_tmp);
	if (qop_auth) free(qop_tmp);
}
#endif

int cseq(char *message)
{
	char *cseq;
	int num=-1;

	cseq=strstr(message, "CSeq");
	if (cseq) {
		cseq+=6;
		num=atoi(cseq);
		if (num < 1) {
			if (verbose > 2)
				printf("CSeq found but not convertable\n");
			return 0;
		}
		return num;
	}
	if (verbose > 2)
		printf("no CSeq found\n");
	return 0;
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

/* this is the main function with the loops and modes */
void shoot(char *buff)
{
	struct sockaddr_in	addr, sockname;
	struct timeval	tv, sendtime, recvtime, firstsendt, delaytime;
	struct timezone tz;
	struct pollfd sockerr;
	int ssock, redirected, retryAfter, nretries;
	int sock, i, len, ret, usrlocstep, randretrys;
	int dontsend, cseqcmp, cseqtmp;
	int rem_rand, rem_namebeg, retrans_r_c, retrans_s_c;
	double big_delay, tmp_delay;
	char *contact, *crlf, *foo, *bar, *lport_str;
	char reply[BUFSIZE];
	fd_set	fd;
	socklen_t slen;
	regex_t redexp, proexp, okexp, tmhexp, errexp, authexp;

	/* initalize some local vars */
	redirected = 1;
	nretries = 5;
	retryAfter = 5000;
	usrlocstep=dontsend=retrans_r_c=retrans_s_c = 0;
	big_delay=tmp_delay = 0;
	delaytime.tv_sec = 0;
	delaytime.tv_usec = 0;

	/* create a sending socket */
	sock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock==-1) {
		perror("no client socket");
		exit(2);
	}

	/* create a listening socket */
	ssock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ssock==-1) {
		perror("no server socket");
		exit(2);
	}

	sockname.sin_family=AF_INET;
	sockname.sin_addr.s_addr = htonl( INADDR_ANY );
	sockname.sin_port = htons((short)lport);
	if (bind( ssock, (struct sockaddr *) &sockname, sizeof(sockname) )==-1) {
		perror("no bind");
		exit(2);
	}

	/* for the via line we need our listening port number */
	if ((via_ins||usrloc) && lport==0){
		memset(&sockname, 0, sizeof(sockname));
		slen=sizeof(sockname);
		getsockname(ssock, (struct sockaddr *)&sockname, &slen);
		lport=ntohs(sockname.sin_port);
	}

	if (replace_b){
		replace_string(buff, "$host$", fqdn);
		lport_str=malloc(6);
		sprintf(lport_str, "%i", lport);
		replace_string(buff, "$port$", lport_str);
		free(lport_str);
	}
	if (replace_str)
		replace_string(buff, "$replace$", replace_str);

	/* set all regular expression to simplfy the result code indetification */
	regcomp(&proexp, "^SIP/[0-9]\\.[0-9] 1[0-9][0-9] ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE); 
	regcomp(&okexp, "^SIP/[0-9]\\.[0-9] 200 ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE); 
	regcomp(&redexp, "^SIP/[0-9]\\.[0-9] 3[0-9][0-9] ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE);
	regcomp(&authexp, "^SIP/[0-9]\\.[0-9] 401 ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE);
	regcomp(&errexp, "^SIP/[0-9]\\.[0-9] 4[0-9][0-9] ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE); 
	regcomp(&tmhexp, "^SIP/[0-9]\\.[0-9] 483 ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE); 

	if (usrloc){
		/* in usrloc every test consists of three steps */
		nretries=3*(nameend-namebeg)+3;
		create_msg(buff, REQ_REG);
	}
	else if (trace){
		/* for trace we need some spezial initis */
		if (maxforw!=-1)
			nretries=maxforw;
		else
			nretries=255;
		namebeg=1;
		maxforw=0;
		create_msg(buff, REQ_OPT);
		add_via(buff);
	}
	else if (flood){
		/* this should be the max of an (32 bit) int without the sign */
		if (namebeg==-1) namebeg=2147483647;
		nretries=namebeg;
		namebeg=1;
		create_msg(buff, REQ_FLOOD);
	}
	else if (randtrash){
		randretrys=0;
		namebeg=1;
		create_msg(buff, REQ_RAND);
		nameend=strlen(buff);
		if (trashchar){
			if (trashchar < nameend)
				nameend=trashchar;
			else
				printf("warning: number of trashed chars to big. setting to "
					"request lenght\n");
		}
		nretries=nameend-1;
		trash_random(buff);
	}
	else {
		/* for non of the modes we also need some inits */
		if (!file_b) {
			namebeg=1;
			create_msg(buff, REQ_OPT);
		}
		retryAfter = 500;
		if(maxforw!=-1)
			set_maxforw(buff);
		if(via_ins)
			add_via(buff);
	}

	/* if we got a redirect this loop ensures sending to the 
	   redirected server*/
	while (redirected) {
		/* we don't want to send for ever */
		redirected=0;

		/* destination socket init here because it could be changed in a 
		   case of a redirect */
		addr.sin_addr.s_addr = address;
		addr.sin_port = htons((short)rport);
		addr.sin_family = AF_INET;
	
		/* we connect as per the RFC 2543 recommendations
		   modified from sendto/recvfrom */
		ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
		if (ret==-1) {
			perror("no connect");
			exit(2);
		}

		/* here we go for the number of nretries which strongly depends on the 
		   mode */
		for (i = 0; i <= nretries; i++)
		{
			if (trace) {
				set_maxforw(buff);
			}
			/* some initial output */
			else if (usrloc && (verbose > 1) && !dontsend) {
				switch (usrlocstep) {
					case 0:
						if (nameend>0)
							printf("registering user %s%i... ", username, 
								namebeg);
						else
							printf("registering user %s... ", username);
						break;
					case 1:
						printf("sending message... ");
						break;
					case 2:
						printf("sending message reply... ");
						break;
					case 3:
						if (nameend>0)
							printf("remove binding for %s%i...", username, 
								namebeg);
						else
							printf("remove binding for %s...", username);
						break;
				}
			}
			else if (flood && verbose) {
				printf("flooding message number %i\n", i+1);
			}
			else if (randtrash && verbose) {
				printf("message with %i randomized chars\n", i+1);
				if (verbose > 2)
					printf("request:\n%s\n", buff);
			}
			else if (!trace && !usrloc && !flood && !randtrash && (verbose > 1)
						&& !dontsend){
				printf("** request **\n%s\n", buff);
			}

			if (! dontsend) {
				/* lets fire the request to the server and store when we did */
				ret = send(sock, buff, strlen(buff), 0);
				(void)gettimeofday(&sendtime, &tz);
				if (ret==-1) {
					printf("\n");
					perror("send failure");
					exit(2);
				}
			}
			else {
				i--;
				dontsend = 0;
			}

			/* in flood we are only interested in sending so skip the rest */
			if (!flood) {
				/* set the timeout and wait for a response */
				tv.tv_sec = retryAfter/1000;
				tv.tv_usec = (retryAfter % 1000) * 1000;

				FD_ZERO(&fd);
				FD_SET(ssock, &fd); 

				ret = select(FD_SETSIZE, &fd, NULL, NULL, &tv);
				(void)gettimeofday(&recvtime, &tz);
				if (ret == 0)
				{
					/* store the time of our first send */
					if (i==0)
						memcpy(&firstsendt, &sendtime, sizeof(struct timeval));
					/* lets see if we at least received an icmp error */
					sockerr.fd=sock;
					sockerr.events=POLLERR;
					if ((poll(&sockerr, 1, 10))==1) {
						if (sockerr.revents && POLLERR) {
							recv(sock, reply, strlen(reply), 0);
							printf("\n");
							perror("send failure");
							if (randtrash) 
								printf ("last message before send failure:"
									"\n%s\n", buff);
							exit(3);
						}
					}
					/* printout that we did not received anything */
					if (trace) printf("%i: timeout after %i ms\n", i, 
									retryAfter);
					else if (usrloc) {
						printf("timeout after %i ms\n", retryAfter);
						i--;
					}
					else if (verbose) printf("** timeout after %i ms**\n", 
										retryAfter);
					if (randtrash) {
						printf("did not get a response on this request:"
							"\n%s\n", buff);
						if (i+1 < nameend) {
							if (randretrys == 2) {
								printf("sended the following message three "
									"times without getting a response:\n%s\n"
									"give up further retransmissions...\n", 
									buff);
								exit(3);
							}
							else {
								printf("resending it without additional "
									"random changes...\n\n");
								randretrys++;
							}
						}
					}
					retryAfter = retryAfter * 2;
					if (retryAfter > 5000) retryAfter = 5000;
					retrans_s_c++;
					if (delaytime.tv_sec == 0)
						memcpy(&delaytime, &sendtime, sizeof(struct timeval));
					/* if we did not exit until here lets try another send */
					continue;
				}
				else if ( ret == -1 ) {
					perror("select error");
					exit(2);
				}
				else if (FD_ISSET(ssock, &fd)) {
					/* no timeout, no error ... something has happened :-) */
				 	if (!trace && !usrloc && !randtrash && verbose)
						printf ("\nmessage received\n");
				}
				else {
					printf("\nselect returned succesfuly, nothing received\n");
					continue;
				}

				/* we are retrieving only the extend of a decent 
				   MSS = 1500 bytes */
				len = sizeof(addr);
				ret = recv(ssock, reply, BUFSIZE, 0);
				if(ret > 0)
				{
					reply[ret] = 0;
					/* store the time of our first send */
					if (i==0)
						memcpy(&firstsendt, &sendtime, sizeof(struct timeval));
					/* store the biggest delay if one occured */
					if (delaytime.tv_sec != 0) {
						tmp_delay = deltaT(&delaytime, &recvtime);
						if (tmp_delay > big_delay) big_delay = tmp_delay;
						delaytime.tv_sec = 0;
						delaytime.tv_usec = 0;
					}
					/* check for old CSeq => ignore retransmission */
					if (usrloc) {
						switch (usrlocstep) {
							case 0: 
								cseqcmp = 3*namebeg+1;
								break;
							case 1:
							case 2:
								cseqcmp = 3*namebeg+2;
								break;
							case 3:
								cseqcmp = 3*namebeg+3;
								break;
							default:
								printf("error: unknown usrloc step on cseq"
									" compare\n");
								exit(2);
								break;
						}
					}
					else
						cseqcmp = namebeg;
					cseqtmp = cseq(reply);
					if ((0 < cseqtmp) && (cseqtmp < cseqcmp)) {
						if (verbose)
							printf("irgnoring retransmission\n");
						retrans_r_c++;
						dontsend = 1;
						continue;
					}
					/* lets see if received a redirect */
					if (redirects && regexec(&redexp, reply, 0, 0, 0)==0) {
						printf("** received redirect ");
						if (warning_ext) {
							printf("from ");
							warning_extract(reply);
							printf("\n");
						}
						else printf("\n");
						/* we'll try to handle 301 and 302 here, other 3xx 
						   are to complex */
						regcomp(&redexp, "^SIP/[0-9]\\.[0-9] 30[1-2] ", 
							REG_EXTENDED|REG_NOSUB|REG_ICASE);
						if (regexec(&redexp, reply, 0, 0, 0)==0) {
							/* try to find the contact in the redirect */
							if ((foo=strstr(reply, "Contact"))==NULL &&
								(foo=strstr(reply, "\nm:"))==NULL ) {
								printf("error: cannot find Contact in this "
									"redirect:\n%s\n", reply);
								exit(3);
							}
							crlf=strchr(foo, '\n');
							if ((contact=strchr(foo, '\r'))!=NULL 
							&& contact<crlf)
								crlf=contact;
							bar=malloc(crlf-foo+1);
							strncpy(bar, foo, crlf-foo);
							*(bar+(crlf-foo))='\0';
							if ((contact=strstr(bar, "sip"))==NULL) {
								printf("error: cannot find sip in the Contact "
									"of this redirect:\n%s\n", reply);
								exit(3);
							}
							if ((foo=strchr(contact, ';'))!=NULL)
								*foo='\0';
							if ((foo=strchr(contact, '>'))!=NULL)
								*foo='\0';
							if ((crlf=strchr(contact,':'))!=NULL){
								crlf++;
								/* extract the needed information*/
								if ((foo=strchr(crlf,':'))!=NULL){
									*foo='\0';
									foo++;
									rport = atoi(foo);
									if (!rport) {
										printf("error: cannot handle the port "
											"in the uri in Contact:\n%s\n", 
											reply);
										exit(3);
									}
								}
								/* correct our request */
								uri_replace(buff, contact);
								if ((foo=strchr(contact,'@'))!=NULL){
									foo++;
									crlf=foo;
								}
								/* get the new destination IP*/
								address = getaddress(crlf);
								if (!address){
									printf("error: cannot determine host "
										"address from Contact of redirect:"
										"\%s\n", reply);
									exit(2);
								}
							}
							else{
								printf("error: missing : in Contact of this "
									"redirect:\n%s\n", reply);
								exit(3);
							}
							free(bar);
							memset(&addr, 0, sizeof(addr));
							redirected=1;
							i=nretries;
						}
						else {
							printf("error: cannot handle this redirect:"
								"\n%s\n", reply);
							exit(2);
						}
					} /* if redircts... */
#ifdef AUTH
					else if (regexec(&authexp, reply, 0, 0, 0)==0) {
						if (!username) {
							printf("error: received 401 but cannot "
								"authentication without a username\n");
							exit(2);
						}
						insert_auth(buff, reply);
						i--;
					}
#endif
					else if (trace) {
						if (regexec(&tmhexp, reply, 0, 0, 0)==0) {
							/* we received 483 to many hops */
							printf("%i: ", i);
							if (verbose > 2) {
								printf("(%.3f ms)\n%s\n", 
									deltaT(&sendtime, &recvtime), reply);
							}
							else {
								warning_extract(reply);
								crlf=strchr(reply, '\n');
								*crlf='\0';
								printf("(%.3f ms) %s\n", 
									deltaT(&sendtime, &recvtime), reply);
							}
							namebeg++;
							maxforw++;
							create_msg(buff, REQ_OPT);
							add_via(buff);
							continue;
						}
						else if (regexec(&proexp, reply, 0, 0, 0)==0) {
							/* we received a provisional response */
							printf("%i: ", i);
							if (verbose > 2) {
								printf("(%.3f ms)\n%s\n", 
									deltaT(&sendtime, &recvtime), reply);
							}
							else {
								warning_extract(reply);
								crlf=strchr(reply, '\n');
								*crlf='\0';
								printf("(%.3f ms) %s\n", 
									deltaT(&sendtime, &recvtime), reply);
							}
							dontsend=1;
							continue;
						}
						else {
							/* anything else then 483 or provisional will
							   be treated as final */
							if (maxforw==i) printf("%i: ", i);
							else printf("\t");
							warning_extract(crlf);
							crlf=strchr(reply,'\n');
							*crlf='\0';
							crlf++;
							contact=strstr(crlf, "Contact");
							if (!contact)
								contact=strstr(crlf, "\nm:");
							printf("(%.3f ms) %s\n", 
								deltaT(&sendtime, &recvtime), reply);
							if (contact){
								crlf=strchr(contact,'\n');
								*crlf='\0';
								printf("\t%s\n", contact);
							}
							else {
								printf("\twithout Contact header\n");
							}
							if (regexec(&okexp, reply, 0, 0, 0)==0)
								exit(0);
							else
								exit(1);
						}
					}
					else if (usrloc) {
						switch (usrlocstep) {
							case 0:
								/* at first we have sended a register and look 
								   at the response now*/
								if (regexec(&okexp, reply, 0, 0, 0)==0) {
									if (verbose > 1)
										printf ("  OK\n");
									if (verbose > 2)
										printf("\n%s\n", reply);
									strcpy(buff, message);
									usrlocstep=1;
								}
								else {
									printf("\nreceived:\n%s\nerror: didn't "
										"received '200 OK' on regsiter (see "
										"above). aborting\n", reply);
									exit(1);
								}
								break;
							case 1:
								/* now we sended the message and look if its 
								   forwarded to us*/
								if (!strncmp(reply, messusern, 
									strlen(messusern))) {
									if (verbose > 1) {
										crlf=strstr(reply, "\r\n\r\n");
										crlf=crlf+4;
										printf("  received message\n  "
											"'%s'\n", crlf);
									}
									if (verbose > 2)
										printf("\n%s\n", reply);
									cpy_vias(reply);
									strcpy(buff, mes_reply);
									usrlocstep=2;
								}
								else {
									printf("\nreceived:\n%s\nerror: didn't "
										"received the 'MESSAGE' we sended (see"
										" above). aborting\n", reply);
									exit(1);
								}
								break;
							case 2:
								/* finnaly we sended our reply on the message 
								   and look if this is also forwarded to us*/
								if (strncmp(reply, MES_STR, MES_STR_LEN)==0) {
									if (verbose)
										printf("ignoring MESSAGE "
											"retransmission\n");
									retrans_r_c++;
									dontsend=1;
									continue;
								}
								if (regexec(&okexp, reply, 0, 0, 0)==0) {
									if (verbose > 1)
										printf("  reply received\n\n");
									else if (verbose && nameend>0)
										printf("USRLOC for %s%i completed "
											"successful\n", username, namebeg);
									else if (verbose)
										printf("USRLOC for %s completed "
											"successful\n", username);
									if (namebeg==nameend) {
										printf("\nAll USRLOC tests completed "
											"successful.\nreceived last message"
											" %.3f ms after first request (test"
											" duration).\n", deltaT(&firstsendt,
											 &recvtime));
										if (big_delay)
											printf("biggest delay between "
												"request and response was %.3f"
												" ms\n", big_delay);
										if (retrans_r_c)
											printf("%i retransmission(s) "
												"received from server.\n", 
												retrans_r_c);
										if (retrans_s_c)
											printf("%i time(s) the timeout of "
												"%i ms exceeded and request was"
												" retransmitted.\n", 
												retrans_s_c, retryAfter);
										exit(0);
									}
									/* lets see if we deceid to remove a 
									   binding (case 3)*/
									rem_rand=rand();
									if (!rand_rem ||
										((float)rem_rand/RAND_MAX) 
											> USRLOC_REMOVE_PERCENT) {
										namebeg++;
										create_msg(buff, REQ_REG);
										usrlocstep=0;
									}
									else {
										/* to prevent only removing of low
										   user numbers new random number*/
										rem_rand = rand();
										rem_namebeg = namebeg;
										namebeg = ((float)rem_rand/RAND_MAX)
													* namebeg;
										create_msg(buff, REQ_REM);
										usrlocstep=3;
									}
								}
								else {
									printf("\nreceived:\n%s\nerror: didn't "
										"received the '200 OK' that we sended "
										"as the reply on the message (see "
										"above). aborting\n", reply);
									exit(1);
								}
								break;
							case 3:
								if (strncmp(reply, MES_STR, MES_STR_LEN)==0) {
									if (verbose)
										printf("ignoring MESSAGE "
											"retransmission\n");
									retrans_r_c++;
									dontsend=1;
									continue;
								}
								if (regexec(&okexp, reply, 0, 0, 0)==0) {
									if (verbose > 1) printf("   OK\n\n");
									else if (verbose && nameend>0)
										printf("Binding removal for %s%i "
											"successful\n", username, namebeg);
									else if (verbose)
										printf("Binding removal for %s "
											"successful\n", username);
									namebeg = rem_namebeg;
									namebeg++;
									create_msg(buff, REQ_REG);
									usrlocstep = 0;
									i--;
								}
								else {
									printf("\nreceived:\n%s\nerror: didn't "
										"received the expected 200 on the "
										"remove bindings request for %s%i (see"
										" above). aborting\n", reply, username, 
										namebeg);
									exit(1);
								}
								break;
							default:
								printf("error: unknown step in usrloc\n");
								exit(2);
								break;
						}
					}
					else if (randtrash) {
						/* in randomzing trash we are expexting 4?? error codes
						   everything else should not be normal */
						if (regexec(&errexp, reply, 0, 0, 0)==0) {
							if (verbose > 2)
								printf("received:\n%s\n", reply);
							if (verbose > 1) {
								printf("received expected 4xx ");
								if (warning_ext) {
									printf ("from ");
									warning_extract(reply);
									printf("\n");
								}
								else printf("\n");
							}
						}
						else {
							printf("warning: did not received 4xx\n");
							if (verbose > 1) 
								printf("sended:\n%s\nreceived:\n%s\n", buff, 
									reply);
						}
						if (nameend==(i+1)) {
							if (randretrys == 0) {
								printf("random end reached. server survived "
									":) respect!\n");
								exit(0);
							}
							else {
								printf("maximum sendings reached but did not "
									"get a response on this request:\n%s\n", 
									buff);
								exit(3);
							}
						}
						else trash_random(buff);
					}
					else {
						/* in the normal send and reply case anything other 
						   then 1xx will be treated as final response*/
						if (verbose) {
							printf("** reply received ");
							if (i==0) 
								printf("after %.3f ms **\n", 
									deltaT(&sendtime, &recvtime));
							else 
								printf("%.3f ms after first send\n   and %.3f ms "
									"after last send **\n", 
									deltaT(&firstsendt, &recvtime), 
									deltaT(&sendtime, &recvtime));
						}
						if (verbose > 1) printf("%s\n", reply);
						else if (verbose) {
							crlf=strchr(reply, '\n');
							*crlf='\0';
							printf("   %s\n", reply);
						}
						if (regexec(&proexp, reply, 0, 0, 0)==0) {
							printf("   provisional received; still waiting "
								"for a final response\n");
							retryAfter = retryAfter * 2;
							if (retryAfter > 5000) retryAfter = 5000;
							dontsend = 1;
							continue;
						} else {
							printf("   final received\n");
							if (regexec(&okexp, reply, 0, 0, 0)==0)
								exit(0);
							else
								exit(1);
						}
					} /* redirect, auth, and modes */
		
				} /* ret > 0 */
				else {
					perror("recv error");
					exit(2);
				}
			} /* !flood */
			else {
				if (i==0)
					memcpy(&firstsendt, &sendtime, sizeof(struct timeval));
				if (namebeg==nretries) {
					printf("flood end reached\n");
					printf("it took %.3f ms seconds to send %i request.\n", 
							deltaT(&firstsendt, &sendtime), namebeg);
					printf("so we sended %f requests per second.\n", 
							(namebeg/deltaT(&firstsendt, &sendtime))*1000);
					exit(0);
				}
				namebeg++;
				create_msg(buff, REQ_FLOOD);
			}
		} /* for nretries */

	} /* while redirected */
	if (randtrash) exit(0);
	printf("** I give up retransmission....\n");
	if (retrans_r_c)
		printf("%i retransmissions received during test\n", retrans_r_c);
	if (retrans_s_c)
		printf("sent %i retransmissions during test\n", retrans_s_c);
	exit(3);
}

/* prints out some usage help and exits */
void print_help() {
	printf("sipsak %s", SIPSAK_VERSION);
#ifdef AUTH
	printf(" (with digest auth support)");
#endif
	printf("\n\n"
		" shoot : sipsak [-f filename] -s sip:uri\n"
		" trace : sipsak -T -s sip:uri\n"
		" USRLOC: sipsak -U [-b number] [-e number] [-x number] [-z] -s "
			"sip:uri\n"
		" flood : sipsak -F [-c number] -s sip:uri\n"
		" random: sipsak -R [-t number] -s sip:uri\n\n"
		" additional parameter in every mode:\n"
#ifdef AUTH
		"   [-a password] [-d] [-i] [-l port] [-m number] [-n] [-r port] [-v] "
#else
		"   [-d] [-i] [-l port] [-m number] [-n] [-r port] [-v] "
#endif
			"[-V] [-w]\n"
		"   -h           displays this help message\n"
		"   -V           prints version string only\n"
		"   -f filename  the file which contains the SIP message to send\n"
		"   -s sip:uri   the destination server uri in form "
			"sip:[user@]servername[:port]\n"
		"   -T           activates the traceroute mode\n"
		"   -U           activates the USRLOC mode\n"
		"   -b number    the starting number appendix to the user name in "
			"USRLOC mode\n"
		"                (default: 0)\n"
		"   -e number    the ending numer of the appendix to the user name in "
			"USRLOC\n"
		"                mode\n"
		"   -x number    the expires header field value (default: 15)\n"
		"   -z           activates randomly removing of user bindings\n"
		"   -F           activates the flood mode\n"
		"   -c number    the maximum CSeq number for flood mode "
			"(default: 2^31)\n"
		"   -R           activates the random modues (dangerous)\n"
		"   -t number    the maximum number of trashed character in random "
			"mode\n"
		"                (default: request length)\n"
		"   -l port      the local port to use (default: any)\n"
		"   -r port      the remote port to use (default: 5060)\n"
		"   -m number    the value for the max-forwards header field\n"
		"   -n           use IPs instead of fqdn in the Via-Line\n"
		"   -i           deactivate the insertion of a Via-Line\n"
#ifdef AUTH
		"   -a password  password for authentication\n"
		"                (if omitted password=username)\n"
#endif
		"   -d           ignore redirects\n"
		"   -v           each v's produces more verbosity (max. 3)\n"
		"   -w           extract IP from the warning in reply\n"
		"   -g string    replacement for a special mark in the message\n"
		"   -G           avtivates replacement of variables\n");
	exit(0);
};

int main(int argc, char *argv[])
{
	FILE	*pf;
	char	buff[BUFSIZE];
	int		length, c;
	char	*delim, *delim2;

	/* some initialisation to be shure */
	file_b=uri_b=trace=lport=usrloc=flood=verbose=randtrash=trashchar = 0;
	numeric=warning_ext=rand_rem=nonce_count=replace_b = 0;
	namebeg=nameend=maxforw = -1;
	via_ins=redirects = 1;
	username=password=replace_str = NULL;
	address = 0;
    rport = 5060;
	expires_t = USRLOC_EXP_DEF;
	memset(buff, 0, BUFSIZE);
	memset(message, 0, BUFSIZE);
	memset(mes_reply, 0, BUFSIZE);
	memset(fqdn, 0, FQDN_SIZE);
	memset(messusern, 0, FQDN_SIZE);

	if (argc==1) print_help();

	/* lots of command line switches to handle*/
#ifdef AUTH
	while ((c=getopt(argc,argv,"a:b:c:de:f:Fg:Ghil:m:nr:Rs:t:TUvVwx:z")) != EOF){
#else
	while ((c=getopt(argc,argv,"b:c:de:f:Fg:Ghil:m:nr:Rs:t:TUvVwx:z")) != EOF){
#endif
		switch(c){
#ifdef AUTH
			case 'a':
				password=malloc(strlen(optarg));
				strncpy(password, optarg, strlen(optarg));
				break;
#endif
			case 'b':
				if ((namebeg=atoi(optarg))==-1) {
					printf("error: non-numerical appendix begin for the "
						"username\n");
					exit(2);
				}
				break;
			case 'c':
				if ((namebeg=atoi(optarg))==-1) {
					printf("error: non-numerical CSeq maximum\n");
					exit(2);
				}
				break;
			case 'd':
				redirects=0;
				break;
			case 'e':
				if ((nameend=atoi(optarg))==-1) {
					printf("error: non-numerical appendix end for the "
						"username\n");
					exit(2);
				}
				break;
			case 'F':
				flood=1;
				break;
			case 'f':
				/* file is opened in binary mode so that the cr-lf is 
				   preserved */
				pf = fopen(optarg, "rb");
				if (!pf){
					puts("unable to open the file.\n");
					exit(2);
				}
				length  = fread(buff, 1, sizeof(buff), pf);
				if (length >= sizeof(buff)){
					printf("error:the file is too big. try files of less "
						"than %i bytes.\n", BUFSIZE);
					printf("      or recompile the program with bigger "
						"BUFSIZE defined.\n");
					exit(2);
				}
				fclose(pf);
				buff[length] = '\0';
				file_b=1;
				break;
			case 'g':
				replace_str=optarg;
				break;
			case 'G':
				replace_b=1;
				break;
			case 'h':
				print_help();
				break;
			case 'i':
				via_ins=0;
				break;
			case 'l':
				lport=atoi(optarg);
				if (!lport) {
					puts("error: non-numerical local port number");
					exit(2);
				}
				break;
			case 'm':
				maxforw=atoi(optarg);
				if (maxforw==-1) {
					printf("error: non-numerical number of max-forwards\n");
					exit(2);
				}
				break;
			case 'n':
				numeric = 1;
				break;
			case 'r':
				rport=atoi(optarg);
				if (!rport) {
					printf("error: non-numerical remote port number\n");
					exit(2);
				}
				break;
			case 'R':
				randtrash=1;
				break;
			case 's':
				/* we try to extract as much informationas we can from the uri*/
				if (!strncmp(optarg,"sip",3)){
					if ((delim=strchr(optarg,':'))!=NULL){
						delim++;
						if ((delim2=strchr(delim,'@'))!=NULL){
							username=malloc(delim2-delim+1);
							strncpy(username, delim, delim2-delim);
							*(username+(delim2-delim)) = '\0';
							delim2++;
							delim=delim2;
						}
						if ((delim2=strchr(delim,':'))!=NULL){
							*delim2 = '\0';
							delim2++;
							rport = atoi(delim2);
							if (!rport) {
								printf("error: non-numerical remote port "
									"number\n");
								exit(2);
							}
						}
						domainname=malloc(strlen(delim)+1);
						strncpy(domainname, delim, strlen(delim));
						*(domainname+strlen(delim)) = '\0';
						address = getaddress(delim);
						if (!address){
							printf("error:unable to determine the remote host "
								"address\n");
							exit(2);
						}
					}
					else{
						printf("error: sip:uri doesn't contain a : ?!\n");
						exit(2);
					}
				}
				else{
					printf("error: sip:uri doesn't not begin with sip\n");
					exit(2);
				}
				uri_b=1;
				break;			break;
			case 't':
				trashchar=atoi(optarg);
				if (!trashchar) {
					printf("error: non-numerical number of trashed "
						"character\n");
					exit(2);
				}
				break;
			case 'T':
				trace=1;
				break;
			case 'U':
				usrloc=1;
				break;
			case 'v':
				verbose++;
				break;
			case 'V':
				printf("sipsak %s\n", SIPSAK_VERSION);
				exit(0);
				break;
			case 'w':
				warning_ext=1;
				break;
			case 'x':
				expires_t=atoi(optarg);
				break;
			case 'z':
				rand_rem=1;
				break;
			default:
				printf("error: unknown parameter %c\n", c);
				exit(2);
				break;
		}
	}

	/* lots of conditions to check */
	if (trace) {
		if (usrloc || flood || randtrash) {
			printf("error: trace can't be combined with usrloc, random or "
				"flood\n");
			exit(2);
		}
		if (!uri_b) {
			printf("error: for trace mode a sip:uri is realy needed\n");
			exit(2);
		}
		if (file_b) {
			printf("warning: file will be ignored for tracing.");
		}
		if (!username) {
			printf("error: for trace mode without a file the sip:uir have to "
				"contain a username\n");
			exit(2);
		}
		if (!via_ins){
			printf("warning: Via-Line is needed for tracing. Ignoring -i\n");
			via_ins=1;
		}
		if (!warning_ext) {
			printf("warning: IP extract from warning activated to be more "
				"informational\n");
			warning_ext=1;
		}
		if (maxforw==-1) maxforw=255;
	}
	else if (usrloc) {
		if (trace || flood || randtrash) {
			printf("error: usrloc can't be combined with trace, random or "
				"flood\n");
			exit(2);
		}
		if (!username || !uri_b) {
			printf("error: for the USRLOC mode you have to give a sip:uri with "
				"a username\n       at least\n");
			exit(2);
		}
		if (namebeg>0 && nameend==-1) {
			printf("error: if a starting numbers is given also an ending "
				"number have to be specified\n");
			exit(2);
		}
		if (via_ins) {
			via_ins=0;
		}
		if (redirects) {
			printf("warning: redirects are not expected in USRLOC. "
				"disableing\n");
			redirects=0;
		}
		if (nameend==-1)
			nameend=0;
		if (namebeg==-1)
			namebeg=0;
	}
	else if (flood) {
		if (trace || usrloc || randtrash) {
			printf("error: flood can't be combined with trace, random or "
				"usrloc\n");
			exit(2);
		}
		if (!uri_b) {
			printf("error: we need at least a sip uri for flood\n");
			exit(2);
		}
		if (redirects) {
			printf("warning: redirects are not expected in flood. "
				"disableing\n");
			redirects=0;
		}
	}
	else if (randtrash) {
		if (trace || usrloc || flood) {
			printf("error: random can't be combined with trace, flood or "
				"usrloc\n");
			exit(2);
		}
		if (!uri_b) {
			printf("error: need at least a sip uri for random\n");
			exit(2);
		}
		if (redirects) {
			printf("warning: redirects are not expected in random. "
				"disableing\n");
			redirects=0;
		}
		if (verbose) {
			printf("warning: random characters may destroy your terminal "
				"output\n");
		}
	}
	else {
		if (!uri_b) {
			printf("error: a spi uri is needed at least\n");
			exit(2);
		}
		if (!(username || file_b)) {
			printf("error: ether a file or an username in the sip uri is "
				"required\n");
			exit(2);
		}
		
	}
	/* determine our hostname */
	get_fqdn();
	
	/* this is not a cryptographic random number generator,
	   but hey this is only a test-tool => should be satisfying*/
	srand(time(0));

	/* here we go...*/
	shoot(buff);

	/* normaly we won't come back here, but to satisfy the compiler */
	return 0;
}

// vim:ts=4
