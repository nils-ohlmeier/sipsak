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

#include "sipsak.h"

#include "header_f.h"
#include "exit_code.h"
#include "helper.h"
#include "shoot.h"
#include "transport.h"


/* add the given header(s) below the request line */
void insert_header(char *mes, char *header, int first) {
	char *ins, *backup;

	if (first) {
		ins = strchr(mes, '\n');
		if (ins == NULL) {
			printf("failed to find a new line in the message\n");
			exit_code(2, __PRETTY_FUNCTION__, "failed to find a new line in the message");
		}
		ins++;
	}
	else {
		ins = mes;
	}
	backup = str_alloc(strlen(ins) + 1);
	strncpy(backup, ins, strlen(ins));
	strncpy(ins, header, strlen(header));
	strncpy(ins + strlen(header), backup, strlen(backup)+1);
	free(backup);
}

/* add a Via Header Field in the message. */
void add_via(char *mes, char *fqdn, int lport)
{
	char *via_line, *via, *backup;

	if ((via=STRCASESTR(mes, VIA_STR)) == NULL &&
			(via=STRCASESTR(mes, VIA_SHORT_STR)) == NULL) {
		/* We didn't found a Via so we insert our via
		   direct after the first line. */
		via=strchr(mes,'\n');
		if(via == NULL) {
			fprintf(stderr, "error: failed to find a position to insert Via:\n"
											"'%s'\n", mes);
			exit_code(2, __PRETTY_FUNCTION__, "failed to find position to insert to insert Via header");
		}
		via++;
	}
	if (*via == '\n')
		via++;
	/* build our own Via-header-line */
	via_line = str_alloc(VIA_SIP_STR_LEN+TRANSPORT_STR_LEN+1+
			strlen(fqdn)+15+30+1);
	snprintf(via_line,
					VIA_SIP_STR_LEN+TRANSPORT_STR_LEN+1+strlen(fqdn)+15+30, 
					"%s%s %s:%i;branch=z9hG4bK.%08x;rport;alias\r\n", 
					VIA_SIP_STR, transport_str, fqdn, lport, rand());
	if (verbose > 2)
		printf("our Via-Line: %s\n", via_line);

	if (strlen(mes)+strlen(via_line)>= BUFSIZE){
		printf("can't add our Via Header Line because file is too big\n");
		exit_code(2, __PRETTY_FUNCTION__, "Via header to big for buffer");
	}
	/* finnaly make a backup, insert our via and append the backup */
	backup=str_alloc((strlen(via)+1));
	strncpy(backup, via, strlen(via));
	strncpy(via, via_line, strlen(via_line));
	strncpy(via+strlen(via_line), backup, strlen(backup)+1);
	if (verbose > 2)
		printf("New message with Via-Line:\n%s\n", mes);
	free(via_line);
	free(backup);
}

/* copy the via lines from the message to the message 
   reply for correct routing of our reply.
*/
void cpy_vias(char *reply, char *dest){
	char *first_via, *middle_via, *last_via, *backup;

	/* lets see if we find any via */
	if ((first_via=STRCASESTR(reply, VIA_STR))==NULL &&
		(first_via=STRCASESTR(reply, VIA_SHORT_STR))==NULL ){
		fprintf(stderr, "error: the received message doesn't contain a Via header\n");
		exit_code(3, __PRETTY_FUNCTION__, "missing Via header in message");
	}
	last_via=first_via+4;
	/* proceed additional via lines */
	while ((middle_via=STRCASESTR(last_via, VIA_STR))!=NULL ||
		   (middle_via=STRCASESTR(last_via, VIA_SHORT_STR))!=NULL )
		last_via=middle_via+4;
	last_via=strchr(last_via, '\n');
	middle_via=strchr(dest, '\n')+1;
	if (middle_via == NULL) {
		fprintf(stderr, "error: failed to locate end of middle Via header\n");
		exit_code(3, __PRETTY_FUNCTION__, "missing end of Via header in message");
	}
	/* make a backup, insert the vias after the first line and append 
	   backup
	*/
	backup=str_alloc(strlen(middle_via)+1);
	strcpy(backup, middle_via);
	strncpy(middle_via, first_via, (size_t)(last_via-first_via+1));
	strcpy(middle_via+(last_via-first_via+1), backup);
	free(backup);
	if (verbose > 2)
		printf("message reply with vias included:\n%s\n", dest);
}

void cpy_to(char *reply, char *dest) {
	char *src_to, *dst_to, *backup, *tmp;

	/* find the position where we want to insert the To */
	if ((dst_to=STRCASESTR(dest, TO_STR))==NULL &&
		(dst_to=STRCASESTR(dest, TO_SHORT_STR))==NULL) {
		fprintf(stderr, "error: could not find To in the destination: %s\n", dest);
		exit_code(2, __PRETTY_FUNCTION__, "missing To header in target buffer");
	}
	if (*dst_to == '\n')
		dst_to++;
	/* find the To we want to copy */
	if ((src_to=STRCASESTR(reply, TO_STR))==NULL && 
		(src_to=STRCASESTR(reply, TO_SHORT_STR))==NULL) {
		if (verbose > 0)
			fprintf(stderr, "warning: could not find To in reply. "
				"trying with original To\n");
	}
	else {
		if (*src_to == '\n')
			src_to++;
		/* both To found, so copy it */
		tmp=strchr(dst_to, '\n');
		tmp++;
		backup=str_alloc(strlen(tmp)+1);
		strcpy(backup, tmp);
		tmp=strchr(src_to, '\n');
		strncpy(dst_to, src_to, (size_t)(tmp-src_to+1));
		strcpy(dst_to+(tmp-src_to+1), backup);
		free(backup);
		if (verbose >2)
			printf("reply with copied To:\n%s\n", dest);
	}
}

/* check for the existence of a Max-Forwards header field. if its 
   present it sets it to the given value, if not it will be inserted.*/
void set_maxforw(char *mes, int value){
	char *max, *backup, *crlfi;
	int maxforward;

	if ((max=STRCASESTR(mes, MAX_FRW_STR))==NULL){
		/* no max-forwards found so insert it after the first line*/
		max=strchr(mes,'\n');
		if (!max) {
			printf("failed to find newline\n");
			exit_code(254, __PRETTY_FUNCTION__, "missing newline in buffer");
		}
		max++;
		backup=str_alloc(strlen(max)+1);
		strncpy(backup, max, (size_t)(strlen(max)));
		if (value == -1) {
			maxforward = 70; // RFC3261 default
		}
		else {
			maxforward = value;
		}
		snprintf(max, MAX_FRW_STR_LEN+6, "%s%i\r\n", MAX_FRW_STR, maxforward);
		max=strchr(max,'\n');
		max++;
		strncpy(max, backup, strlen(backup)+1);
		free(backup);
		if (verbose > 1)
			printf("Max-Forwards %i inserted into header\n", maxforward);
		if (verbose > 2)
			printf("New message with inserted Max-Forwards:\n%s\n", mes);
	}
	else{
		/* found max-forwards => overwrite the value with maxforw*/
		crlfi=strchr(max,'\n');
		crlfi++;
		backup=str_alloc(strlen(crlfi)+1);
		strncpy(backup, crlfi, strlen(crlfi));
		crlfi=max + MAX_FRW_STR_LEN;
		if (value == -1) {
			maxforward = str_to_int(1, crlfi);
			maxforward++;
		}
		else {
			maxforward = value;
		}
		snprintf(crlfi, 6, "%i\r\n", maxforward);
		crlfi=strchr(max,'\n');
		crlfi++;
		strncpy(crlfi, backup, strlen(backup)+1);
		free(backup);
		if (verbose > 1)
			printf("Max-Forwards set to %i\n", maxforward);
		if (verbose > 2)
			printf("New message with changed Max-Forwards:\n%s\n", mes);
	}
}

/* replaces the uri in first line of mes with the other uri */
void uri_replace(char *mes, char *uri)
{
	char *foo, *backup;

	foo=strchr(mes, '\n');
	if (!foo) {
		printf("failed to find newline\n");
		exit_code(254, __PRETTY_FUNCTION__, "missing newline in buffer");
	}
	foo++;
	backup=str_alloc(strlen(foo)+1);
	strncpy(backup, foo, strlen(foo));
	foo=STRCASESTR(mes, "sip");
	strncpy(foo, uri, strlen(uri));
	strncpy(foo+strlen(uri), SIP20_STR, SIP20_STR_LEN);
	strncpy(foo+strlen(uri)+SIP20_STR_LEN, backup, strlen(backup)+1);
	free(backup);
	if (verbose > 2)
		printf("Message with modified uri:\n%s\n", mes);
}

/* replace the Content-Length value with the given value */
void set_cl(char* mes, int contentlen) {
	char *cl, *cr, *backup;

	if ((cl=STRCASESTR(mes, CON_LEN_STR)) == NULL &&
		(cl=STRCASESTR(mes, CON_LEN_SHORT_STR)) == NULL) {
		printf("missing Content-Length in message\n");
		return;
	}
	if (*cl == '\n') {
		cl++;
	}
	cr = strchr(cl, '\n');
	cr++;
	backup=str_alloc(strlen(cr)+1);
	strncpy(backup, cr, strlen(cr));
	if (*cl == 'C')
		cr=cl + CON_LEN_STR_LEN;
	else
		cr=cl + 3;
	snprintf(cr, 6, "%i\r\n", contentlen);
	cr=strchr(cr, '\n');
	cr++;
	strncpy(cr, backup, strlen(backup)+1);
	free(backup);
	if (verbose > 2) {
		printf("Content-Length set to %i\n"
				"New message with changed Content-Length:\n%s\n", contentlen, mes);
	}
}

/* returns the content length from the message; in case of error it
 * return -1 */
int get_cl(char* mes) {
	char *cl;

	if ((cl=STRCASESTR(mes, CON_LEN_STR)) == NULL &&
		(cl=STRCASESTR(mes, CON_LEN_SHORT_STR)) == NULL) {
		if (verbose > 1)
			printf("missing Content-Length in message\n");
		return -1;
	}
	if (*cl == '\n') {
		cl+=3;
	}
	else {
		cl+=15;
	}
	return str_to_int(1, cl);
}

/* returns 1 if the rr_line contains the lr parameter
 * otherwise 0 */
int find_lr_parameter(char *rr_line) {
	char *eol, *lr;

	eol = strchr(rr_line, '\n');
	lr = STRCASESTR(rr_line, ";lr");
	if ((eol == NULL) || (lr == NULL) || (lr > eol)) {
		return 0;
	}
	else {
		return 1;
	}
}

/* copies the Record-Route header from src to dst.
 * if route is set Record-Route will be replaced by Route */
void cpy_rr(char* src, char *dst, int route) {
	char *rr, *cr, *cr2, *backup;
	int len;

	cr = strchr(dst, '\n');
	if (cr == NULL) {
		fprintf(stderr, "error: failed to find newline in destination\n");
		exit_code(3, __PRETTY_FUNCTION__, "missing newline in target buffer");
	}
	cr++;
	rr = STRCASESTR(src, RR_STR);
	if (rr != NULL) {
		if (find_lr_parameter(rr) == 0) {
			fprintf(stderr, "error: strict routing is not support yet\n");
			exit_code(252, __PRETTY_FUNCTION__, "strict routing is not supported");
		}
		backup=str_alloc(strlen(cr)+1);
		strncpy(backup, cr, strlen(cr));
		if (route == 0)
			len = RR_STR_LEN;
		else
			len = ROUTE_STR_LEN;
		while (rr != NULL) {
			if (route == 0) {
				strncpy(cr, RR_STR, RR_STR_LEN);
			}
			else {
				strncpy(cr, ROUTE_STR, ROUTE_STR_LEN);
			}
			cr += len;
			cr2 = strchr(rr, '\n');
			if (cr2 == NULL) {
				fprintf(stderr, "error: failed to find end of line\n");
				exit_code(3, __PRETTY_FUNCTION__, "missing newline in buffer");
			}
			strncpy(cr, rr + RR_STR_LEN, (cr2 - (rr + len) + 1));
			cr+=(cr2 - (rr + RR_STR_LEN) + 1);
			rr = STRCASESTR(++rr, RR_STR);
		}
		strncpy(cr, backup, strlen(backup)+1);
		free(backup);
		if (verbose > 2)
			printf("New message with inserted Route:\n%s\n", dst);
	}
}

/* build an ACK from the given invite and reply.
 * NOTE: space has to be allocated already for the ACK */
void build_ack(char *invite, char *reply, char *dest, 
			struct sipsak_regexp *reg) {
	char *tmp;
	int len;

	if ((tmp = STRCASESTR(invite, "\r\n\r\n")) != NULL) {
		len = (tmp + 4) - invite;
	}
	else {
		len = strlen(invite);
	}
	memcpy(dest, invite, len);
	*(dest + len) = '\0';
	replace_string(dest, "INVITE", "ACK");
	set_cl(dest, 0);
	cpy_to(reply, dest);
	if (regexec(&(reg->okexp), reply, 0, 0, 0)==0) {
		cpy_rr(reply, dest, 1);
		/* 200 ACK must be in new transaction */
		new_branch(dest);
		if((tmp = uri_from_contact(reply))!= NULL) {
			uri_replace(dest, tmp);
			free(tmp);
		}
	}
}

/* tryes to find the warning header filed and prints out the IP */
void warning_extract(char *message)
{
	char *warning, *end, *mid, *server;
	int srvsize;

	if ((warning=STRCASESTR(message, "Warning:"))==NULL) {
		if (verbose > 0) 
			printf("'no Warning header found' ");
		else 
			printf("?? ");
		return;
	}
	end=strchr(warning, '"');
	end--;
	warning=strchr(warning, '3');
	warning+=4;
	mid=strchr(warning, ':');
	if (mid)
		end=mid;
	srvsize=end - warning + 1;
	server=str_alloc((size_t)srvsize);
	server=strncpy(server, warning, (size_t)(srvsize - 1));
	printf("%s ", server);
	free(server);
}

/* tries to find and return the number in the CSeq header */
int cseq(char *message)
{
	char *cseq;
	int num;

	cseq=STRCASESTR(message, CSEQ_STR);
	if (cseq) {
		cseq+=6;
		num=str_to_int(1, cseq);
		if (num < 1) {
			if (verbose > 2)
				printf("CSeq found but not convertible\n");
			return 0;
		}
		return num;
	}
	if (verbose > 2)
		printf("no CSeq found\n");
	return 0;
}

/* if it find the Cseq number in the message it will increased by one */
int increase_cseq(char *message, char *reply)
{
	int cs = 0;
	char *cs_s, *eol, *backup;

	cs = cseq(message);
	if ((cs < 1) && (verbose > 1)) {
		printf("CSeq increase failed because unable to extract CSeq number\n");
		return 0;
	}
	if (cs == INT_MAX)
		cs = 1;
	else
		cs++;
	cs_s=STRCASESTR(message, CSEQ_STR);
	if (cs_s) {
		cs_s+=6;
		eol=strchr(cs_s, ' ');
		eol++;
		backup=str_alloc(strlen(eol)+1);
		strncpy(backup, eol, (size_t)(strlen(eol)));
		snprintf(cs_s, 11, "%i ", cs);
		cs_s+=strlen(cs_s);
		strncpy(cs_s, backup, strlen(backup));
		free(backup);
	}
	else if (verbose > 1)
		printf("'CSeq' not found in message\n");
	if (reply != NULL) {
		cs_s=STRCASESTR(reply, CSEQ_STR);
		if (cs_s) {
			cs_s+=6;
			eol=strchr(cs_s, ' ');
			eol++;
			backup=str_alloc(strlen(eol)+1);
			strncpy(backup, eol, (size_t)(strlen(eol)));
			snprintf(cs_s, 11, "%i ", cs);
			cs_s+=strlen(cs_s);
			strncpy(cs_s, backup, strlen(backup));
			free(backup);
		}
		else if (verbose > 1)
			printf("'CSeq' not found in reply\n");
	}
	return cs;
}

/* separates the given URI into the parts by setting the pointer but it
   destroyes the URI */
void parse_uri(char *uri, char **scheme, char **user, char **host, int *port)
{
	char *col, *col2, *at;
	col = col2 = at = NULL;
	*port = 0;
	*scheme = *user = *host = NULL;
	if ((col=strchr(uri,':'))!=NULL) {
		if ((at=strchr(uri,'@'))!=NULL) {
			*col = '\0';
			*at = '\0';
			if (at > col) {
				*scheme = uri;
				*user = ++col;
				*host = ++at;
				if ((col2=strchr(*host,':'))!=NULL) {
					*col2 = '\0';
					*port = str_to_int(1, ++col2);
				}
			}
			else {
				*user = uri;
				*host = ++at;
				*port = str_to_int(1, ++col);
			}
		}
		else {
			*col = '\0';
			col++;
			if ((col2=strchr(col,':'))!=NULL) {
				*col2 = '\0';
				*scheme = uri;
				*host = col;
				*port = str_to_int(1, ++col2);
			}
			else {
				if (is_number(col)) {
					*host = uri;
					*port = str_to_int(1, col);
				}
				else {
					*scheme = uri;
					*host = col;
				}
			}
		}
	}
	else {
		*host = uri;
	}
}

/* return a copy of the URI from the Contact of the message if found */
char* uri_from_contact(char *message)
{
	char *contact, *end, *tmp, c;

	/* try to find the contact in the redirect */
	if ((contact=STRCASESTR(message, CONT_STR))==NULL && 
		(contact=STRCASESTR(message, CONT_SHORT_STR))==NULL ) {
		if(verbose > 1)
			printf("'Contact' not found in the message\n");
		return NULL;
	}
	if (*contact == '\n')
		contact++;

	if((end=strchr(contact,'\r'))!=NULL) {
		c = '\r';
		*end = '\0';
	}
	else if((end=strchr(contact,'\n'))!=NULL) {
		c = '\n';
		*end = '\0';
	}
	else {
		c = '\0';
		end = contact + strlen(contact);
	}

	tmp = NULL;

	if ((contact=STRCASESTR(contact, "sip:"))!=NULL) {
		if ((tmp=strchr(contact+4, ';'))!=NULL) {
			*end = c;
			end = tmp;
			c = *end;
			*end = '\0';
		}
		if ((tmp=strchr(contact+4, '>'))!=NULL) {
			*end = c;
			end = tmp;
			c = *end;
			*end = '\0';
		}
		tmp = str_alloc(strlen(contact)+1);
		memcpy(tmp,contact,strlen(contact));
	}
	
	*end = c;

	return tmp;
}

/* replace the 8 bytes behind the first magic cookie with a new
 * random value */
void new_branch(char *message)
{
	char *branch;
	char backup;

	if((branch = STRCASESTR(message,"branch=z9hG4bK.")) != NULL) {
		backup = *(branch+15+8);
		snprintf(branch+15, 9, "%08x", rand());
		*(branch+15+8) = backup;
	}
}

/* increase the CSeq and insert a new branch value */
int new_transaction(char *message, char *reply)
{
	new_branch(message);
	return increase_cseq(message, reply);
}

/* just print the first line of the message */
void print_message_line(char *message)
{
	char *crlf;

	crlf=strchr(message, '\n');
	if (!crlf) {
		printf("failed to find newline\n");
		exit_code(254, __PRETTY_FUNCTION__, "missing newline in buffer");
	}
	else if (*(crlf - 1) == '\r')
		crlf--;
	printf("%.*s\n", (int)(crlf - message), message);
}

/* return pointer to the beginning of the message body */
char* get_body(char *mes) {
	char *cr;

	if ((cr = strstr(mes, "\r\n\r\n")) != NULL) {
		cr+=4;
	}
	return cr;
}
