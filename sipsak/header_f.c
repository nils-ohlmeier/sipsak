/*
 * $Id: header_f.c,v 1.9 2005/01/05 23:37:24 calrissian Exp $
 *
 * Copyright (C) 2002-2004 Fhg Fokus
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

#include <stdio.h>
#include <stdlib.h>

#include "header_f.h"
#include "sipsak.h"
#include "exit_code.h"
#include "helper.h"

#include <string.h>

/* add a Via Header Field in the message. */
void add_via(char *mes)
{
	char *via_line, *via, *via2, *backup; 

	/* first build our own Via-header-line */
	via_line = malloc(VIA_SIP_STR_LEN+strlen(fqdn)+15);
	if (!via_line) {
		printf("failed to allocate memory\n");
		exit_code(255);
	}
	snprintf(via_line, VIA_SIP_STR_LEN+strlen(fqdn)+5+10, "%s%s:%i;rport\r\n", VIA_SIP_STR, fqdn, lport);
	if (verbose > 2)
		printf("our Via-Line: %s\n", via_line);

	if (strlen(mes)+strlen(via_line)>= BUFSIZE){
		printf("can't add our Via Header Line because file is too big\n");
		exit_code(2);
	}
	via=strstr(mes, "\nVIA_STR");
	via2=strstr(mes, "\nVIA_SHORT_STR");
	if (via==NULL && via2==NULL ){
		/* We doesn't find a Via so we insert our via
		   direct after the first line. */
		via=strchr(mes,'\n');
		if(via == NULL) {
			printf("failed to find new line to insert Via\n");
			return;
		}
	}
	else if (via!=NULL && via2!=NULL && via2<via){
		/* the short via is above the long version */
		via = via2;
	}
	else if (via==NULL && via2!=NULL){
		/* their is only a short via */
		via = via2;
	}
	via++;
	if (!via) {
		printf("failed to find Via header\n");
		exit_code(1);
	}
	/* finnaly make a backup, insert our via and append the backup */
	backup=malloc((strlen(via)+1));
	if (!backup) {
		printf("failed to allocate memory\n");
		exit_code(255);
	}
	strncpy(backup, via, strlen(via)+1);
	strncpy(via, via_line, strlen(via_line));
printf("%s\n", via);
	strncpy(via+strlen(via_line), backup, strlen(backup)+1);
	if (verbose > 1)
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
	if ((first_via=strstr(reply, "VIA_STR"))==NULL &&
		(first_via=strstr(reply, "\nVIA_SHORT_STR"))==NULL ){
		printf("error: the received message doesn't contain a Via header\n");
		exit_code(3);
	}
	last_via=first_via+4;
	middle_via=last_via;
	/* proceed additional via lines */
	while ((middle_via=strstr(last_via, "VIA_STR"))!=NULL ||
		   (middle_via=strstr(last_via, "\nVIA_SHORT_STR"))!=NULL )
		last_via=middle_via+4;
	last_via=strchr(last_via, '\n');
	middle_via=strchr(dest, '\n')+1;
	/* make a backup, insert the vias after the first line and append 
	   backup
	*/
	backup=malloc(strlen(middle_via)+1);
	if (!backup) {
		printf("failed to allocate memory\n");
		exit_code(255);
	}
	strcpy(backup, middle_via);
	strncpy(middle_via, first_via, (size_t)(last_via-first_via+1));
	strcpy(middle_via+(last_via-first_via+1), backup);
	free(backup);
	if (verbose > 2)
		printf("message reply with vias included:\n%s\n", reply);
}

void cpy_to(char *reply, char *dest) {
	char *src_to, *dst_to, *backup, *tmp;

	/* find the position where we want to insert the To */
	if ((dst_to=strstr(dest, "TO_STR"))==NULL &&
		(dst_to=strstr(dest, "\nTO_SHORT_STR"))==NULL) {
		printf("error: could not find To in the reply\n");
		exit_code(2);
	}
	/* find the To we want to copy */
	if ((src_to=strstr(reply, "TO_STR"))==NULL && 
		(src_to=strstr(reply, "\nTO_SHORT_STR"))==NULL) {
		if (verbose > 0)
			printf("warning: could not find To in reply. "
				"trying with original To\n");
	}
	else {
		/* both To found, so copy it */
		tmp=strchr(dst_to, '\n');
		tmp++;
		backup=malloc(strlen(tmp)+1);
		if (!backup) {
			printf("failed to allocate memory\n");
			exit_code(255);
		}
		strcpy(backup, tmp);
		tmp=strchr(src_to, '\n');
		strncpy(dst_to, src_to, (size_t)(tmp-src_to+1));
		strcpy(dst_to+(tmp-src_to+1), backup);
		free(backup);
		if (verbose >2)
			printf("reply with copyed To:\n%s\n", dest);
	}
}

/* check for the existence of a Max-Forwards header field. if its 
   present it sets it to the given value, if not it will be inserted.*/
void set_maxforw(char *mes){
	char *max, *backup, *crlfi;

	if ((max=strstr(mes, "MAX_FRW_STR"))==NULL){
		/* no max-forwards found so insert it after the first line*/
		max=strchr(mes,'\n');
		if (!max) {
			printf("failed to find newline\n");
			exit_code(254);
		}
		max++;
		backup=malloc(strlen(max)+1);
		if (!backup) {
			printf("failed to allocate memory\n");
			exit_code(255);
		}
		strncpy(backup, max, (size_t)(strlen(max)+1));
		snprintf(max, MAX_FRW_STR_LEN+6, "%s%i\r\n", MAX_FRW_STR, maxforw);
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
		crlfi=strchr(max,'\n');
		crlfi++;
		backup=malloc(strlen(crlfi)+1);
		if (!backup) {
			printf("failed to allocate memory\n");
			exit_code(255);
		}
		strncpy(backup, crlfi, strlen(crlfi)+1);
		crlfi=max + MAX_FRW_STR_LEN;
		snprintf(crlfi, 6, "%i\r\n", maxforw);
		crlfi=strchr(max,'\n');
		crlfi++;
		strncpy(crlfi, backup, strlen(backup)+1);
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
	if (!foo) {
		printf("failed to find newline\n");
		exit_code(254);
	}
	foo++;
	backup=malloc(strlen(foo)+1);
	if (!backup) {
		printf("failed to allocate memory\n");
		exit_code(255);
	}
	strncpy(backup, foo, strlen(foo)+1);
	foo=strstr(mes, "sip");
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

	if ((cl=strstr(ack, CON_LEN_STR)) == NULL &&
		(cl=strstr(ack, CON_LEN_SHORT_STR)) == NULL) {
		printf("missing Content-Lenght in message\n");
		return;
	}
	cr = strchr(cl, '\n');
	cr++;
	backup=malloc(strlen(cr)+1);
	if (!backup) {
		printf("failed to allocate memory\n");
		exit_code(255);
	}
	strncpy(backup, cr, strlen(cr)+1);
	if (*cl == 'C')
		cr=cl + CON_LEN_STR_LEN;
	else
		cr=cl + 3;
	snprintf(cr, 6, "%i\r\n", contentlen);
	cr=strchr(cr, '\n');
	cr++;
	strncpy(cr, backup, strlen(backup)+1);
	free(backup);
	if (verbose > 1)
		printf("Content-Length set to %i\n", contentlen);
	if (verbose > 2)
		printf("New message with changed Content-Length:\n%s\n", mes);
}

/* build an ACK from the given invite and reply.
 * NOTE: space has to be allocated allready for the ACK */
void build_ack(char *invite, char *reply, char *ack) {
	char *body;
	int len;

	body = strstr(invite, "\r\n\r\n");
	if (body) {
		body++; body++;
		len = body - invite;
		memcpy(ack, invite, len);
		*(ack+len+1) = '\0';
		replace_string(ack, "INVITE", "ACK");
		cpy_to(ack,reply);
		set_cl(ack, 0);
	}
}

/* tryes to find the warning header filed and prints out the IP */
void warning_extract(char *message)
{
	char *warning, *end, *mid, *server;
	int srvsize;

	if ((warning=strstr(message, "Warning:"))==NULL) {
		if (verbose > 0) printf("'no Warning header found' ");
		else printf("?? ");
		return;
	}
	end=strchr(warning, '"');
	end--;
	warning=strchr(warning, '3');
	warning=warning+4;
	mid=strchr(warning, ':');
	if (mid) end=mid;
	srvsize=end - warning + 1;
	server=malloc((size_t)srvsize);
	if (!server) {
		printf("failed to allocate memory\n");
		exit_code(255);
	}
	memset(server, 0, (size_t)srvsize);
	server=strncpy(server, warning, (size_t)(srvsize - 1));
	printf("%s ", server);
	free(server);
}

int cseq(char *message)
{
	char *cseq;
	int num=-1;

	cseq=strstr(message, CSEQ_STR);
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

void increase_cseq(char *message)
{
	int cs;
	char *cs_s, *eol, *backup;

	cs = cseq(message);
	if ((cs < 1) && (verbose > 1)) {
		printf("CSeq increase failed because unable to extract CSeq number\n");
		return;
	}
	cs++;
	cs_s=strstr(message, CSEQ_STR);
	if (cs_s) {
		cs_s+=6;
		eol=strchr(cs_s, ' ');
		eol++;
		backup=malloc(strlen(eol)+1);
		if (!backup) {
			printf("failed to allocate memory\n");
			exit_code(255);
		}
		strncpy(backup, eol, (size_t)(strlen(eol)+1));
		snprintf(cs_s, 11, "%i ", cs);
		cs_s+=strlen(cs_s);
		strncpy(cs_s, backup, strlen(backup));
		free(backup);
	}
	else if (verbose > 1)
		printf("'CSeq' not found in message\n");
}
