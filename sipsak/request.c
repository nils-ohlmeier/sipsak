/*
 * $Id: request.c,v 1.6 2004/02/22 01:06:33 calrissian Exp $
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "request.h"
#include "sipsak.h"

/* create a valid sip header for the different modes */
void create_msg(char *buff, int action){
	unsigned int c;
	char *usern=NULL;
	int usern_len;

	if (username)
		usern_len=strlen(username)+11;
	else
		usern_len=1;
	usern=malloc(usern_len);
	if (usern)
		memset(usern, 0, usern_len);
	else {
		printf("error: create_msg(): out of mem\n");
		exit(2);
	}
	if (username) {
		if (verbose > 2)
			printf("username: %s\ndomainname: %s\n", username, domainname);
		if (nameend>0) 
			sprintf(usern, "%s%i@", username, namebeg);
		else
			sprintf(usern, "%s@", username);
	}
	c=rand();
	switch (action){
		case REQ_REG:
			// not elegant but easier :)
			if (empty_contact) {
				sprintf(buff, 
					"%s sip:%s%s"
					"%s%s:%i;rport\r\n"
					"%s<sip:%s%s>\r\n"
					"%s<sip:%s%s>\r\n"
					"%s%u@%s\r\n"
					"%s%i %s\r\n"
					"%s0\r\n"
					"%s70\r\n"
					"%ssipsak %s\r\n"
					"\r\n", 
					REG_STR, domainname, SIP20_STR, 
					VIA_STR, fqdn, lport, 
					FROM_STR, usern, domainname, 
					TO_STR, usern, domainname, 
					CALL_STR, c, fqdn, 
					CSEQ_STR, 3*namebeg+1, REG_STR, 
					CON_LEN_STR, 
					MAX_FRW_STR, 
					UA_STR, SIPSAK_VERSION);
			}
			else if (contact_uri!=NULL) {
				sprintf(buff, 
					"%s sip:%s%s"
					"%s%s:%i;rport\r\n"
					"%s<sip:%s%s>\r\n"
					"%s<sip:%s%s>\r\n"
					"%s%u@%s\r\n"
					"%s%i %s\r\n"
					"%s<%s>\r\n"
					"%s%i\r\n"
					"%s0\r\n"
					"%s70\r\n"
					"%ssipsak %s\r\n"
					"\r\n", 
					REG_STR, domainname, SIP20_STR, 
					VIA_STR, fqdn, lport, 
					FROM_STR, usern, domainname, 
					TO_STR, usern, domainname, 
					CALL_STR, c, fqdn, 
					CSEQ_STR, 3*namebeg+1, REG_STR, 
					CONT_STR, contact_uri, 
					EXP_STR, expires_t, 
					CON_LEN_STR, 
					MAX_FRW_STR, 
					UA_STR, SIPSAK_VERSION);
			}
			else{
				sprintf(buff, 
					"%s sip:%s%s"
					"%s%s:%i;rport\r\n"
					"%s<sip:%s%s>\r\n"
					"%s<sip:%s%s>\r\n"
					"%s%u@%s\r\n"
					"%s%i %s\r\n"
					"%s<sip:%s%s:%i>\r\n"
					"%s%i\r\n"
					"%s0\r\n"
					"%s70\r\n"
					"%ssipsak %s\r\n"
					"\r\n", 
					REG_STR, domainname, SIP20_STR, 
					VIA_STR, fqdn, lport, 
					FROM_STR, usern, domainname, 
					TO_STR, usern, domainname, 
					CALL_STR, c, fqdn, 
					CSEQ_STR, 3*namebeg+1, REG_STR, 
					CONT_STR, usern, fqdn, lport, 
					EXP_STR, expires_t, 
					CON_LEN_STR, 
					MAX_FRW_STR, 
					UA_STR, SIPSAK_VERSION);
			}
			break;
		case REQ_REM:
			sprintf(buff, 
				"%s sip:%s%s"
				"%s%s:%i;rport\r\n"
				"%s<sip:%s%s>\r\n"
				"%s<sip:%s%s>\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s<sip:%s%s:%i>;%s0\r\n"
				"%s%i\r\n"
				"%s0\r\n"
				"%s70\r\n"
				"%ssipsak %s\r\n"
				"\r\n", 
				REG_STR, domainname, SIP20_STR, 
				VIA_STR, fqdn, lport, 
				FROM_STR, usern, domainname, 
				TO_STR, usern, domainname, 
				CALL_STR, c, fqdn,
				CSEQ_STR, trashchar, REG_STR, 
				CONT_STR, usern, fqdn, lport, CON_EXP_STR, 
				EXP_STR, expires_t, 
				CON_LEN_STR, 
				MAX_FRW_STR, 
				UA_STR, SIPSAK_VERSION);
			break;
		case REQ_INV:
			sprintf(buff, 
				"%s sip:%s%s%s"
				"%s%s:%i;rport\r\n"
				"%s<sip:sipsak@%s:%i>\r\n"
				"%s<sip:%s%s>\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s0\r\n"
				"%sDONT ANSWER this test call!\r\n"
				"%s70\r\n"
				"%ssipsak %s\r\n"
				"\r\n", 
				INV_STR, usern, domainname, SIP20_STR, 
				VIA_STR, fqdn, lport, 
				FROM_STR, fqdn, lport, 
				TO_STR, usern, domainname, 
				CALL_STR, c, fqdn, 
				CSEQ_STR, 3*namebeg+2, INV_STR, 
				CON_LEN_STR, 
				SUB_STR, 
				MAX_FRW_STR, 
				UA_STR, SIPSAK_VERSION);
			sprintf(confirm, 
				"%s"
				"%s<sip:sipsak@%s:%i>\r\n"
				"%s<sip:%s%s>\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s0\r\n"
				"%ssipsak %s\r\n"
				"\r\n", 
				SIP200_STR, 
				FROM_STR, fqdn, lport, 
				TO_STR, usern, domainname, 
				CALL_STR, c, fqdn, 
				CSEQ_STR, 3*namebeg+2, INV_STR, 
				CON_LEN_STR,
				UA_STR, SIPSAK_VERSION);
			sprintf(ack, 
				"%s sip:%s%s%s"
				"%s%s:%i;rport\r\n"
				"%s<sip:sipsak@%s:%i>\r\n"
				"%s<sip:%s%s>\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s0\r\n"
				"%s70\r\n"
				"%ssipsak %s\r\n"
				"\r\n", 
				ACK_STR, usern, domainname, SIP20_STR, 
				VIA_STR, fqdn, lport, 
				FROM_STR, fqdn, lport, 
				TO_STR, usern, domainname, 
				CALL_STR, c, fqdn, 
				CSEQ_STR, 3*namebeg+2, ACK_STR, 
				CON_LEN_STR, 
				MAX_FRW_STR, 
				UA_STR, SIPSAK_VERSION);
			if (verbose > 2)
				printf("ack:\n%s\nreply:\n%s\n", ack, confirm);
			if (nameend>0)
				sprintf(messusern, "%s sip:%s%i", INV_STR, username, namebeg);
			else
				sprintf(messusern, "%s sip:%s", INV_STR, username);
			break;
		case REQ_MES:
			sprintf(buff, 
				"%s sip:%s%s%s"
				"%s%s:%i;rport\r\n"
				"%s<sip:sipsak@%s:%i>\r\n"
				"%s<sip:%s%s>\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s%s\r\n"
				"%s%i\r\n"
				"%s70\r\n"
				"%ssipsak %s\r\n"
				"\r\n"
				"%s%s%i.", 
				MES_STR, usern, domainname, SIP20_STR, 
				VIA_STR, fqdn, lport, 
				FROM_STR, fqdn, lport, 
				TO_STR, usern, domainname, 
				CALL_STR, c, fqdn, 
				CSEQ_STR, 3*namebeg+2, MES_STR, 
				CON_TYP_STR, TXT_PLA_STR, 
				CON_LEN_STR, SIPSAK_MES_STR_LEN+strlen(usern)-1, 
				MAX_FRW_STR, 
				UA_STR, SIPSAK_VERSION,	
				SIPSAK_MES_STR, username, namebeg);
			sprintf(confirm, 
				"%s"
				"%s<sip:sipsak@%s:%i>\r\n"
				"%s<sip:%s%s>\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s0\r\n"
				"%ssipsak %s\r\n"
				"\r\n", 
				SIP200_STR, 
				FROM_STR, fqdn, lport, 
				TO_STR, usern, domainname, 
				CALL_STR, c, fqdn, 
				CSEQ_STR, 3*namebeg+2, MES_STR, 
				CON_LEN_STR,
				UA_STR, SIPSAK_VERSION);
			if (nameend>0)
				sprintf(messusern, "%s sip:%s%i", MES_STR, username, namebeg);
			else
				sprintf(messusern, "%s sip:%s", MES_STR, username);
			if (verbose > 2)
				printf("reply:\n%s\n", confirm);
			break;
		case REQ_OPT:
			sprintf(buff, 
				"%s sip:%s%s%s"
				"%s<sip:sipsak@%s:%i>\r\n"
				"%s<sip:%s%s>\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s<sip:sipsak@%s:%i>\r\n"
				"%s0\r\n"
				"%s70\r\n"
				"%ssipsak %s\r\n"
				"%s%s\r\n"
				"\r\n", 
				OPT_STR, usern, domainname, SIP20_STR, 
				FROM_STR, fqdn, lport, 
				TO_STR, usern, domainname, 
				CALL_STR, c, fqdn, 
				CSEQ_STR, namebeg, OPT_STR, 
				CONT_STR, fqdn, lport, 
				CON_LEN_STR, 
				MAX_FRW_STR, 
				UA_STR, SIPSAK_VERSION, 
				ACP_STR, TXT_PLA_STR);
			break;
		case REQ_FLOOD:
			sprintf(buff, 
				"%s sip:%s%s"
				"%s%s:9\r\n"
				"%s<sip:sipsak@%s:9>\r\n"
				"%s<sip:%s>\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s<sipsak@%s:9>\r\n"
				"%s0\r\n"
				"%s70\r\n"
				"%ssipsak %s\r\n"
				"\r\n", 
				FLOOD_METH, domainname, SIP20_STR, 
				VIA_STR, fqdn, 
				FROM_STR, fqdn, 
				TO_STR, domainname, 
				CALL_STR, c, fqdn, 
				CSEQ_STR, namebeg, FLOOD_METH, 
				CONT_STR, fqdn, 
				CON_LEN_STR, 
				MAX_FRW_STR, 
				UA_STR, SIPSAK_VERSION);
			break;
		case REQ_RAND:
			sprintf(buff, 
				"%s sip:%s%s"
				"%s%s:%i;rport\r\n"
				"%s<sip:sipsak@%s:%i>\r\n"
				"%s<sip:%s>\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s<sipsak@%s:%i>\r\n"
				"%s0\r\n"
				"%s70\r\n"
				"%ssipsak %s\r\n"
				"\r\n", 
				OPT_STR, domainname, SIP20_STR, 
				VIA_STR, fqdn, lport, 
				FROM_STR, fqdn, lport, 
				TO_STR, domainname,	
				CALL_STR, c, fqdn, 
				CSEQ_STR, namebeg, OPT_STR, 
				CONT_STR, fqdn,	lport, 
				CON_LEN_STR, 
				MAX_FRW_STR, 
				UA_STR, SIPSAK_VERSION);
			break;
		default:
			printf("error: unknown request type to create\n");
			exit(2);
			break;
	}
//	if (usern)
	free(usern);
	if (verbose > 2)
		printf("request:\n%s", buff);
}

