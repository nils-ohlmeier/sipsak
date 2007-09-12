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

#ifdef HAVE_STRING_H
# include <string.h>
#endif

#include "request.h"
#include "exit_code.h"
#include "helper.h"
#include "header_f.h"

/* create a valid sip header for the different modes */
void create_msg(int action, char *req_buff, char *repl_buff, char *username, int cseq){
	unsigned int c, d, len;
	char *req_buf_begin = req_buff;

	if(cseq == 0) {
		fprintf(stderr, "error: CSeq 0 is not allowed\n");
		exit_code(253, __PRETTY_FUNCTION__, "invalid CSeq 0");
	}
	if (req_buff == NULL)
		abort();
	if (username == NULL)
		username = "";
	c=(unsigned int)rand();
	c+=lport;
	d=(unsigned int)rand();
	switch (action){
		case REQ_REG:
			sprintf(req_buff, 
				"%s sip:%s%s"
				"%ssip:%s%s;tag=%x\r\n"
				"%ssip:%s%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s0\r\n"
				"%s70\r\n"
				"%s%s\r\n",
				REG_STR, domainname, SIP20_STR, 
				FROM_STR, username, domainname, c,
				TO_STR, username, domainname, 
				CALL_STR, c, fqdn, 
				CSEQ_STR, cseq, REG_STR, 
				CON_LEN_STR, 
				MAX_FRW_STR, 
				UA_STR, UA_VAL_STR);
			req_buff += strlen(req_buff);
			if (contact_uri!=NULL) {
				sprintf(req_buff, "%s%i\r\n"
					"%s%s\r\n\r\n",
					EXP_STR, expires_t,
					CONT_STR, contact_uri);
			}
			else if (empty_contact == 0) {
				sprintf(req_buff, "%s%i\r\n"
					"%ssip:%s%s:%i",
					EXP_STR, expires_t,
					CONT_STR, username, fqdn, lport);
				req_buff += strlen(req_buff);
				if (transport != SIP_UDP_TRANSPORT)
					sprintf(req_buff, "%s%s\r\n\r\n", TRANSPORT_PARAMETER_STR,
							transport_str);
				else
					sprintf(req_buff, "\r\n\r\n");
			}
			else{
				sprintf(req_buff, "\r\n");
			}
			add_via(req_buf_begin);
			break;
		case REQ_REM:
			sprintf(req_buff, 
				"%s sip:%s%s"
				"%ssip:%s%s;tag=%x\r\n"
				"%ssip:%s%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s%i\r\n"
				"%s0\r\n"
				"%s70\r\n"
				"%s%s\r\n"
				"%ssip:%s%s:%i;%s0",
				REG_STR, domainname, SIP20_STR, 
				FROM_STR, username, domainname, c,
				TO_STR, username, domainname, 
				CALL_STR, c, fqdn,
				CSEQ_STR, cseq, REG_STR, 
				EXP_STR, expires_t, 
				CON_LEN_STR, 
				MAX_FRW_STR, 
				UA_STR, UA_VAL_STR,
				CONT_STR, username, fqdn, lport, CON_EXP_STR);
			req_buff += strlen(req_buff);
			if (transport != SIP_UDP_TRANSPORT) {
				sprintf(req_buff, "\r\n\r\n");
			}
			else {
				sprintf(req_buff, "%s%s\r\n\r\n", TRANSPORT_PARAMETER_STR,
						transport_str);
			}
			add_via(req_buf_begin);
			break;
		case REQ_INV:
			sprintf(req_buff, 
				"%s sip:%s%s%s"
				"%ssip:%s%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s0\r\n"
				"%ssip:sipsak@%s:%i\r\n"
				"%sDONT ANSWER this test call!\r\n"
				"%s70\r\n"
				"%s%s\r\n",
				INV_STR, username, domainname, SIP20_STR, 
				TO_STR, username, domainname, 
				CALL_STR, c, fqdn, 
				CSEQ_STR, cseq, INV_STR, 
				CON_LEN_STR, 
				CONT_STR, fqdn, lport,
				SUB_STR, 
				MAX_FRW_STR, 
				UA_STR, UA_VAL_STR);
			req_buff += strlen(req_buff);
			if (from_uri) {
				sprintf(req_buff,
					"%s%s;tag=%x\r\n"
					"\r\n",
					FROM_STR, from_uri, c);
			}
			else {
				sprintf(req_buff,
					"%ssip:sipsak@%s:%i;tag=%x\r\n"
					"\r\n",
					FROM_STR, fqdn, lport, c);
			}
			add_via(req_buf_begin);
			sprintf(repl_buff, 
				"%s"
				"%ssip:sipsak@%s:%i;tag=%x\r\n"
				"%ssip:%s%s;tag=%o%o\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s0\r\n"
				"%ssip:sipsak_conf@%s:%i\r\n"
				"%s%s\r\n"
				"\r\n", 
				SIP200_STR, 
				FROM_STR, fqdn, lport, c,
				TO_STR, username, domainname, c, d,
				CALL_STR, c, fqdn, 
				CSEQ_STR, cseq, INV_STR, 
				CON_LEN_STR,
				CONT_STR, fqdn, lport,
				UA_STR, UA_VAL_STR);
			break;
		case REQ_MES:
			sprintf(req_buff,
				"%s sip:%s%s%s"
				"%ssip:%s%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s%s\r\n"
				"%s70\r\n"
				"%s%s\r\n",
				MES_STR, username, domainname, SIP20_STR, 
				TO_STR, username, domainname, 
				CALL_STR, c, fqdn, 
				CSEQ_STR, cseq, MES_STR, 
				CON_TYP_STR, TXT_PLA_STR, 
				MAX_FRW_STR, 
				UA_STR, UA_VAL_STR);
			req_buff += strlen(req_buff);
			if (from_uri) {
				sprintf(req_buff,
					"%s%s;tag=%x\r\n",
					FROM_STR, from_uri, c);
			}
			else {
				sprintf(req_buff,
					"%ssip:sipsak@%s:%i;tag=%x\r\n",
					FROM_STR, fqdn, lport, c);
			}
			req_buff += strlen(req_buff);
			if (mes_body) {
				len = strlen(mes_body);
			}
			else {
				len = SIPSAK_MES_STR_LEN + strlen(username);
			}
			sprintf(req_buff, "%s%u\r\n", CON_LEN_STR, len);
			req_buff += strlen(req_buff);
			if (con_dis) {
				sprintf(req_buff, "%s%s\r\n", CON_DIS_STR, con_dis);
				req_buff += strlen(req_buff);
			}
			sprintf(req_buff, "\r\n");
			req_buff += 2;
			if (mes_body) {
				sprintf(req_buff,
					"%s",
					mes_body);
			}
			else {
				sprintf(req_buff, "%s%s", SIPSAK_MES_STR, username);
				req_buff += strlen(req_buff) - 1;
				*(req_buff) = '.';
			}
			add_via(req_buf_begin);
			sprintf(repl_buff,
				"%s"
				"%ssip:sipsak@%s:%i;tag=%x\r\n"
				"%ssip:%s%s;tag=%o%o\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s0\r\n"
				"%s%s\r\n"
				"\r\n", 
				SIP200_STR, 
				FROM_STR, fqdn, lport, c,
				TO_STR, username, domainname, c, d,
				CALL_STR, c, fqdn, 
				CSEQ_STR, cseq, MES_STR, 
				CON_LEN_STR,
				UA_STR, UA_VAL_STR);
			break;
		case REQ_OPT:
			sprintf(req_buff, 
				"%s sip:%s%s%s"
				"%ssip:sipsak@%s:%i;tag=%x\r\n"
				"%ssip:%s%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%ssip:sipsak@%s:%i\r\n"
				"%s0\r\n"
				"%s70\r\n"
				"%s%s\r\n"
				"%s%s\r\n"
				"\r\n", 
				OPT_STR, username, domainname, SIP20_STR, 
				FROM_STR, fqdn, lport, c,
				TO_STR, username, domainname,
				CALL_STR, c, fqdn, 
				CSEQ_STR, cseq, OPT_STR, 
				CONT_STR, fqdn, lport, 
				CON_LEN_STR, 
				MAX_FRW_STR, 
				UA_STR, UA_VAL_STR,
				ACP_STR, TXT_PLA_STR);
			add_via(req_buf_begin);
			break;
		case REQ_FLOOD:
			sprintf(req_buff, 
				"%s sip:%s%s%s"
				"%s%s %s:9;branch=z9hG4bK.%08x\r\n"
				"%ssip:sipsak@%s:9;tag=%x\r\n"
				"%ssip:%s%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%ssip:sipsak@%s:9\r\n"
				"%s0\r\n"
				"%s70\r\n"
				"%s%s\r\n"
				"\r\n", 
				FLOOD_METH, username, domainname, SIP20_STR, 
				VIA_SIP_STR, TRANSPORT_UDP_STR, fqdn, d,
				FROM_STR, fqdn, c,
				TO_STR, username, domainname, 
				CALL_STR, c, fqdn, 
				CSEQ_STR, cseq, FLOOD_METH, 
				CONT_STR, fqdn, 
				CON_LEN_STR, 
				MAX_FRW_STR, 
				UA_STR, UA_VAL_STR);
			break;
		case REQ_RAND:
			sprintf(req_buff, 
				"%s sip:%s%s"
				"%ssip:sipsak@%s:%i;tag=%x\r\n"
				"%ssip:%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%ssipsak@%s:%i\r\n"
				"%s0\r\n"
				"%s70\r\n"
				"%s%s\r\n"
				"\r\n", 
				OPT_STR, domainname, SIP20_STR, 
				FROM_STR, fqdn, lport, c,
				TO_STR, domainname,	
				CALL_STR, c, fqdn, 
				CSEQ_STR, cseq, OPT_STR, 
				CONT_STR, fqdn,	lport, 
				CON_LEN_STR, 
				MAX_FRW_STR, 
				UA_STR, UA_VAL_STR);
			add_via(req_buf_begin);
			break;
		default:
			fprintf(stderr, "error: unknown request type to create\n");
			exit_code(2, __PRETTY_FUNCTION__, "unknown request type requested");
			break;
	}
	if (headers) {
		insert_header(req_buf_begin, headers, 1);
		if (repl_buff)
			insert_header(repl_buff, headers, 1);
	}
}

