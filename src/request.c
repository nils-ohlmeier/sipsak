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

#ifdef HAVE_STRING_H
# include <string.h>
#endif

#include "request.h"
#include "exit_code.h"
#include "helper.h"
#include "header_f.h"
#include "transport.h"

/* create a valid sip header for the different modes */
void create_msg(int action, struct sipsak_msg_data *msg_data){
	unsigned int c, d, len;
	char *req_buf_begin = msg_data->req_buff;

	if(msg_data->cseq_counter == 0) {
		fprintf(stderr, "error: CSeq 0 is not allowed\n");
		exit_code(253, __PRETTY_FUNCTION__, "invalid CSeq 0");
	}
	if (msg_data->req_buff == NULL)
		abort();
	if (msg_data->username == NULL)
		msg_data->username = "";
	c=(unsigned int)rand();
	c+=msg_data->lport;
	d=(unsigned int)rand();
	switch (action){
		case REQ_REG:
			sprintf(msg_data->req_buff,
				"%s sip:%s%s"
				"%ssip:%s%s;tag=%x\r\n"
				"%ssip:%s%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s0\r\n"
				"%s70\r\n"
				"%s%s\r\n",
				REG_STR, msg_data->domainname, SIP20_STR,
				FROM_STR, msg_data->username, msg_data->domainname, c,
				TO_STR, msg_data->username, msg_data->domainname,
				CALL_STR, c, msg_data->fqdn,
				CSEQ_STR, msg_data->cseq_counter, REG_STR,
				CON_LEN_STR,
				MAX_FRW_STR,
				UA_STR, UA_VAL_STR);
			msg_data->req_buff += strlen(msg_data->req_buff);
			if (msg_data->contact_uri!=NULL) {
				sprintf(msg_data->req_buff, "%s%i\r\n"
					"%s%s\r\n\r\n",
					EXP_STR, msg_data->expires_t,
					CONT_STR, msg_data->contact_uri);
			}
			else if (msg_data->empty_contact == 0) {
				sprintf(msg_data->req_buff, "%s%i\r\n"
					"%ssip:%s%s:%i",
					EXP_STR, msg_data->expires_t,
					CONT_STR, msg_data->username, msg_data->fqdn, msg_data->lport);
				msg_data->req_buff += strlen(msg_data->req_buff);
				if (msg_data->transport != SIP_UDP_TRANSPORT)
					sprintf(msg_data->req_buff, "%s%s\r\n\r\n", TRANSPORT_PARAMETER_STR,
							transport_str);
				else
					sprintf(msg_data->req_buff, "\r\n\r\n");
			}
			else{
				sprintf(msg_data->req_buff, "\r\n");
			}
			add_via(req_buf_begin, msg_data->fqdn, msg_data->lport);
			break;
		case REQ_REM:
			sprintf(msg_data->req_buff,
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
				REG_STR, msg_data->domainname, SIP20_STR,
				FROM_STR, msg_data->username, msg_data->domainname, c,
				TO_STR, msg_data->username, msg_data->domainname,
				CALL_STR, c, msg_data->fqdn,
				CSEQ_STR, msg_data->cseq_counter, REG_STR,
				EXP_STR, msg_data->expires_t,
				CON_LEN_STR,
				MAX_FRW_STR,
				UA_STR, UA_VAL_STR,
				CONT_STR, msg_data->username, msg_data->fqdn, msg_data->lport, CON_EXP_STR);
			msg_data->req_buff += strlen(msg_data->req_buff);
			if (msg_data->transport != SIP_UDP_TRANSPORT) {
				sprintf(msg_data->req_buff, "\r\n\r\n");
			}
			else {
				sprintf(msg_data->req_buff, "%s%s\r\n\r\n", TRANSPORT_PARAMETER_STR,
						transport_str);
			}
			add_via(req_buf_begin, msg_data->fqdn, msg_data->lport);
			break;
		case REQ_INV:
			sprintf(msg_data->req_buff,
				"%s sip:%s%s%s"
				"%ssip:%s%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s0\r\n"
				"%ssip:sipsak@%s:%i\r\n"
				"%sDONT ANSWER this test call!\r\n"
				"%s70\r\n"
				"%s%s\r\n",
				INV_STR, msg_data->username, msg_data->domainname, SIP20_STR,
				TO_STR, msg_data->username, msg_data->domainname,
				CALL_STR, c, msg_data->fqdn,
				CSEQ_STR, msg_data->cseq_counter, INV_STR,
				CON_LEN_STR,
				CONT_STR, msg_data->fqdn, msg_data->lport,
				SUB_STR,
				MAX_FRW_STR,
				UA_STR, UA_VAL_STR);
			msg_data->req_buff += strlen(msg_data->req_buff);
			if (msg_data->from_uri) {
				sprintf(msg_data->req_buff,
					"%s%s;tag=%x\r\n"
					"\r\n",
					FROM_STR, msg_data->from_uri, c);
			}
			else {
				sprintf(msg_data->req_buff,
					"%ssip:sipsak@%s:%i;tag=%x\r\n"
					"\r\n",
					FROM_STR, msg_data->fqdn, msg_data->lport, c);
			}
			add_via(req_buf_begin, msg_data->fqdn, msg_data->lport);
			sprintf(msg_data->repl_buff,
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
				FROM_STR, msg_data->fqdn, msg_data->lport, c,
				TO_STR, msg_data->username, msg_data->domainname, c, d,
				CALL_STR, c, msg_data->fqdn,
				CSEQ_STR, msg_data->cseq_counter, INV_STR,
				CON_LEN_STR,
				CONT_STR, msg_data->fqdn, msg_data->lport,
				UA_STR, UA_VAL_STR);
			break;
		case REQ_MES:
			sprintf(msg_data->req_buff,
				"%s sip:%s%s%s"
				"%ssip:%s%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s%s\r\n"
				"%s70\r\n"
				"%s%s\r\n",
				MES_STR, msg_data->username, msg_data->domainname, SIP20_STR,
				TO_STR, msg_data->username, msg_data->domainname,
				CALL_STR, c, msg_data->fqdn,
				CSEQ_STR, msg_data->cseq_counter, MES_STR,
				CON_TYP_STR, TXT_PLA_STR,
				MAX_FRW_STR,
				UA_STR, UA_VAL_STR);
			msg_data->req_buff += strlen(msg_data->req_buff);
			if (msg_data->from_uri) {
				sprintf(msg_data->req_buff,
					"%s%s;tag=%x\r\n",
					FROM_STR, msg_data->from_uri, c);
			}
			else {
				sprintf(msg_data->req_buff,
					"%ssip:sipsak@%s:%i;tag=%x\r\n",
					FROM_STR, msg_data->fqdn, msg_data->lport, c);
			}
			msg_data->req_buff += strlen(msg_data->req_buff);
			if (msg_data->mes_body) {
				len = strlen(msg_data->mes_body);
			}
			else {
				len = SIPSAK_MES_STR_LEN + strlen(msg_data->username);
			}
			sprintf(msg_data->req_buff, "%s%u\r\n", CON_LEN_STR, len);
			msg_data->req_buff += strlen(msg_data->req_buff);
			if (msg_data->con_dis) {
				sprintf(msg_data->req_buff, "%s%s\r\n", CON_DIS_STR, msg_data->con_dis);
				msg_data->req_buff += strlen(msg_data->req_buff);
			}
			sprintf(msg_data->req_buff, "\r\n");
			msg_data->req_buff += 2;
			if (msg_data->mes_body) {
				sprintf(msg_data->req_buff,
					"%s",
					msg_data->mes_body);
			}
			else {
				sprintf(msg_data->req_buff, "%s%s", SIPSAK_MES_STR, msg_data->username);
				msg_data->req_buff += strlen(msg_data->req_buff) - 1;
				*(msg_data->req_buff) = '.';
			}
			add_via(req_buf_begin, msg_data->fqdn, msg_data->lport);
			sprintf(msg_data->repl_buff,
				"%s"
				"%ssip:sipsak@%s:%i;tag=%x\r\n"
				"%ssip:%s%s;tag=%o%o\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s0\r\n"
				"%s%s\r\n"
				"\r\n", 
				SIP200_STR,
				FROM_STR, msg_data->fqdn, msg_data->lport, c,
				TO_STR, msg_data->username, msg_data->domainname, c, d,
				CALL_STR, c, msg_data->fqdn,
				CSEQ_STR, msg_data->cseq_counter, MES_STR,
				CON_LEN_STR,
				UA_STR, UA_VAL_STR);
			break;
		case REQ_OPT:
			sprintf(msg_data->req_buff,
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
				OPT_STR, msg_data->username, msg_data->domainname, SIP20_STR,
				FROM_STR, msg_data->fqdn, msg_data->lport, c,
				TO_STR, msg_data->username, msg_data->domainname,
				CALL_STR, c, msg_data->fqdn,
				CSEQ_STR, msg_data->cseq_counter, OPT_STR,
				CONT_STR, msg_data->fqdn, msg_data->lport,
				CON_LEN_STR,
				MAX_FRW_STR,
				UA_STR, UA_VAL_STR,
				ACP_STR, TXT_PLA_STR);
			add_via(req_buf_begin, msg_data->fqdn, msg_data->lport);
			break;
		case REQ_FLOOD:
			sprintf(msg_data->req_buff, 
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
				FLOOD_METH, msg_data->username, msg_data->domainname, SIP20_STR,
				VIA_SIP_STR, TRANSPORT_UDP_STR, msg_data->fqdn, d,
				FROM_STR, msg_data->fqdn, c,
				TO_STR, msg_data->username, msg_data->domainname,
				CALL_STR, c, msg_data->fqdn,
				CSEQ_STR, msg_data->cseq_counter, FLOOD_METH,
				CONT_STR, msg_data->fqdn,
				CON_LEN_STR,
				MAX_FRW_STR,
				UA_STR, UA_VAL_STR);
			break;
		case REQ_RAND:
			sprintf(msg_data->req_buff,
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
				OPT_STR, msg_data->domainname, SIP20_STR,
				FROM_STR, msg_data->fqdn, msg_data->lport, c,
				TO_STR, msg_data->domainname,
				CALL_STR, c, msg_data->fqdn,
				CSEQ_STR, msg_data->cseq_counter, OPT_STR,
				CONT_STR, msg_data->fqdn, msg_data->lport,
				CON_LEN_STR,
				MAX_FRW_STR,
				UA_STR, UA_VAL_STR);
			add_via(req_buf_begin, msg_data->fqdn, msg_data->lport);
			break;
		default:
			fprintf(stderr, "error: unknown request type to create\n");
			exit_code(2, __PRETTY_FUNCTION__, "unknown request type requested");
			break;
	}
	if (msg_data->headers) {
		insert_header(req_buf_begin, msg_data->headers, 1);
		if (msg_data->repl_buff)
			insert_header(msg_data->repl_buff, msg_data->headers, 1);
	}
}

