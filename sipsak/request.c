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

/* create a valid sip header for the different modes */
void create_msg(int action, char *req_buff, char *repl_buff, char *username, int cseq){
	unsigned int c, d, len;

	if(cseq == 0) {
		printf("error: CSeq 0 is not allowed\n");
		exit_code(253);
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
				"%s%s:%i;branch=z9hG4bK.%08x;rport\r\n"
				"%ssip:%s%s;tag=%x\r\n"
				"%ssip:%s%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s0\r\n"
				"%s70\r\n"
				"%ssipsak %s\r\n",
				REG_STR, domainname, SIP20_STR, 
				VIA_SIP_STR, fqdn, lport, d,
				FROM_STR, username, domainname, c,
				TO_STR, username, domainname, 
				CALL_STR, c, fqdn, 
				CSEQ_STR, cseq, REG_STR, 
				CON_LEN_STR, 
				MAX_FRW_STR, 
				UA_STR, SIPSAK_VERSION);
			req_buff += strlen(req_buff);
			if (contact_uri!=NULL) {
				sprintf(req_buff, "%s%i\r\n"
					"%s%s\r\n\r\n",
					EXP_STR, expires_t,
					CONT_STR, contact_uri);
			}
			else if (empty_contact == 0) {
				sprintf(req_buff, "%s%i\r\n"
					"%ssip:%s%s:%i\r\n\r\n",
					EXP_STR, expires_t,
					CONT_STR, username, fqdn, lport);
			}
			else{
				sprintf(req_buff, "\r\n");
			}
			break;
		case REQ_REM:
			sprintf(req_buff, 
				"%s sip:%s%s"
				"%s%s:%i;branch=z9hG4bK.%08x;rport\r\n"
				"%ssip:%s%s;tag=%x\r\n"
				"%ssip:%s%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%ssip:%s%s:%i;%s0\r\n"
				"%s%i\r\n"
				"%s0\r\n"
				"%s70\r\n"
				"%ssipsak %s\r\n"
				"\r\n", 
				REG_STR, domainname, SIP20_STR, 
				VIA_SIP_STR, fqdn, lport, d,
				FROM_STR, username, domainname, c,
				TO_STR, username, domainname, 
				CALL_STR, c, fqdn,
				CSEQ_STR, cseq, REG_STR, 
				CONT_STR, username, fqdn, lport, CON_EXP_STR, 
				EXP_STR, expires_t, 
				CON_LEN_STR, 
				MAX_FRW_STR, 
				UA_STR, SIPSAK_VERSION);
			break;
		case REQ_INV:
			sprintf(req_buff, 
				"%s sip:%s%s%s"
				"%s%s:%i;branch=z9hG4bK.%08x;rport\r\n"
				"%ssip:sipsak@%s:%i;tag=%x\r\n"
				"%ssip:%s%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s0\r\n"
				"%ssip:sipsak@%s:%i\r\n"
				"%sDONT ANSWER this test call!\r\n"
				"%s70\r\n"
				"%ssipsak %s\r\n"
				"\r\n", 
				INV_STR, username, domainname, SIP20_STR, 
				VIA_SIP_STR, fqdn, lport, d,
				FROM_STR, fqdn, lport, c,
				TO_STR, username, domainname, 
				CALL_STR, c, fqdn, 
				CSEQ_STR, cseq, INV_STR, 
				CON_LEN_STR, 
				CONT_STR, fqdn, lport,
				SUB_STR, 
				MAX_FRW_STR, 
				UA_STR, SIPSAK_VERSION);
			sprintf(repl_buff, 
				"%s"
				"%ssip:sipsak@%s:%i;tag=%x\r\n"
				"%ssip:%s%s;tag=%o%o\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s0\r\n"
				"%ssip:sipsak_conf@%s:%i\r\n"
				"%ssipsak %s\r\n"
				"\r\n", 
				SIP200_STR, 
				FROM_STR, fqdn, lport, c,
				TO_STR, username, domainname, c, d,
				CALL_STR, c, fqdn, 
				CSEQ_STR, cseq, INV_STR, 
				CON_LEN_STR,
				CONT_STR, fqdn, lport,
				UA_STR, SIPSAK_VERSION);
			break;
		case REQ_MES:
			sprintf(req_buff,
				"%s sip:%s%s%s"
				"%s%s:%i;branch=z9hG4bK.%08x;rport\r\n"
				"%ssip:sipsak@%s:%i;tag=%x\r\n"
				"%ssip:%s%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s%s\r\n"
				"%s70\r\n"
				"%ssipsak %s\r\n",
				MES_STR, username, domainname, SIP20_STR, 
				VIA_SIP_STR, fqdn, lport, d,
				FROM_STR, fqdn, lport, c,
				TO_STR, username, domainname, 
				CALL_STR, c, fqdn, 
				CSEQ_STR, cseq, MES_STR, 
				CON_TYP_STR, TXT_PLA_STR, 
				MAX_FRW_STR, 
				UA_STR, SIPSAK_VERSION);
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
			sprintf(repl_buff,
				"%s"
				"%ssip:sipsak@%s:%i;tag=%x\r\n"
				"%ssip:%s%s;tag=%o%o\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%s0\r\n"
				"%ssipsak %s\r\n"
				"\r\n", 
				SIP200_STR, 
				FROM_STR, fqdn, lport, c,
				TO_STR, username, domainname, c, d,
				CALL_STR, c, fqdn, 
				CSEQ_STR, cseq, MES_STR, 
				CON_LEN_STR,
				UA_STR, SIPSAK_VERSION);
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
				"%ssipsak %s\r\n"
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
				UA_STR, SIPSAK_VERSION, 
				ACP_STR, TXT_PLA_STR);
			break;
		case REQ_FLOOD:
			sprintf(req_buff, 
				"%s sip:%s%s"
				"%s%s:9;branch=z9hG4bK.%08x\r\n"
				"%ssip:sipsak@%s:9;tag=%x\r\n"
				"%ssip:%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%ssip:sipsak@%s:9\r\n"
				"%s0\r\n"
				"%s70\r\n"
				"%ssipsak %s\r\n"
				"\r\n", 
				FLOOD_METH, domainname, SIP20_STR, 
				VIA_SIP_STR, fqdn, d,
				FROM_STR, fqdn, c,
				TO_STR, domainname, 
				CALL_STR, c, fqdn, 
				CSEQ_STR, cseq, FLOOD_METH, 
				CONT_STR, fqdn, 
				CON_LEN_STR, 
				MAX_FRW_STR, 
				UA_STR, SIPSAK_VERSION);
			break;
		case REQ_RAND:
			sprintf(req_buff, 
				"%s sip:%s%s"
				"%s%s:%i;branch=z9hG4bK.%08x;rport\r\n"
				"%ssip:sipsak@%s:%i;tag=%x\r\n"
				"%ssip:%s\r\n"
				"%s%u@%s\r\n"
				"%s%i %s\r\n"
				"%ssipsak@%s:%i\r\n"
				"%s0\r\n"
				"%s70\r\n"
				"%ssipsak %s\r\n"
				"\r\n", 
				OPT_STR, domainname, SIP20_STR, 
				VIA_SIP_STR, fqdn, lport, d,
				FROM_STR, fqdn, lport, c,
				TO_STR, domainname,	
				CALL_STR, c, fqdn, 
				CSEQ_STR, cseq, OPT_STR, 
				CONT_STR, fqdn,	lport, 
				CON_LEN_STR, 
				MAX_FRW_STR, 
				UA_STR, SIPSAK_VERSION);
			break;
		default:
			printf("error: unknown request type to create\n");
			exit_code(2);
			break;
	}
}

