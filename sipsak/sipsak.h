/*
 * $Id: sipsak.h,v 1.24 2005/03/01 11:38:05 calrissian Exp $
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

#ifndef SIPSAK_H
#define SIPSAK_H

#include <sys/types.h>
#include <regex.h>

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_STRCASESTR
#define __USE_GNU
#define strstr strcasestr
#endif

#define SIPSAK_VERSION PACKAGE_VERSION
#define BUFSIZE		4096
#ifdef HAVE_SYS_PARAM_H
#define FQDN_SIZE   MAXHOSTNAMELEN + 1
#else
#define FQDN_SIZE   100
#endif

#ifdef HAVE_CONFIG_H
#define SIP_T1 DEFAULT_TIMEOUT
#else
#define SIP_T1 500
#endif
#define SIP_T2 8*SIP_T1

#define REQ_REG 1
#define REQ_REM 2
#define REQ_INV 3
#define REQ_MES 4
#define REQ_OPT 5
#define REQ_FLOOD 6
#define REQ_RAND 7

#define VIA_SIP_STR "Via: SIP/2.0/UDP "
#define VIA_SIP_STR_LEN (sizeof(VIA_SIP_STR) - 1)

#define MAX_FRW_STR "Max-Forwards: "
#define MAX_FRW_STR_LEN (sizeof(MAX_FRW_STR) - 1)

#define SIP20_STR " SIP/2.0\r\n"
#define SIP20_STR_LEN (sizeof(SIP20_STR) - 1)

#define SIP200_STR "SIP/2.0 200 OK\r\n"
#define SIP200_STR_LEN (sizeof(SIP200_STR) - 1)

#define INV_STR "INVITE"
#define INV_STR_LEN (sizeof(INV_STR) - 1)

#define REG_STR "REGISTER"
#define REG_STR_LEN (sizeof(REG_STR) - 1)

#define OPT_STR "OPTIONS"
#define OPT_STR_LEN (sizeof(OPT_STR) - 1)

#define MES_STR "MESSAGE"
#define MES_STR_LEN (sizeof(MES_STR) - 1)

#define ACK_STR "ACK"
#define ACK_STR_LEN (sizeof(ACK_STR) - 1)

#define FROM_STR "From: "
#define FROM_STR_LEN (sizeof(FROM_STR) - 1)
#define FROM_SHORT_STR "f: "
#define FROM_SHORT_STR_LEN (sizeof(FROM_SHORT_STR) - 1)

#define TO_STR "To: "
#define TO_STR_LEN (sizeof(TO_STR) - 1)
#define TO_SHORT_STR "t: "
#define TO_SHORT_STR_LEN (sizeof(TO_SHORT_STR) - 1)

#define VIA_STR "Via: "
#define VIA_STR_LEN (sizeof(VIA_STR) - 1)
#define VIA_SHORT_STR "v: "
#define VIA_SHORT_STR_LEN (sizeof(VIA_SHORT_STR) - 1)

#define CALL_STR "Call-ID: "
#define CALL_STR_LEN (sizeof(CALL_STR) - 1)

#define CSEQ_STR "CSeq: "
#define CSEQ_STR_LEN (sizeof(CSEQ_STR) - 1)

#define CONT_STR "Contact: "
#define CONT_STR_LEN (sizeof(CONT_STR) - 1)
#define CONT_SHORT_STR "m: "
#define CONT_SHORT_STR_LEN (sizeof(CONT_SHORT_STR) - 1)

#define CON_TYP_STR "Content-Type: "
#define CON_TYP_STR_LEN (sizeof(CON_TYP_STR) - 1)

#define CON_DIS_STR "Content-Disposition: "
#define CON_DIS_STR_LEN (sizeof(CON_DIS_STR) - 1)

#define TXT_PLA_STR "text/plain"
#define TXT_PLA_STR_LEN (sizeof(TXT_PLA_STR) - 1)

#define ACP_STR "Accept: "
#define ACP_STR_LEN (sizeof(ACP_STR) - 1)

#define CON_LEN_STR "Content-Length: "
#define CON_LEN_STR_LEN (sizeof(CON_LEN_STR) - 1)
#define CON_LEN_SHORT_STR "l: "
#define CON_LEN_SHORT_STR_LEN (sizeof(CON_LEN_SHORT_STR) - 1)

#define RR_STR "Record-Route: "
#define RR_STR_LEN (sizeof(RR_STR) -  1)

#define ROUTE_STR "Route: "
#define ROUTE_STR_LEN (sizeof(ROUTE_STR) - 1)

#define SIPSAK_MES_STR "usrloc test message from SIPsak for user "
#define SIPSAK_MES_STR_LEN (sizeof(SIPSAK_MES_STR) - 1)

#define EXP_STR "Expires: "
#define EXP_STR_LEN (sizeof(EXP_STR) - 1)

#define CON_EXP_STR "expires="
#define CON_EXP_STR_LEN (sizeof(CON_EXP_STR) - 1)

#define USRLOC_EXP_DEF 15
#define FLOOD_METH "OPTIONS"
#define USRLOC_REMOVE_PERCENT 0.1

#define WWWAUTH_STR "WWW-Authenticate: "
#define WWWAUTH_STR_LEN (sizeof(WWWAUTH_STR) - 1)

#define PROXYAUTH_STR "Proxy-Authenticate: "
#define PROXYAUTH_STR_LEN (sizeof(PROXYAUTH_STR) - 1)

#define AUTH_STR "Authorization: Digest "
#define AUTH_STR_LEN (sizeof(AUTH_STR) - 1)

#define PROXYAUZ_STR "Proxy-Authorization: Digest "
#define PROXYAUZ_STR_LEN (sizeof(PROXYAUZ_STR) - 1)

#define ALGO_MD5_STR "algorithm=MD5, "
#define ALGO_MD5_STR_LEN (sizeof(ALGO_MD5_STR) - 1)

#define REALM_STR "realm="
#define REALM_STR_LEN (sizeof(REALM_STR) - 1)

#define OPAQUE_STR "opaque="
#define OPAQUE_STR_LEN (sizeof(OPAQUEE_STR) - 1)

#define NONCE_STR "nonce="
#define NONCE_STR_LEN (sizeof(NONCE_STR) - 1)

#define RESPONSE_STR "response="
#define RESPONSE_STR_LEN (sizeof(RESPONSE_STR) - 1)

#define QOP_STR "qop="
#define QOP_STR_LEN (sizeof(QOP_STR) - 1)

#define QOPAUTH_STR "auth"
#define QOPAUTH_STR_LEN (sizeof(QOPAUTH_STR) - 1)

#define NC_STR "nc="
#define NC_STR_LEN (sizeof(NC_STR) - 1)

#define EMPTY_STR ""
#define EMPTY_STR_LEN (sizeof(EMPTY_STR) - 1)

#define UA_STR "User-Agent: "
#define UA_STR_LEN (sizeof(UA_STR) - 1)

#define SUB_STR "Subject: "
#define SUB_STR_LEN (sizeof(SUB_STR) - 1)

#define SIP100_STR "SIP/2.0 100"
#define SIP100_STR_LEN (sizeof(SIP100_STR) - 1)

#define MD5_HASHLEN 16
#define HASHHEXLEN 2 * MD5_HASHLEN

/* lots of global variables. ugly but makes life easier. */
long address;
int sleep_ms;
int verbose, nameend, namebeg, expires_t, flood, warning_ext, invite, message;
int maxforw, lport, rport, randtrash, trashchar, numeric;
unsigned int nonce_count;
int file_b, uri_b, trace, via_ins, usrloc, redirects, rand_rem, replace_b;
int empty_contact, nagios_warn, fix_crlf;
char *username, *domainname, *password, *replace_str, *hostname, *contact_uri;
char *mes_body, *con_dis, *auth_username;
char fqdn[FQDN_SIZE];
char messusern[FQDN_SIZE];
char confirm[BUFSIZE];
char ack[BUFSIZE];
regex_t* re;
int processes;

#endif
