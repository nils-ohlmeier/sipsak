/*
 * $Id: sipsak.h,v 1.14 2004/07/25 18:45:46 calrissian Exp $
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#define SIPSAK_VERSION PACKAGE_VERSION
#define BUFSIZE		4096
#ifdef HAVE_SYS_PARAMS_H
#define FQDN_SIZE   MAXHOSTNAMELEN + 1
#else
#define FQDN_SIZE   200
#endif

#define SIP_T1 500
#define SIP_T2 4000

#define REQ_REG 1
#define REQ_REM 2
#define REQ_INV 3
#define REQ_MES 4
#define REQ_OPT 5
#define REQ_FLOOD 6
#define REQ_RAND 7
#define VIA_STR "Via: SIP/2.0/UDP "
#define VIA_STR_LEN 17
#define MAX_FRW_STR "Max-Forwards: "
#define MAX_FRW_STR_LEN 14
#define SIP20_STR " SIP/2.0\r\n"
#define SIP20_STR_LEN 10
#define SIP200_STR "SIP/2.0 200 OK\r\n"
#define SIP200_STR_LEN 16
#define INV_STR "INVITE"
#define INV_STR_LEN 6
#define REG_STR "REGISTER"
#define REG_STR_LEN 8
#define OPT_STR "OPTIONS"
#define OPT_STR_LEN 7
#define MES_STR "MESSAGE"
#define MES_STR_LEN 7
#define ACK_STR "ACK"
#define ACK_STR_LEN 3
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
#define CON_TYP_STR "Content-Type: "
#define CON_TYP_STR_LEN 14
#define CON_DIS_STR "Content-Disposition: "
#define CON_DIS_STR_LEN 21
#define TXT_PLA_STR "text/plain"
#define TXT_PLA_STR_LEN 10
#define ACP_STR "Accept: "
#define ACP_STR_LEN 8
#define CON_LEN_STR "Content-Length: "
#define CON_LEN_STR_LEN 16
#define SIPSAK_MES_STR "usrloc test message from SIPsak for user "
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
#define PROXYAUTH_STR "Proxy-Authenticate: "
#define PROXYAUTH_STR_LEN 20
#define AUTH_STR "Authorization: Digest "
#define AUTH_STR_LEN 22
#define PROXYAUZ_STR "Proxy-Authorization: Digest "
#define PROXYAUZ_STR_LEN 28
#define REALM_STR "realm="
#define REALM_STR_LEN 6
#define OPAQUE_STR "opaque="
#define NONCE_STR "nonce="
#define NONCE_STR_LEN 6
#define RESPONSE_STR "response="
#define RESPONSE_STR_LEN 9
#define QOP_STR "qop="
#define QOP_STR_LEN 4
#define QOPAUTH_STR "auth"
#define NC_STR "nc="
#define UA_STR "User-Agent: "
#define SUB_STR "Subject: "
#define SUB_STR_LEN 8
#define SIP100_STR "SIP/2.0 100"
#define SIP100_STR_LEN 11

#define MD5_HASHLEN 16
#define HASHHEXLEN 2*MD5_HASHLEN

/* lots of global variables. ugly but makes life easier. */
long address;
int sleep_ms;
int verbose, nameend, namebeg, expires_t, flood, warning_ext, invite, message;
int maxforw, lport, rport, randtrash, trashchar, numeric, nonce_count;
int file_b, uri_b, trace, via_ins, usrloc, redirects, rand_rem, replace_b;
int empty_contact, nagios_warn;
char *username, *domainname, *password, *replace_str, *hostname, *contact_uri;
char *mes_body, *con_dis;
char fqdn[FQDN_SIZE], messusern[FQDN_SIZE];
char confirm[BUFSIZE], ack[BUFSIZE];

#endif
