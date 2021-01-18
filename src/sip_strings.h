/*
 * Copyright (C) 2002-2004 Fhg Fokus
 * Copyright (C) 2004-2021 Nils Ohlmeier
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

#ifndef SIP_STRINGS_H
#define SIP_STRINGS_H

#define VIA_SIP_STR "Via: SIP/2.0/"
#define VIA_SIP_STR_LEN (sizeof(VIA_SIP_STR) - 1)

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
#define FROM_SHORT_STR "\nf: "
#define FROM_SHORT_STR_LEN (sizeof(FROM_SHORT_STR) - 1)

#define TO_STR "To: "
#define TO_STR_LEN (sizeof(TO_STR) - 1)
#define TO_SHORT_STR "\nt: "
#define TO_SHORT_STR_LEN (sizeof(TO_SHORT_STR) - 1)

#define VIA_STR "Via: "
#define VIA_STR_LEN (sizeof(VIA_STR) - 1)
#define VIA_SHORT_STR "\nv: "
#define VIA_SHORT_STR_LEN (sizeof(VIA_SHORT_STR) - 1)

#define CALL_STR "Call-ID: "
#define CALL_STR_LEN (sizeof(CALL_STR) - 1)
#define CALL_SHORT_STR "\ni: "
#define CALL_SHORT_STR_LEN (sizeof(CALL_SHORT_STR) - 1)

#define MAX_FRW_STR "Max-Forwards: "
#define MAX_FRW_STR_LEN (sizeof(MAX_FRW_STR) - 1)

#define CSEQ_STR "CSeq: "
#define CSEQ_STR_LEN (sizeof(CSEQ_STR) - 1)

#define CONT_STR "Contact: "
#define CONT_STR_LEN (sizeof(CONT_STR) - 1)
#define CONT_SHORT_STR "\nm: "
#define CONT_SHORT_STR_LEN (sizeof(CONT_SHORT_STR) - 1)

#define CON_TYP_STR "Content-Type: "
#define CON_TYP_STR_LEN (sizeof(CON_TYP_STR) - 1)
#define CON_TYP_SHORT_STR "\nc: "
#define CON_TYP_SHORT_STR_LEN (sizeof(CON_TYP_SHORT_STR) - 1)

#define CON_DIS_STR "Content-Disposition: "
#define CON_DIS_STR_LEN (sizeof(CON_DIS_STR) - 1)

#define TXT_PLA_STR "text/plain"
#define TXT_PLA_STR_LEN (sizeof(TXT_PLA_STR) - 1)

#define ACP_STR "Accept: "
#define ACP_STR_LEN (sizeof(ACP_STR) - 1)

#define CON_LEN_STR "Content-Length: "
#define CON_LEN_STR_LEN (sizeof(CON_LEN_STR) - 1)
#define CON_LEN_SHORT_STR "\nl: "
#define CON_LEN_SHORT_STR_LEN (sizeof(CON_LEN_SHORT_STR) - 1)

#define RR_STR "Record-Route: "
#define RR_STR_LEN (sizeof(RR_STR) -  1)

#define ROUTE_STR "Route: "
#define ROUTE_STR_LEN (sizeof(ROUTE_STR) - 1)

#define SIPSAK_MES_STR "test message from SIPsak for user "
#define SIPSAK_MES_STR_LEN (sizeof(SIPSAK_MES_STR) - 1)

#define EXP_STR "Expires: "
#define EXP_STR_LEN (sizeof(EXP_STR) - 1)

#define CON_EXP_STR "expires="
#define CON_EXP_STR_LEN (sizeof(CON_EXP_STR) - 1)

#define WWWAUTH_STR "WWW-Authenticate: "
#define WWWAUTH_STR_LEN (sizeof(WWWAUTH_STR) - 1)

#define PROXYAUTH_STR "Proxy-Authenticate: "
#define PROXYAUTH_STR_LEN (sizeof(PROXYAUTH_STR) - 1)

#define AUTH_STR "Authorization: Digest "
#define AUTH_STR_LEN (sizeof(AUTH_STR) - 1)

#define PROXYAUZ_STR "Proxy-Authorization: Digest "
#define PROXYAUZ_STR_LEN (sizeof(PROXYAUZ_STR) - 1)

#define ALGO_STR "algorithm="
#define ALGO_STR_LEN (sizeof(ALGO_STR) - 1)

#define MD5_STR "MD5, "
#define MD5_STR_LEN (sizeof(MD5_STR) - 1)

#define SHA1_STR "SHA1, "
#define SHA1_STR_LEN (sizeof(SHA1_STR) - 1)

#define SHA256_STR "SHA-256, "
#define SHA256_STR_LEN (sizeof(SHA256_STR) - 1)

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

#define TRANSPORT_PARAMETER_STR ";transport="
#define TRANSPORT_PARAMETER_STR_LEN (sizeof(TRANSPORT_PARAMETER_STR) - 1)

#endif
