/*
 * $Id: auth.c,v 1.17 2005/03/01 12:05:35 calrissian Exp $
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

#include "config.h"
#include "auth.h"
#include "sipsak.h"
#include "exit_code.h"

#include <string.h>

#ifdef HAVE_OPENSSL_MD5_H
#include <openssl/md5.h>
#else
#include "md5global.h"
#endif

#include "md5.h"

/* converts a hash into hex output
   taken from the RFC 2617 */
void cvt_hex(unsigned char *_b, unsigned char *_h)
{
        unsigned short i;
        unsigned char j;

        for (i = 0; i < MD5_HASHLEN; i++) {
                j = (_b[i] >> 4) & 0xf;
                if (j <= (unsigned char)9) {
                        _h[i * 2] = (j + (unsigned char)'0');
                } else {
                        _h[i * 2] = (unsigned char)(j + (unsigned char)'a' - (unsigned char)10);
                }
                j = _b[i] & 0xf;
                if (j <= (unsigned char)9) {
                        _h[i * 2 + 1] = (j + (unsigned char)'0');
                } else {
                        _h[i * 2 + 1] = (unsigned char)(j + (unsigned char)'a' - (unsigned char)10);
                }
        };
        _h[HASHHEXLEN] = '\0';
}

/* check for, create and insert a auth header into the message */
void insert_auth(char *message, char *authreq)
{
	char *auth, *begin, *end, *insert, *backup, *realm, *usern, *nonce;
	char *method, *uri;
	char *qop_tmp = NULL;
	unsigned char ha1[MD5_HASHLEN], ha2[MD5_HASHLEN], resp[MD5_HASHLEN]; 
	unsigned char ha1_hex[HASHHEXLEN+1], ha2_hex[HASHHEXLEN+1], resp_hex[HASHHEXLEN+1];
	int qop_auth=0, proxy_auth=0;
	unsigned int cnonce;
	MD5_CTX Md5Ctx;

	auth=begin=end=insert=backup=realm=usern=nonce=method=uri = NULL;

	/* prevent double auth insertion */
	if ((begin=strstr(message, AUTH_STR))!=NULL ||
			(begin=strstr(message, PROXYAUZ_STR))!=NULL) {
		printf("\nrequest:\n%s\nresponse:\n%s\nerror: authorization failed\n  "
			"     request already contains (Proxy-) Authorization, but "
			"received 40[1|7], see above\n", message, authreq);
		exit_code(2);
	}
	/* make a backup of all except the request line because for 
	   simplicity we insert the auth header direct behind the request line */
	insert=strchr(message, '\n');
	if (!insert) {
		printf("failed to find newline\n");
		return;
	}
	insert++;
	backup=malloc(strlen(insert)+1);
	if (!backup) {
		printf("failed to allocate memory\n");
		exit_code(255);
	}
	strncpy(backup, insert, strlen(insert)+1);

	begin=strstr(authreq, WWWAUTH_STR);
	if (begin==NULL) {
		begin=strstr(authreq, PROXYAUTH_STR);
		proxy_auth = 1;
	}
	if (begin) {
		/* make a copy of the auth header to prevent that our searches
		   hit content of other header fields */
		end=strchr(begin, '\n');
		auth=malloc((size_t)((end-begin)+1));
		if (!auth) {
			printf("failed to allocate memory\n");
			exit_code(255);
		}
		strncpy(auth, begin, (size_t)(end-begin));
		*(auth+(end-begin))='\0';
		/* we support Digest and MD5 only */
		if ((begin=strstr(auth, "Basic"))!=NULL) {
			printf("%s\nerror: authentication method Basic is deprecated since"
				" RFC 3261 and not supported by sipsak\n", authreq);
			exit_code(3);
		}
#ifdef HAVE_STRCASESTR
		if ((begin=(char*)strcasestr(auth, "Digest"))==NULL) {
#else
		if ((begin=strstr(auth, "Digest"))==NULL) {
#endif
			printf("%s\nerror: couldn't find authentication method Digest in "
				"the 40[1|7] response above\n", authreq);
			exit_code(3);
		}
		if ((begin=strstr(auth, "algorithm="))!=NULL) {
			begin+=10;
			if ((strncmp(begin, "MD5", 3))!=0 && (strncmp(begin, "\"MD5\"", 5))!=0) {
				printf("\n%s\nerror: unsupported authentication algorithm\n", 
					authreq);
				exit_code(2);
			}
		}
		/* we need the username at some points */
		if (auth_username != NULL) {
			usern = auth_username;
		}
		else {
			usern=malloc(strlen(username)+10);
			if (!usern) {
				printf("failed to allocate memory\n");
				exit_code(255);
			}
			if (nameend>0)
				snprintf(usern, strlen(username)+10, "%s%i", username, namebeg);
			else
				snprintf(usern, strlen(username)+10, "%s", username);
		}
		/* extract the method from the original request */
		end=strchr(message, ' ');
		method=malloc((size_t)(end-message+1));
		if (!method) {
			printf("failed to allocate memory\n");
			exit_code(255);
		}
		strncpy(method, message, (size_t)(end-message));
		*(method+(end-message))='\0';
		/* extract the uri also */
		begin=end++;
		begin++;
		end=strchr(end, ' ');
		uri=malloc((size_t)(end-begin+1));
		if (!uri) {
			printf("failed to allocate memory\n");
			exit_code(255);
		}
		strncpy(uri, begin, (size_t)(end-begin));
		*(uri+(end-begin))='\0';

		/* lets start with some basic stuff... username, uri and algorithm */
		if (proxy_auth == 1) {
			snprintf(insert, PROXYAUZ_STR_LEN+1, PROXYAUZ_STR);
			insert+=PROXYAUZ_STR_LEN;
		}
		else {
			snprintf(insert, AUTH_STR_LEN+1, AUTH_STR);
			insert+=AUTH_STR_LEN;
		}
		snprintf(insert, strlen(usern)+14, "username=\"%s\", ", usern);
		insert+=strlen(insert);
		snprintf(insert, strlen(uri)+9, "uri=\"%s\", ", uri);
		insert+=strlen(insert);
		snprintf(insert, ALGO_MD5_STR_LEN+1, ALGO_MD5_STR);
		insert+=ALGO_MD5_STR_LEN;
		/* search for the realm, copy it to request and extract it for hash*/
		if ((begin=strstr(auth, REALM_STR))!=NULL) {
			end=strchr(begin, ',');
			if (!end)
				end=strchr(begin, '\r');
			strncpy(insert, begin, (size_t)(end-begin+1));
			insert=insert+(end-begin+1);
			if (*(insert-1) == '\r')
				*(insert-1)=',';
			snprintf(insert, 2, " ");
			insert++;
			begin+=REALM_STR_LEN+1;
			end--;
			realm=malloc((size_t)(end-begin+1));
			if (!realm) {
				printf("failed to allocate memory\n");
				exit_code(255);
			}
			strncpy(realm, begin, (size_t)(end-begin));
			*(realm+(end-begin))='\0';
		}
		else {
			printf("%s\nerror: realm not found in 401 above\n", authreq);
			exit_code(3);
		}
		/* copy opaque if needed */
		if ((begin=strstr(auth, OPAQUE_STR))!=NULL) {
			end=strchr(begin, ',');
			if (!end) {
				end=strchr(begin, '\r');
			}
			strncpy(insert, begin, (size_t)(end-begin+1));
			insert=insert+(end-begin+1);
			if (*(insert-1) == '\r')
				*(insert-1)=',';
			snprintf(insert, 2, " ");
			insert++;
		}
		/* lets see if qop=auth is uspported */
		if ((begin=strstr(auth, QOP_STR))!=NULL) {
			if (strstr(begin, QOPAUTH_STR)==NULL) {
				printf("\nresponse\n%s\nerror: qop \"auth\" not supported by"
					" server\n", authreq);
				exit_code(3);
			}
			qop_auth=1;
		}
		/* search, copy and extract the nonce */
		if ((begin=strstr(auth, NONCE_STR))!=NULL) {
			end=strchr(begin, ',');
			if (!end)
				end=strchr(begin, '\r');
			strncpy(insert, begin, (size_t)(end-begin+1));
			insert=insert+(end-begin+1);
			if (*(insert-1) == '\r')
				*(insert-1)=',';
			snprintf(insert, 2, " ");
			insert++;
			begin+=NONCE_STR_LEN+1;
			end--;
			nonce=malloc((size_t)(end-begin+1));
			if (!nonce) {
				printf("failed to allocate memory\n");
				exit_code(255);
			}
			strncpy(nonce, begin, (size_t)(end-begin));
			*(nonce+(end-begin))='\0';
		}
		else {
			printf("%s\nerror: nonce not found in 401 above\n", authreq);
			exit_code(3);
		}
		/* if qop is supported we need som additional header */
		if (qop_auth == 1) {
			snprintf(insert, QOP_STR_LEN+QOPAUTH_STR_LEN+3, "%s%s, ", QOP_STR, QOPAUTH_STR);
			insert+=strlen(insert);
			nonce_count++;
			snprintf(insert, NC_STR_LEN+13, "%s%x, ", NC_STR, nonce_count);
			insert+=strlen(insert);
			cnonce=(unsigned int)rand();
			/* FIXME: RANDMAX has probably 4 bytes on 32 arch, but 64 bits..? */
			snprintf(insert, 12+8, "cnonce=\"%x\", ", cnonce);
			insert+=strlen(insert);
			/* hopefully 100 is enough */
			qop_tmp=malloc(100);
			if (!qop_tmp) {
				printf("failed to allocate memory\n");
				exit_code(255);
			}
			snprintf(qop_tmp, 10+8, "%x:%x:auth:", nonce_count, cnonce);
		}
		/* if no password is given we try it with empty password */
		if (!password)
			password = EMPTY_STR;

		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx, usern, (unsigned int)strlen(usern));
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, realm, (unsigned int)strlen(realm));
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, password, (unsigned int)strlen(password));
		MD5Final(&ha1[0], &Md5Ctx);
		cvt_hex(&ha1[0], &ha1_hex[0]);

		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx, method, (unsigned int)strlen(method));
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, uri, (unsigned int)strlen(uri));
		MD5Final(&ha2[0], &Md5Ctx);
		cvt_hex(&ha2[0], &ha2_hex[0]);

		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx, &ha1_hex, HASHHEXLEN);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, nonce, (unsigned int)strlen(nonce));
		MD5Update(&Md5Ctx, ":", 1);
		if (qop_auth == 1) {
			MD5Update(&Md5Ctx, qop_tmp, (unsigned int)strlen(qop_tmp));
		}
		MD5Update(&Md5Ctx, &ha2_hex, HASHHEXLEN);
		MD5Final(&resp[0], &Md5Ctx);
		cvt_hex(&resp[0], &resp_hex[0]);

		snprintf(insert, RESPONSE_STR_LEN+1, RESPONSE_STR);
		insert+=RESPONSE_STR_LEN;
		snprintf(insert, sizeof(resp_hex)+5,"\"%s\"\r\n", &resp_hex[0]);
		insert+=strlen(insert);
		/* the auth header is complete, reinsert the rest of the request */
		strncpy(insert, backup, strlen(backup));
	}
	else {
		printf("%s\nerror: couldn't find Proxy- or WWW-Authentication header"
			" in the 401 response above\n",	authreq);
		exit_code(3);
	}
	if (verbose>1) 
		printf("authorizing\n");
	/* hopefully we free all here */
	free(backup);
	free(auth);
	free(method);
	free(uri); 
	free(realm);
	free(nonce); 
	if (auth_username == NULL) free(usern); 
	if (qop_auth == 1) free(qop_tmp);
}

