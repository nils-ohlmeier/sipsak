/*
 * $Id: auth.c,v 1.7 2004/06/05 17:39:14 calrissian Exp $
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
#include <string.h>

#include "auth.h"
#include "sipsak.h"
#include "md5global.h"
#include "md5.h"
#include "exit_code.h"

/* converts a hash into hex output
   taken from the RFC 2617 */
void cvt_hex(char *_b, char *_h)
{
        unsigned short i;
        unsigned char j;

        for (i = 0; i < MD5_HASHLEN; i++) {
                j = (_b[i] >> 4) & 0xf;
                if (j <= 9) {
                        _h[i * 2] = (j + '0');
                } else {
                        _h[i * 2] = (j + 'a' - 10);
                }
                j = _b[i] & 0xf;
                if (j <= 9) {
                        _h[i * 2 + 1] = (j + '0');
                } else {
                        _h[i * 2 + 1] = (j + 'a' - 10);
                }
        };
        _h[HASHHEXLEN] = '\0';
}

/* check for, create and insert a auth header into the message */
void insert_auth(char *message, char *authreq)
{
	char *auth, *begin, *end, *insert, *backup, *realm, *usern, *nonce, 
		*method, *uri;
	char *qop_tmp = NULL;
	char ha1[MD5_HASHLEN], ha2[MD5_HASHLEN], resp[MD5_HASHLEN]; 
	char ha1_hex[HASHHEXLEN+1], ha2_hex[HASHHEXLEN+1], resp_hex[HASHHEXLEN+1];
	int cnonce, qop_auth=0, proxy_auth=0;
	MD5_CTX Md5Ctx;

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
	insert++;
	backup=malloc(strlen(insert)+1);
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
		auth=malloc((end-begin)+1);
		strncpy(auth, begin, (end-begin));
		*(auth+(end-begin))='\0';
		/* we support Digest nad MD5 only */
		if ((begin=strstr(auth, "Basic"))!=NULL) {
			printf("%s\nerror: authentication method Basic is deprecated since"
				" RFC 3261 and not supported by sipsak\n", authreq);
			exit_code(3);
		}
		if ((begin=strstr(auth, "Digest"))==NULL) {
			printf("%s\nerror: couldn't find authentication method Digest in "
				"the 402 response above\n", authreq);
			exit_code(3);
		}
		if ((begin=strstr(auth, "algorithm="))!=NULL) {
			begin+=10;
			if ((strncmp(begin, "MD5", 3))!=0) {
				printf("%s\nerror: unsupported authentication algorithm\n", 
					authreq);
				exit_code(2);
			}
		}
		/* we need the username at some points */
		usern=malloc(strlen(username)+10);
		if (nameend>0)
			sprintf(usern, "%s%i", username, namebeg);
		else
			sprintf(usern, "%s", username);
		/* extract the method from teh original request */
		end=strchr(message, ' ');
		method=malloc(end-message+1);
		strncpy(method, message, (end-message));
		*(method+(end-message))='\0';
		/* extract the uri also */
		begin=end++;
		begin++;
		end=strchr(end, ' ');
		uri=malloc(end-begin+1);
		strncpy(uri, begin, (end-begin));
		*(uri+(end-begin))='\0';

		/* lets start with some basic stuff... username, uri and algorithm */
		if (proxy_auth) {
			sprintf(insert, PROXYAUZ_STR);
			insert=insert+PROXYAUZ_STR_LEN;
		}
		else {
			sprintf(insert, AUTH_STR);
			insert=insert+AUTH_STR_LEN;
		}
		sprintf(insert, "username=\"%s\", ", usern);
		insert+=strlen(insert);
		sprintf(insert, "uri=\"%s\", ", uri);
		insert+=strlen(insert);
		sprintf(insert, "algorithm=MD5, ");
		insert+=15;
		/* search for the realm, copy it to request and extract it for hash*/
		if ((begin=strstr(auth, REALM_STR))!=NULL) {
			end=strchr(begin, ',');
			if (!end)
				end=strchr(begin, '\r');
			strncpy(insert, begin, end-begin+1);
			insert=insert+(end-begin+1);
			if (*(insert-1) == '\r')
				*(insert-1)=',';
			sprintf(insert, " ");
			insert++;
			begin+=REALM_STR_LEN+1;
			end--;
			realm=malloc(end-begin+1);
			strncpy(realm, begin, (end-begin));
			*(realm+(end-begin))='\0';
		}
		else {
			printf("%s\nerror: realm not found in 401 above\n", authreq);
			exit_code(3);
		}
		/* copy opaque if needed */
		if ((begin=strstr(auth, OPAQUE_STR))!=NULL) {
			end=strchr(begin, ',');
			strncpy(insert, begin, end-begin+1);
			insert=insert+(end-begin+1);
			sprintf(insert, " ");
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
			strncpy(insert, begin, end-begin+1);
			insert=insert+(end-begin+1);
			if (*(insert-1) == '\r')
				*(insert-1)=',';
			sprintf(insert, " ");
			insert++;
			begin+=NONCE_STR_LEN+1;
			end--;
			nonce=malloc(end-begin+1);
			strncpy(nonce, begin, (end-begin));
			*(nonce+(end-begin))='\0';
		}
		else {
			printf("%s\nerror: nonce not found in 401 above\n", authreq);
			exit_code(3);
		}
		/* if qop is supported we need som additional header */
		if (qop_auth) {
			sprintf(insert, "%s%s, ", QOP_STR, QOPAUTH_STR);
			insert+=strlen(insert);
			nonce_count++;
			sprintf(insert, "%s%x, ", NC_STR, nonce_count);
			insert+=strlen(insert);
			cnonce=rand();
			sprintf(insert, "cnonce=\"%x\", ", cnonce);
			insert+=strlen(insert);
			/* hopefully 100 is enough */
			qop_tmp=malloc(100);
			sprintf(qop_tmp, "%x:%x:auth:", nonce_count, cnonce);
		}
		/* if no password is given we try it with the username */
		if (!password)
			password=usern;

		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx, usern, strlen(usern));
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, realm, strlen(realm));
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, password, strlen(password));
		MD5Final(ha1, &Md5Ctx);
		cvt_hex(&ha1[0], &ha1_hex[0]);

		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx, method, strlen(method));
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, uri, strlen(uri));
		MD5Final(ha2, &Md5Ctx);
		cvt_hex(&ha2[0], &ha2_hex[0]);

		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx, &ha1_hex, HASHHEXLEN);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, nonce, strlen(nonce));
		MD5Update(&Md5Ctx, ":", 1);
		if (qop_auth) {
			MD5Update(&Md5Ctx, qop_tmp, strlen(qop_tmp));
		}
		MD5Update(&Md5Ctx, &ha2_hex, HASHHEXLEN);
		MD5Final(resp, &Md5Ctx);
		cvt_hex(&resp[0], &resp_hex[0]);

		sprintf(insert, RESPONSE_STR);
		insert+=RESPONSE_STR_LEN;
		sprintf(insert, "\"%s\"\r\n", resp_hex);
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
	free(backup); free(auth); free(usern); free(method); free(uri); 
	free(realm); free(nonce); 
	if (qop_auth) free(qop_tmp);
}

