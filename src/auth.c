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
#include "auth.h"
#include "exit_code.h"
#include "helper.h"
#include "md5.h"

#ifdef HAVE_OPENSSL_SHA1
# include <openssl/sha.h>
#endif

#define SIPSAK_ALGO_MD5 1
#define SIPSAK_ALGO_SHA1 2
#define SIPSAK_ALGO_SHA256 3

unsigned int nonce_count;

/* converts a hash into hex output
   taken from the RFC 2617 */
void cvt_hex(unsigned char *_b, unsigned char *_h, unsigned short length)
{
        unsigned short i;

        for (i = 0; i < length; i++) {
                unsigned char j;
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
        _h[2*length] = '\0';
}

/* check for, create and insert a auth header into the message */
void insert_auth(char *message, char *authreq, char *username,
    char *password, char *auth_username, char *authhash,
    int namebeg, int nameend)
{
	char *auth, *begin, *end, *insert, *backup, *realm, *usern, *nonce;
	char *method, *uri;
	char *qop_tmp = NULL;
	unsigned char ha1[SIPSAK_HASHLEN], ha2[SIPSAK_HASHLEN], resp[SIPSAK_HASHLEN];
	unsigned char ha1_hex[SIPSAK_HASHHEXLEN+1], ha2_hex[SIPSAK_HASHHEXLEN+1], resp_hex[SIPSAK_HASHHEXLEN+1];
	int qop_auth=0, proxy_auth=0, algo=0;
	MD5_CTX Md5Ctx;
#ifdef HAVE_OPENSSL_SHA1
	SHA_CTX Sha1Ctx;
	SHA256_CTX Sha256Ctx;
#endif

	auth=begin=end=insert=backup=realm=usern=nonce=method=uri = NULL;

	memset(&ha1[0], '\0', SIPSAK_HASHLEN);
	memset(&ha2[0], '\0', SIPSAK_HASHLEN);
	memset(&resp[0], '\0', SIPSAK_HASHLEN);
	memset(&ha1_hex[0], '\0', SIPSAK_HASHHEXLEN+1);
	memset(&ha2_hex[0], '\0', SIPSAK_HASHHEXLEN+1);
	memset(&resp_hex[0], '\0', SIPSAK_HASHHEXLEN+1);

	/* prevent double auth insertion */
	if ((begin=STRCASESTR(message, AUTH_STR))!=NULL ||
			(begin=STRCASESTR(message, PROXYAUZ_STR))!=NULL) {
		fprintf(stderr, "request:\n%s\nresponse:\n%s\nerror: authorization failed\n  "
			"     request already contains (Proxy-) Authorization, but "
			"received 40[1|7], see above\n", message, authreq);
		exit_code(2, __PRETTY_FUNCTION__, "failed to add auth header, because request contained already one");
	}
	/* make a backup of all except the request line because for
	   simplicity we insert the auth header direct behind the request line */
	insert=strchr(message, '\n');
	if (!insert) {
    fprintf(stderr, "%s\nerror: failed to locate new line in request message\n",
        message);
    exit_code(3, __PRETTY_FUNCTION__, "missing new line in request");
	}
	insert++;
	backup=str_alloc(strlen(insert)+1);
	strncpy(backup, insert, strlen(insert));

	begin=STRCASESTR(authreq, WWWAUTH_STR);
	if (begin==NULL) {
		begin=STRCASESTR(authreq, PROXYAUTH_STR);
		proxy_auth = 1;
	}
	if (begin) {
		/* make a copy of the auth header to prevent that our searches
		   hit content of other header fields */
		end=strchr(begin, '\n');
    if (end == NULL) {
      fprintf(stderr, "%s\nerror: failed to locate new line after auth header\n",
          authreq);
      exit_code(3, __PRETTY_FUNCTION__, "missing new line after auth header");
    }
		auth=str_alloc((size_t)(end-begin+1));
		strncpy(auth, begin, (size_t)(end-begin));
		/* we support Digest with MD5 or SHA1 */
		if ((begin=STRCASESTR(auth, "Basic"))!=NULL) {
			fprintf(stderr, "%s\nerror: authentication method Basic is deprecated since"
				" RFC 3261 and not supported by sipsak\n", authreq);
			exit_code(3, __PRETTY_FUNCTION__, "authentication method 'Basic' is deprecated");
		}
		if ((begin=STRCASESTR(auth, "Digest"))==NULL) {
			fprintf(stderr, "%s\nerror: couldn't find authentication method Digest in "
				"the 40[1|7] response above\n", authreq);
			exit_code(3, __PRETTY_FUNCTION__, "missing authentication method 'Digest' in reply");
		}
		if ((begin=STRCASESTR(auth, "algorithm="))!=NULL) {
			begin+=10;
			if ((STRNCASECMP(begin, "MD5", 3))==0 || (STRNCASECMP(begin, "\"MD5\"", 5))==0) {
				algo = SIPSAK_ALGO_MD5;
			}
#ifdef HAVE_OPENSSL_SHA1
			else if ((STRNCASECMP(begin, "SHA1", 4))==0 || (STRNCASECMP(begin, "\"SHA1\"", 6))==0) {
				algo = SIPSAK_ALGO_SHA1;
			}
			else if ((STRNCASECMP(begin, "SHA-256", 7))==0 || (STRNCASECMP(begin, "\"SHA-256\"", 9))==0) {
				algo = SIPSAK_ALGO_SHA256;
			}
#endif
			else {
				fprintf(stderr, "\n%s\nerror: unsupported authentication algorithm\n", authreq);
				exit_code(2, __PRETTY_FUNCTION__, "unsupported authentication algorithm");
			}
		}
		else {
			algo = SIPSAK_ALGO_MD5;
		}
		/* we need the username at some points */
		if (auth_username != NULL) {
			usern = auth_username;
		}
		else {
			usern=str_alloc(strlen(username)+11);
      if (usern == NULL) {
        fprintf(stderr, "error: failed to allocate space for username: %s\n",
            username);
        exit_code(3, __PRETTY_FUNCTION__, "memory allocation failure");
      }
			if (nameend>0)
				snprintf(usern, strlen(username)+10, "%s%d", username, namebeg);
			else
				snprintf(usern, strlen(username)+1, "%s", username);
		}
		/* extract the method from the original request */
		end=strchr(message, ' ');
    if (end == NULL) {
      fprintf(stderr, "%s\nerror: failed to locate space in message first line\n",
          authreq);
      exit_code(3, __PRETTY_FUNCTION__, "missing space in message");
    }
		method=str_alloc((size_t)(end-message+1));
		strncpy(method, message, (size_t)(end-message));
		/* extract the uri also */
		begin=end++;
		begin++;
		end=strchr(end, ' ');
    if (end == NULL) {
      fprintf(stderr, "%s\nerror: failed to locate space in message first line\n",
          authreq);
      exit_code(3, __PRETTY_FUNCTION__, "missing space in message");
    }
		uri=str_alloc((size_t)(end-begin+1));
		strncpy(uri, begin, (size_t)(end-begin));

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
		snprintf(insert, ALGO_STR_LEN+1, ALGO_STR);
		insert+=ALGO_STR_LEN;
		if (algo == SIPSAK_ALGO_MD5) {
			snprintf(insert, MD5_STR_LEN+1, MD5_STR);
			insert+=MD5_STR_LEN;
		}
#ifdef HAVE_OPENSSL_SHA1
		else if (algo == SIPSAK_ALGO_SHA1) {
			snprintf(insert, SHA1_STR_LEN+1, SHA1_STR);
			insert+=SHA1_STR_LEN;
		}
		else if (algo == SIPSAK_ALGO_SHA256) {
			snprintf(insert, SHA256_STR_LEN+1, SHA256_STR);
			insert+=SHA256_STR_LEN;
		}
#endif
		/* search for the realm, copy it to request and extract it for hash*/
		if ((begin=STRCASESTR(auth, REALM_STR))!=NULL) {
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
			realm=str_alloc((size_t)(end-begin+1));
			strncpy(realm, begin, (size_t)(end-begin));
		}
		else {
			fprintf(stderr, "%s\nerror: realm not found in 401 above\n", authreq);
			exit_code(3, __PRETTY_FUNCTION__, "realm not found in reply");
		}
		/* copy opaque if needed */
		if ((begin=STRCASESTR(auth, OPAQUE_STR))!=NULL) {
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
		if ((begin=STRCASESTR(auth, QOP_STR))!=NULL) {
			if (STRCASESTR(begin, QOPAUTH_STR)==NULL) {
				fprintf(stderr, "response\n%s\nerror: qop \"auth\" not supported by"
					" server\n", authreq);
				exit_code(3, __PRETTY_FUNCTION__, "qop 'auth' is not supported by server");
			}
			qop_auth=1;
		}
		/* search, copy and extract the nonce */
		if ((begin=STRCASESTR(auth, NONCE_STR))!=NULL) {
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
			nonce=str_alloc((size_t)(end-begin+1));
			strncpy(nonce, begin, (size_t)(end-begin));
		}
		else {
			fprintf(stderr, "%s\nerror: nonce not found in 401 above\n", authreq);
			exit_code(3, __PRETTY_FUNCTION__, "missing nonce in reply");
		}
		/* if qop is supported we need som additional header */
		if (qop_auth == 1) {
			unsigned int cnonce;
			snprintf(insert, QOP_STR_LEN+QOPAUTH_STR_LEN+3, "%s%s, ", QOP_STR, QOPAUTH_STR);
			insert+=strlen(insert);
			nonce_count++;
			snprintf(insert, NC_STR_LEN+11, "%s%08x, ", NC_STR, nonce_count);
			insert+=strlen(insert);
			cnonce=(unsigned int)rand();
			snprintf(insert, 12+8, "cnonce=\"%x\", ", cnonce);
			insert+=strlen(insert);
			/* hopefully 100 is enough */
			qop_tmp=str_alloc(100);
			snprintf(qop_tmp, 8+8+8, "%08x:%x:auth:", nonce_count, cnonce);
		}
		/* if no password is given we try it with empty password */
		if (!password)
			password = EMPTY_STR;

		if (algo == SIPSAK_ALGO_MD5) {
			if (authhash) {
				strncpy((char*)&ha1_hex[0], authhash, SIPSAK_HASHHEXLEN_MD5);
			}
			else {
				MD5Init(&Md5Ctx);
				MD5Update(&Md5Ctx, usern, (unsigned int)strlen(usern));
				MD5Update(&Md5Ctx, ":", 1);
				MD5Update(&Md5Ctx, realm, (unsigned int)strlen(realm));
				MD5Update(&Md5Ctx, ":", 1);
				MD5Update(&Md5Ctx, password, (unsigned int)strlen(password));
				MD5Final(&ha1[0], &Md5Ctx);
				cvt_hex(&ha1[0], &ha1_hex[0], SIPSAK_HASHLEN_MD5);
			}

			MD5Init(&Md5Ctx);
			MD5Update(&Md5Ctx, method, (unsigned int)strlen(method));
			MD5Update(&Md5Ctx, ":", 1);
			MD5Update(&Md5Ctx, uri, (unsigned int)strlen(uri));
			MD5Final(&ha2[0], &Md5Ctx);
			cvt_hex(&ha2[0], &ha2_hex[0], SIPSAK_HASHLEN_MD5);

			MD5Init(&Md5Ctx);
			MD5Update(&Md5Ctx, &ha1_hex, SIPSAK_HASHHEXLEN_MD5);
			MD5Update(&Md5Ctx, ":", 1);
			MD5Update(&Md5Ctx, nonce, (unsigned int)strlen(nonce));
			MD5Update(&Md5Ctx, ":", 1);
			if (qop_auth == 1) {
				MD5Update(&Md5Ctx, qop_tmp, (unsigned int)strlen(qop_tmp));
			}
			MD5Update(&Md5Ctx, &ha2_hex, SIPSAK_HASHHEXLEN_MD5);
			MD5Final(&resp[0], &Md5Ctx);
			cvt_hex(&resp[0], &resp_hex[0], SIPSAK_HASHLEN_MD5);
		}
#ifdef HAVE_OPENSSL_SHA1
		else if (algo == SIPSAK_ALGO_SHA1) {
			if (authhash) {
				strncpy((char*)&ha1_hex[0], authhash, SIPSAK_HASHHEXLEN_SHA1);
			}
			else {
				SHA1_Init(&Sha1Ctx);
				SHA1_Update(&Sha1Ctx, usern, (unsigned int)strlen(usern));
				SHA1_Update(&Sha1Ctx, ":", 1);
				SHA1_Update(&Sha1Ctx, realm, (unsigned int)strlen(realm));
				SHA1_Update(&Sha1Ctx, ":", 1);
				SHA1_Update(&Sha1Ctx, password, (unsigned int)strlen(password));
				SHA1_Final(&ha1[0], &Sha1Ctx);
				cvt_hex(&ha1[0], &ha1_hex[0], SIPSAK_HASHLEN_SHA1);
			}

			SHA1_Init(&Sha1Ctx);
			SHA1_Update(&Sha1Ctx, method, (unsigned int)strlen(method));
			SHA1_Update(&Sha1Ctx, ":", 1);
			SHA1_Update(&Sha1Ctx, uri, (unsigned int)strlen(uri));
			SHA1_Final(&ha2[0], &Sha1Ctx);
			cvt_hex(&ha2[0], &ha2_hex[0], SIPSAK_HASHLEN_SHA1);

			SHA1_Init(&Sha1Ctx);
			SHA1_Update(&Sha1Ctx, &ha1_hex, SIPSAK_HASHHEXLEN_SHA1);
			SHA1_Update(&Sha1Ctx, ":", 1);
			SHA1_Update(&Sha1Ctx, nonce, (unsigned int)strlen(nonce));
			SHA1_Update(&Sha1Ctx, ":", 1);
			if (qop_auth == 1) {
				SHA1_Update(&Sha1Ctx, qop_tmp, (unsigned int)strlen(qop_tmp));
			}
			SHA1_Update(&Sha1Ctx, &ha2_hex, SIPSAK_HASHHEXLEN_SHA1);
			SHA1_Final(&resp[0], &Sha1Ctx);
			cvt_hex(&resp[0], &resp_hex[0], SIPSAK_HASHLEN_SHA1);
		}
		else if (algo == SIPSAK_ALGO_SHA256) {
			if (authhash) {
				strncpy((char*)&ha1_hex[0], authhash, SIPSAK_HASHHEXLEN_SHA256);
			}
			else {
				SHA256_Init(&Sha256Ctx);
				SHA256_Update(&Sha256Ctx, usern, (unsigned int)strlen(usern));
				SHA256_Update(&Sha256Ctx, ":", 1);
				SHA256_Update(&Sha256Ctx, realm, (unsigned int)strlen(realm));
				SHA256_Update(&Sha256Ctx, ":", 1);
				SHA256_Update(&Sha256Ctx, password, (unsigned int)strlen(password));
				SHA256_Final(&ha1[0], &Sha256Ctx);
				cvt_hex(&ha1[0], &ha1_hex[0], SIPSAK_HASHLEN_SHA256);
			}

			SHA256_Init(&Sha256Ctx);
			SHA256_Update(&Sha256Ctx, method, (unsigned int)strlen(method));
			SHA256_Update(&Sha256Ctx, ":", 1);
			SHA256_Update(&Sha256Ctx, uri, (unsigned int)strlen(uri));
			SHA256_Final(&ha2[0], &Sha256Ctx);
			cvt_hex(&ha2[0], &ha2_hex[0], SIPSAK_HASHLEN_SHA256);

			SHA256_Init(&Sha256Ctx);
			SHA256_Update(&Sha256Ctx, &ha1_hex, SIPSAK_HASHHEXLEN_SHA256);
			SHA256_Update(&Sha256Ctx, ":", 1);
			SHA256_Update(&Sha256Ctx, nonce, (unsigned int)strlen(nonce));
			SHA256_Update(&Sha256Ctx, ":", 1);
			if (qop_auth == 1) {
				SHA256_Update(&Sha256Ctx, qop_tmp, (unsigned int)strlen(qop_tmp));
			}
			SHA256_Update(&Sha256Ctx, &ha2_hex, SIPSAK_HASHHEXLEN_SHA256);
			SHA256_Final(&resp[0], &Sha256Ctx);
			cvt_hex(&resp[0], &resp_hex[0], SIPSAK_HASHLEN_SHA256);
		}
#endif

		snprintf(insert, RESPONSE_STR_LEN+1, RESPONSE_STR);
		insert+=RESPONSE_STR_LEN;
		snprintf(insert, sizeof(resp_hex) + 8,"\"%s\"\r\n", &resp_hex[0]);
		insert+=strlen(insert);
		/* the auth header is complete, reinsert the rest of the request */
		strncpy(insert, backup, strlen(backup));
	}
	else {
		fprintf(stderr, "%s\nerror: couldn't find Proxy- or WWW-Authentication header"
			" in the 401 response above\n",	authreq);
		exit_code(3, __PRETTY_FUNCTION__, "missing authentication header in reply");
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

