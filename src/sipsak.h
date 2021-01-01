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

#ifndef SIPSAK_H
#define SIPSAK_H

#if HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_REGEX_H
# include <regex.h>
#endif
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifndef INET_ADDRSTRLEN
# define INET_ADDRSTRLEN 16
#endif
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif

#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif
#ifndef INT_MAX
# define INT_MAX 2147483648
#endif

#ifdef HAVE_STRCASESTR
# define __USE_GNU
# define STRCASESTR(s1,s2) strcasestr(s1,s2)
#else
# define STRCASESTR(s1,s2) strstr(s1,s2)
#endif
#ifdef HAVE_STRNCASECMP
# define STRNCASECMP(s1,s2,s3) strncasecmp(s1,s2,s3)
#else
# define STRNCASECMP(s1,s2,s3) strncmp(s1,s2,s3)
#endif
#ifdef HAVE_STRING_H
# include <string.h>
#endif

#ifdef HAVE_GNUTLS
# define USE_GNUTLS
# ifndef SIPSAK_NO_TLS
#  define WITH_TLS_TRANSP 1
# endif
# include <gnutls/gnutls.h>
#else
# ifdef HAVE_OPENSSL_MD5_H
#  ifdef HAVE_CRYPTO_WITH_MD5
#   define HAVE_FULL_OPENSSL
#   define HAVE_EXTERNAL_MD5
#   define USE_OPENSSL
#   include <openssl/ssl.h>
#  endif
# endif
#endif

#ifdef HAVE_OPENSSL_SHA_H
# ifdef HAVE_CRYPTO_WITH_SHA1
#  define HAVE_OPENSSL_SHA1
# endif
#endif

#ifdef SIPSAK_PRINT_DBG
# define DEBUG 1
#endif

#ifndef REG_NOERROR
# define REG_NOERROR 0
#endif

#ifdef HAVE_SYS_PARAM_H
# ifdef MAXHOSTNAMELEN
#  define FQDN_SIZE   MAXHOSTNAMELEN + 1
# else
#  define FQDN_SIZE   100
# endif
#else
# define FQDN_SIZE   100
#endif

#ifdef HAVE_CONFIG_H
# define SIP_T1 DEFAULT_TIMEOUT
#else
# define SIP_T1 500
#endif

#define SIP_T2 8*SIP_T1

#define SIPSAK_VERSION PACKAGE_VERSION
#define UA_VAL_STR "sipsak " SIPSAK_VERSION
#define BUFSIZE		4096

#define SIPSAK_MAX_PASSWD_LEN 20

#define REQ_REG 1
#define REQ_REM 2
#define REQ_INV 3
#define REQ_MES 4
#define REQ_OPT 5
#define REQ_FLOOD 6
#define REQ_RAND 7

#define SIP_TLS_TRANSPORT 1
#define SIP_TCP_TRANSPORT 2
#define SIP_UDP_TRANSPORT 3

#define TRANSPORT_TLS_STR "TLS"
#define TRANSPORT_TCP_STR "TCP"
#define TRANSPORT_UDP_STR "UDP"
#define TRANSPORT_STR_LEN 3

#define USRLOC_EXP_DEF 15
#define FLOOD_METH "OPTIONS"

#define SIPSAK_HASHLEN_MD5 16
#define SIPSAK_HASHHEXLEN_MD5 2 * SIPSAK_HASHLEN_MD5
#ifdef HAVE_OPENSSL_SHA1
# define SIPSAK_HASHLEN_SHA1 20
# define SIPSAK_HASHHEXLEN_SHA1 2 * SIPSAK_HASHLEN_SHA1
# define SIPSAK_HASHLEN_SHA256 32
# define SIPSAK_HASHHEXLEN_SHA256 2 * SIPSAK_HASHLEN_SHA256
# define SIPSAK_HASHLEN SIPSAK_HASHLEN_SHA256
#else
# define SIPSAK_HASHLEN SIPSAK_HASHLEN_MD5
#endif
#define SIPSAK_HASHHEXLEN 2 * SIPSAK_HASHLEN

extern int verbose;

enum sipsak_modes { SM_UNDEFINED, SM_USRLOC, SM_USRLOC_INVITE, SM_USRLOC_MESSAGE, SM_INVITE, SM_MESSAGE, SM_FLOOD, SM_TRACE, SM_RANDTRASH };

struct sipsak_options {
  int timing;
  int namebeg;
  int nameend;
  int empty_contact;
  int redirects;
  int timer_final;
  int file_b;
  int replace_b;
  int via_ins;
  int lport;
  int rport;
  int fix_crlf;
  int maxforw;
  int numeric;
  int sleep_ms;
  int outbound_proxy;
  int processes;
  int randtrash;
  int trashchar;
  int uri_b;
  int symmetric;
  int warning_ext;
  int nagios_warn;
  int expires_t;
  int rand_rem;
  int timer_t1;
#ifdef WITH_TLS_TRANSP
  int ignore_ca_fail;
#endif
  enum sipsak_modes mode;
  char *password;
  char *mes_body;
  char *from_uri;
  char *contact_uri;
  char *replace_str;
  char *hostname;
  char *headers;
  char *authhash;
  char *local_ip;
  char *con_dis;
  char *username;
  char *domainname;
  char *auth_username;
#ifdef WITH_TLS_TRANSP
  char *cert_file;
  char *ca_file;
#endif
  unsigned int transport;
  unsigned long address;
  regex_t *regex;
};

#endif
