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

#ifndef SIPSAK_HELPER_H
#define SIPSAK_HELPER_H

#include "sipsak.h"

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#else
# include <time.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/socket.h>
#endif

#ifdef HAVE_CARES_H
# define HAVE_SRV
#else
# ifdef HAVE_RULI_H
#  define HAVE_SRV
# endif
#endif

#ifdef HAVE_CARES_H
# define CARES_TYPE_A 1
# define CARES_TYPE_CNAME 5
# define CARES_TYPE_SRV 33
# define CARES_CLASS_C_IN 1
/* copied from ares_dns.h */
# define DNS__16BIT(p)                   (((p)[0] << 8) | (p)[1])
# define DNS_HEADER_ANCOUNT(h)           DNS__16BIT((h) + 6)
# define DNS_HEADER_NSCOUNT(h)           DNS__16BIT((h) + 8)
# define DNS_HEADER_ARCOUNT(h)           DNS__16BIT((h) + 10)
# define DNS_RR_TYPE(r)                  DNS__16BIT(r)
# define DNS_RR_CLASS(r)                 DNS__16BIT((r) + 2)
# define DNS_RR_LEN(r)                   DNS__16BIT((r) + 8)
#endif

#ifdef HAVE_SRV
# define SRV_SIP_TLS "_sip._tls"
# define SRV_SIP_TCP "_sip._tcp"
# define SRV_SIP_UDP "_sip._udp"
#endif

int is_ip(char *str);

unsigned long getaddress(char *host);

unsigned long getsrvadr(char *host, int *port, unsigned int *transport);

void get_fqdn(char *buf, int numeric, char *hostname);

void replace_string(char *mes, char *search, char *replacement);

void replace_strings(char *mes, char *strings);

void insert_cr(char *mes);

void swap_buffers(char *fst, char *snd);

void swap_ptr(char **fst, char **snd);

void trash_random(char *message);

double deltaT(struct timeval *t1p, struct timeval *t2p);

int is_number(char *number);

int str_to_int(int mode, char *num);

int read_stdin(char *buf, int size, int ret);

void *str_alloc(size_t size);

void dbg(char* format, ...);
#endif
