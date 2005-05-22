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

#ifndef SIPSAK_HELPER_H
#define SIPSAK_HELPER_H

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#else
# include <time.h>
#endif

unsigned long getaddress(char *host);

unsigned long getsrvaddress(char *host, int *port);

void get_fqdn();

void replace_string(char *mes, char *search, char *replacement);

void insert_cr(char *mes);

void swap_buffers(char *fst, char *snd);

void trash_random(char *message);

double deltaT(struct timeval *t1p, struct timeval *t2p);

#endif
