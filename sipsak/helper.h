/*
 * $Id: helper.h,v 1.1 2003/04/04 02:12:18 calrissian Exp $
 *
 * Copyright (C) 2002-2003 Fhg Fokus
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

#include <sys/time.h>

long getaddress(char *host);

void get_fqdn();

void replace_string(char *mes, char *search, char *replacement);

void trash_random(char *message);

double deltaT(struct timeval *t1p, struct timeval *t2p);

#endif
