/*
 * $Id: header_f.h,v 1.1 2003/04/04 02:12:18 calrissian Exp $
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

#ifndef SIPSAK_HEADER_H
#define SIPSAK_HEADER_H

void add_via(char *mes);

void cpy_vias(char *reply, char *dest);

void cpy_to(char *reply, char *dest);

void set_maxforw(char *mes);

void uri_replace(char *mes, char *uri);

void warning_extract(char *message);

int cseq(char *message);

#endif
