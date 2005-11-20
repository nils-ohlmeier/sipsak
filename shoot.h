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

#ifndef SIPSAK_SHOOT_H
#define SIPSAK_SHOOT_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_NETINET_IP_H
# ifdef HAVE_NETINET_IP_ICMP_H
#  ifdef HAVE_NETINET_UDP_H
#   ifndef HAVE_CYGWIN_ICMP_H
#    define RAW_SUPPORT
#   endif
#  endif
# endif
#endif

#define LPORT_STR_LEN 6

struct sipsak_regexp {
	regex_t redexp;
	regex_t proexp;
	regex_t okexp;
	regex_t tmhexp;
	regex_t errexp;
	regex_t authexp;
	regex_t replyexp;
};

enum usteps { 
	REG_REP,
	INV_RECV,
	INV_OK_RECV,
	INV_ACK_RECV,
	MES_RECV, 
	MES_OK_RECV,
	UNREG_REP
};

int inv_trans;

void shoot(char *buff, int buff_size);

#endif
