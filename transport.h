/*
 * $Id:$
 *
 * Copyright (C) 2005 Nils Ohlmeier
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

#ifndef SIPSAK_TRANSPORT_H
#define SIPSAK_TRANSPORT_H

#include "sipsak.h"
#include "shoot.h"

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif /* TIME_WITH_SYS_TIME */
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

struct sipsak_sr_time {
	struct timeval sendtime;
	struct timeval recvtime;
	struct timeval firstsendt;
	struct timeval starttime;
	struct timeval delaytime;
};

struct sipsak_con_data {
	struct sockaddr_in adr;
	int csock;
	int usock;
	int dontsend;
	int dontrecv;
	int connected;
	char *buf_tmp;
	int buf_tmp_size;
};

struct sipsak_counter {
	int send_counter;
	int retrans_r_c;
	int retrans_s_c;
	int randretrys;
	int run;
};

struct sipsak_delay {
	int retryAfter;
	double big_delay;
	double small_delay;
	double all_delay;
};

void create_sockets(struct sipsak_con_data *cd);

void close_sockets(struct sipsak_con_data *cd);

void send_message(char* mes, struct sipsak_con_data *cd,
			struct sipsak_counter *sc, struct sipsak_sr_time *srt);

void check_socket_error(int socket, int size);

int check_for_message(char *recv, int size, struct sipsak_con_data *cd,
			struct sipsak_sr_time *srt, struct sipsak_counter *count,
			struct sipsak_delay *sd);

int recv_message(char *buf, int size, int inv_trans, 
			struct sipsak_delay *sd, struct sipsak_sr_time *srt,
			struct sipsak_counter *count, struct sipsak_con_data *cd,
			struct sipsak_regexp *reg);

int set_target(struct sockaddr_in *adr, unsigned long target, int port, int socket, int connected);
#endif
