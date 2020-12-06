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

#ifndef SIPSAK_REQUEST_H
#define SIPSAK_REQUEST_H

struct sipsak_msg_data {
  int cseq_counter;
  int lport;
  int expires_t;
  int empty_contact;
  unsigned int transport;
  char *req_buff;
  char *repl_buff;
  char *username;
  char *usern;
  char *domainname;
  char *contact_uri;
  char *con_dis;
  char *from_uri;
  char *mes_body;
  char *headers;
  char *fqdn;
};

void create_msg(int action, struct sipsak_msg_data *data);

#endif
