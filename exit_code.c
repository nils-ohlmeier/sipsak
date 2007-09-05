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

#include "sipsak.h"

#if HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif
#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#include "exit_code.h"

enum exit_modes exit_mode = EM_DEFAULT;

void log_message(const char *message) {
	if ((sysl > 3) && (message != NULL)) {
#ifdef HAVE_SYSLOG
		syslog(LOG_INFO, "%s", message);
#endif
	}
}

void exit_code(int code, const char *function, const char *reason)
{
#ifdef WITH_TLS_TRANSP
	if (transport == SIP_TLS_TRANSPORT) {
# ifdef USE_GNUTLS
		if (tls_session) {
			gnutls_deinit(tls_session);
		}
		if (xcred) {
			gnutls_certificate_free_credentials(xcred);
		}
		gnutls_global_deinit();
# else /* USE_GNUTLS */
#  ifdef USE_OPENSSL
#  endif /* USE_OPENSSL */
# endif /* USE_GNUTLS */
	}
#endif /* WITH_TLS_TRANSP */

	if ((sysl > 0) && (reason != NULL)) {
#ifdef HAVE_SYSLOG
		syslog(LOG_INFO, "%s: %s", function, reason);
		closelog();
#endif
	}

	switch(exit_mode) {
		case EM_DEFAULT:	
			if (code == 4) {
				exit(0);
			} else {
				exit(code);
			}
		case EM_NAGIOS:		
			if (code == 0) {
				printf("SIP ok\n");
				exit(0);
			} else if (code == 4) {
				printf("SIP warning\n");
				exit(1);
			} else {
				printf("SIP failure\n");
				exit(2);
			}
		default:		
			fprintf(stderr, "ERROR: unknown exit code\n");
			exit(1);
	}
}
