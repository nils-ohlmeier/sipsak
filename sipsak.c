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

/* sipsak written by nils ohlmeier (ohlmeier@fokus.fraunhofer.de).
   based up on a modifyed version of shoot.
   return codes are now: 0 for an received 200, 1 for all other
   received responses, 2 for local errors, and 3 for remote errors.
*/

/* changes by jiri@iptel.org; now messages can be really received;
   status code returned is 2 for some local errors , 0 for success
   and 1 for remote error -- ICMP/timeout; can be used to test if
   a server is alive; 1xx messages are now ignored; windows support
   dropped
*/

#include "sipsak.h"

#ifdef HAVE_UNISTD_H
# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif
# include <unistd.h>
#endif
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif
#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#include "helper.h"
#include "header_f.h"
#include "shoot.h"
#include "exit_code.h"

static void sigchld_handler(int signo)
{
	int chld_status;
	pid_t chld;

	while ((chld = waitpid(-1, &chld_status, WNOHANG)) > 0);
}


void print_version() {
	printf("%s %s by Nils Ohlmeier\n", PACKAGE_NAME, PACKAGE_VERSION);
	printf(" Copyright (C) 2002-2004 FhG Fokus\n");
	printf(" Copyright (C) 2004-2005 Nils Ohlmeier\n");
	printf(" report bugs to %s\n\n", PACKAGE_BUGREPORT);
	printf(
		" shoot  : sipsak [-f FILE] [-L] -s SIPURI\n"
		" trace  : sipsak -T -s SIPURI\n"
		" monitor: sipsak -X [-Z timeout ] -s SIPURI\n\n"
		" usrloc : sipsak -U [-I|M] [-b NUMBER] [-e NUMBER] [-x NUMBER] [-z NUMBER] -s SIPURI\n"
		" usrloc : sipsak -I|M [-b NUMBER] [-e NUMBER] -s SIPURI\n"
		" usrloc : sipsak -U [-C SIPURI] [-x NUMBER] -s SIPURI\n"
		" message: sipsak -M [-B STRING] [-O STRING] [-c SIPURI] -s SIPURI\n"
		" flood  : sipsak -F [-e NUMBER] -s SIPURI\n"
		" random : sipsak -R [-t NUMBER] -s SIPURI\n\n"
		" additional parameter in every mode:\n"
		);
	printf("   [-a PASSWORD] [-d] [-i] [-H HOSTNAME] [-l PORT] [-m NUMBER] [-n] "
			"[-N]\n"
		"   [-r PORT] [-v] [-V] [-w]\n\n"
		);
}

#ifdef HAVE_GETOPT_LONG
void print_long_help() {
	print_version();
	printf(
		"  --help                     displays this help message\n"
		"  --version                  prints version string only\n"
		"  --filename=FILE            the file which contains the SIP message to send\n"
		"                               use - for standard input\n"
		"  --no-crlf                  de-activate CR (\\r) insertion\n"
		"  --sip-uri=SIPURI           the destination server uri in form\n"
		"                               sip:[user@]servername[:port]\n"
		"  --traceroute               activates the traceroute mode\n"
		"  --monitor                  activates the monitor  mode\n"
		);
	printf("  --usrloc-mode              activates the usrloc mode\n"
		"  --invite-mode              simulates a successful calls with itself\n"
		"  --message-mode             sends messages to itself\n"
		"  --contact=SIPURI           use the given uri as Contact in REGISTER\n"
		"  --appendix-begin=NUMBER    the starting number appendix to the user name (default: 0)\n"
		"  --appendix-end=NUMBER      the ending numer of the appendix to the user name\n"
		"  --sleep=NUMBER             sleep number ms before sending next request\n"
		);
	printf("  --expires=NUMBER           the expires header field value (default: 15)\n"
		"  --remove-bindings=NUMBER   activates randomly removing of user bindings\n"
		"  --flood-mode               activates the flood mode\n"
		"  --random-mode              activates the random modues (dangerous)\n"
		"  --trash-chars=NUMBER       the maximum number of trashed character in random mode\n"
		"                               (default: request length)\n"
		);
	printf("  --local-port=PORT          the local port to use (default: any)\n"
		"  --remote-port=PORT         the remote port to use (default: 5060)\n"
		"  --outbound-proxy=HOSTNAME  request target (outbound proxy)\n"
		"  --hostname=HOSTNAME        overwrites the local hostname in all headers\n"
		"  --max-forwards=NUMBER      the value for the max-forwards header field\n"
#ifdef OLDSTYLE_FQDN
		"  --numeric                  use IP instead of FQDN in the Via-Line\n"
#else
		"  --numeric                  use FQDN instead of IP in the Via-Line\n"
#endif
);
	printf("  --processes=NUMBER         Divide the workflow among the number of processes\n"
		"  --auth-username=STRING     username for authentication\n"
		);
	printf("  --no-via                   deactivate the insertion of a Via-Line\n"
		"  --password=PASSWORD        password for authentication\n"
		"                               (if omitted password=username)\n"
		"  --ignore-redirects         ignore redirects\n"
		"  --verbose                  each v produces more verbosity (max. 3)\n"
		"  --extract-ip               extract IP from the warning in reply\n"
		"  --replace-string=STRING    replacement for a special mark in the message\n"
		"  --replace                  activates replacement of variables\n"
		);
	printf("  --nagios-code              returns exit codes Nagios compliant\n"
		"  --nagios-warn=NUMBER       return Nagios warning if retrans > number\n"
		"  --message-body=STRING      send a message with string as body\n"
		"  --disposition=STRING       Content-Disposition value\n"
		"  --search=REGEXP            search for a RegExp in replies and return error\n"
		"                             on failfure\n"
		"  --timing=NUMBER            number of test runs and print just the timings\n"
		"  --symmetric                send and received on the same port\n"
		"  --from=SIPURI              use the given uri as From in MESSAGE\n"
		"  --timeout-factor=NUMBER    timeout multiplier for INVITE transactions\n"
		"                             on non-reliable transports (default: 64)\n"
		"  --timer-t1=NUMBER          timeout T1 in ms (default: %i)\n"
		"  --transport=STRING         specify transport to be used\n"
		"  --headers=STRING           adds additional headers to the request\n"
		"  --local-ip=STRING          specify local ip address to be used\n"
		"  --authhash=STRING          ha1 hash for authentication instead of password\n"
		"  --sylog=NUMBER             log exit message to syslog with given log level\n"
		, DEFAULT_TIMEOUT
		);
#ifdef WITH_TLS_TRANSP
	printf("  --tls-ca-cert=FILE         file with the cert of the root CA\n"
		"  --tls-client-cert=FILE     file with the cert which sipsak will send\n"
		"  --tls-ignore-cert-failure  ignore failures during the TLS handshake\n"
		);
#endif
	exit_code(0, __PRETTY_FUNCTION__, NULL);
}
#endif

/* prints out some usage help and exits */
void print_help() {
	print_version();
	printf(
		"  -h                displays this help message\n"
		"  -V                prints version string only\n"
		"  -f FILE           the file which contains the SIP message to send\n"
		"                      use - for standard input\n"
		"  -L                de-activate CR (\\r) insertion in files\n"
		"  -s SIPURI         the destination server uri in form\n"
		"                      sip:[user@]servername[:port]\n"
		"  -T                activates the traceroute mode\n"
		"  -X                activates the monitor mode\n"
		"  -U                activates the usrloc mode\n"
		"  -I                simulates a successful calls with itself\n"
		"  -M                sends messages to itself\n"
		);
	printf(
		"  -C SIPURI         use the given uri as Contact in REGISTER\n"
		"  -b NUMBER         the starting number appendix to the user name (default: 0)\n"
		"  -e NUMBER         the ending numer of the appendix to the user name\n"
		"  -o NUMBER         sleep number ms before sending next request\n"
		"  -x NUMBER         the expires header field value (default: 15)\n"
		"  -z NUMBER         activates randomly removing of user bindings\n"
		"  -F                activates the flood mode\n"
		);
	printf(
		"  -R                activates the random modues (dangerous)\n"
		"  -t NUMBER         the maximum number of trashed character in random mode\n"
		"                      (default: request length)\n"
		"  -l PORT           the local port to use (default: any)\n"
		"  -r PORT           the remote port to use (default: 5060)\n"
		"  -p HOSTNAME       request target (outbound proxy)\n"
		);
	printf(
		"  -H HOSTNAME       overwrites the local hostname in all headers\n"
		"  -m NUMBER         the value for the max-forwards header field\n"
#ifdef OLDSTYLE_FQDN
		"  -n                use IP instead of FQDN in the Via-Line\n"
#else
		"  -n                use FQDN instead of IP in the Via-Line\n"
#endif
		"  -i                deactivate the insertion of a Via-Line\n"
		"  -a PASSWORD       password for authentication\n"
		"                      (if omitted password=\"\")\n"
		"  -u STRING         Authentication username\n"
		);
	printf(
		"  -d                ignore redirects\n"
		"  -v                each v produces more verbosity (max. 3)\n"
		"  -w                extract IP from the warning in reply\n"
		"  -g STRING         replacement for a special mark in the message\n"
		"  -G                activates replacement of variables\n"
		"  -N                returns exit codes Nagios compliant\n"
		"  -q STRING         search for a RegExp in replies and return error\n"
		"                    on failure\n");
	printf("  -W NUMBER         return Nagios warning if retrans > number\n"
		"  -B STRING         send a message with string as body\n"
		"  -O STRING         Content-Disposition value\n"
		"  -P NUMBER         Number of processes to start\n"
		"  -A NUMBER         number of test runs and print just timings\n"
		"  -S                use same port for receiving and sending\n"
		"  -c SIPURI         use the given uri as From in MESSAGE\n"
		"  -D NUMBER         timeout multiplier for INVITE transactions\n"
		"                    on non-reliable transports (default: 64)\n"
		"  -Z NUMBER         timeout T1 in ms (default: %i)\n"
		"  -E STRING         specify transport to be used\n"
		"  -j STRING         adds additional headers to the request\n"
		"  -J STRING         ha1 hash for authentication instead of password\n"
		"  -k STRING         specify local ip address to be used\n"
		"  -K NUMBER         log exit message to syslog with given log level\n"
		, DEFAULT_TIMEOUT
		);
		exit_code(0, __PRETTY_FUNCTION__, NULL);
}

int main(int argc, char *argv[])
{
	FILE	*pf;
	char	buff[BUFSIZE];
	int		c, i, port;
	unsigned int tsp;
	char	*scheme, *user, *host, *backup;
	pid_t 	pid;
	struct 	timespec ts;
	int 	upp;

#ifdef HAVE_GETOPT_LONG
	int option_index = 0;
	static struct option l_opts[] = {
		{"help", 0, 0, 0},
		{"version", 0, 0, 'V'},
		{"filename", 1, 0, 'f'},
		{"sip-uri", 1, 0, 's'},
		{"traceroute-mode", 0, 0, 'T'},
		{"monitor-mode", 0, 0, 'X'},
		{"usrloc-mode", 0, 0, 'U'},
		{"invite-mode", 0, 0, 'I'},
		{"message-mode", 0, 0, 'M'},
		{"contact", 1, 0, 'C'},
		{"appendix-begin", 1, 0, 'b'},
		{"appendix-end", 1, 0, 'e'},
		{"sleep", 1, 0, 'o'},
		{"expires", 1, 0, 'x'},
		{"remove-bindings", 1, 0, 'z'},
		{"flood-mode", 0, 0, 'F'},
		{"random-mode", 0, 0, 'R'},
		{"trash-chars", 1, 0, 't'},
		{"local-port", 1, 0, 'l'},
		{"remote-port", 1, 0, 'r'},
		{"outbound-proxy", 1, 0, 'p'},
		{"hostname", 1, 0, 'H'},
		{"max-fowards", 1, 0, 'm'},
		{"numeric", 0, 0, 'n'},
		{"no-via", 0, 0, 'i'},
		{"password", 1, 0, 'a'},
		{"ignore-redirects", 0, 0, 'd'},
		{"verbose", 0, 0, 'v'},
		{"extract-ip", 0, 0, 'w'},
		{"replace-string", 0, 0, 'g'},
		{"replace", 0, 0, 'G'},
		{"nagios-code", 0, 0, 'N'},
		{"nagios-warn", 1, 0, 'W'},
		{"search", 1, 0, 'q'},
		{"message-body", 1, 0, 'B'},
		{"disposition", 1, 0, 'O'},
		{"processes", 1, 0, 'P'},
		{"auth-username", 1, 0, 'u'},
		{"no-crlf", 0, 0, 'L'},
		{"timing", 1, 0, 'A'},
		{"symmetric", 0, 0, 'S'},
		{"from", 1, 0, 'c'},
		{"timeout-factor", 1, 0, 'D'},
		{"timer-t1", 1, 0, 'Z'},
		{"transport", 1, 0, 'E'},
		{"headers", 1, 0, 'j'},
		{"authhash", 1, 0, 'J'},
		{"local-ip", 1, 0, 'k'},
		{"syslog", 1, 0, 'K'},
#ifdef WITH_TLS_TRANSP
		{"tls-ca-cert", 1, 0, 0},
		{"tls-client-cert", 1, 0, 0},
		{"tls-ignore-cert-failure", 0, 0, 0},
#endif
		{0, 0, 0, 0}
	};
#endif
	/* some initialisation to be safe */
	file_b=uri_b=trace=lport=usrloc=flood=verbose=randtrash=trashchar = 0;
	warning_ext=rand_rem=nonce_count=replace_b=invite=message=sysl = 0;
	sleep_ms=empty_contact=nagios_warn=timing=outbound_proxy=symmetric = 0;
	namebeg=nameend=maxforw= -1;
	monitor_mode=0;
#ifdef OLDSTYLE_FQDN
	numeric = 0;
#else
	numeric = 1;
#endif
	via_ins=redirects=fix_crlf=processes = 1;
	username=password=replace_str=hostname=contact_uri=mes_body = NULL;
	con_dis=auth_username=from_uri=headers=authhash=local_ip = NULL;
	scheme = user = host = backup = req = rep = rec = NULL;
	re = NULL;
	address= 0;
	transport=tsp = 0;
	rport = port = 0;
	expires_t = USRLOC_EXP_DEF;
	timer_t1 = SIP_T1;
	timer_t2 = 8;
	timer_final = 64;
	memset(buff, 0, BUFSIZE);
	memset(fqdn, 0, FQDN_SIZE);
#ifdef WITH_TLS_TRANSP
	cert_file = ca_file = NULL;
	ignore_ca_fail = 0;
# ifdef USE_GNUTLS
	tls_session = NULL;
	xcred = NULL;
# else
#  ifdef USE_OPENSSL
	ctx = NULL;
	ssl = NULL;
#  endif
#endif
#endif /* WITH_TLS_TRANSP */

	if (argc==1) {
		print_help();
	}

	/* lots of command line switches to handle*/
#ifdef HAVE_GETOPT_LONG
	while ((c=getopt_long(argc, argv, OPTIONS_STRING, l_opts, &option_index)) != EOF){
#else
	while ((c=getopt(argc, argv, OPTIONS_STRING)) != EOF){
#endif
		switch(c){
#ifdef HAVE_GETOPT_LONG
			case 0:
				printf("long option %s", l_opts[option_index].name);
				if (optarg) {
					printf(" with arg %s", optarg);
				}
				printf("\n");
				if (STRNCASECMP("help", l_opts[option_index].name, 4) == 0) {
					print_long_help();
				}
#ifdef WITH_TLS_TRANSP
				else if (STRNCASECMP("tls-ca-cert", l_opts[option_index].name, 11) == 0) {
					pf = fopen(optarg, "rb");
					if (!pf){
						fprintf(stderr, "error: unable to open the CA cert file '%s'.\n", optarg);
						exit_code(2, __PRETTY_FUNCTION__, "failed to open CA cert file");
					}
					fclose(pf);
					ca_file=optarg;
					break;
				}
				else if (STRNCASECMP("tls-ignore-cert-failure", l_opts[option_index].name, 22) == 0) {
					ignore_ca_fail = 1;
					break;
				}
				else if (STRNCASECMP("tls-client-cert", l_opts[option_index].name, 14) == 0) {
					pf = fopen(optarg, "rb");
					if (!pf){
						fprintf(stderr, "error: unable to open the client cert file '%s'.\n", optarg);
						exit_code(2, __PRETTY_FUNCTION__, "failed to open client cert file");
					}
					fclose(pf);
					cert_file=optarg;
					break;
				}
#endif
				break;
#endif
			case 'a':
				if (strlen(optarg) == 1 && STRNCASECMP(optarg, "-", 1) == 0) {
					password = str_alloc(SIPSAK_MAX_PASSWD_LEN);
					printf("Please enter the password (max. length %i): ", SIPSAK_MAX_PASSWD_LEN);
					if (read_stdin(password, SIPSAK_MAX_PASSWD_LEN, 1) == 0) {
						exit_code(0, __PRETTY_FUNCTION__, NULL);
					}
				}
				else {
					password=str_alloc(strlen(optarg) + 1);
					strncpy(password, optarg, strlen(optarg));
				}
				break;
			case 'A':
				timing=str_to_int(0, optarg);
				break;
			case 'b':
				namebeg=str_to_int(0, optarg);
				break;
			case 'B':
				mes_body=str_alloc(strlen(optarg) + 1);
				strncpy(mes_body, optarg, strlen(optarg));
				break;
			case 'c':
				backup=str_alloc(strlen(optarg)+1);
				strncpy(backup, optarg, strlen(optarg));
				parse_uri(backup, &scheme, &user, &host, &port);
				if (scheme  == NULL) {
					fprintf(stderr, "error: missing scheme in From URI\n");
					exit_code(2, __PRETTY_FUNCTION__, "missing scheme in From URI");
				}
				else if (user == NULL) {
					fprintf(stderr, "error: missing username in From URI\n");
					exit_code(2, __PRETTY_FUNCTION__, "missing username in From URI");
				}
				else if (host == NULL) {
					fprintf(stderr, "error: missing host in From URI\n");
					exit_code(2, __PRETTY_FUNCTION__, "missing host in From URI");
				}
				else {
					from_uri=str_alloc(strlen(optarg)+1);
					strncpy(from_uri, optarg, strlen(optarg));
				}
				free(backup);
				break;
			case 'C':
				if ((strlen(optarg) == 5 && STRNCASECMP(optarg, "empty", 5) == 0) || 
					(strlen(optarg) == 4 && STRNCASECMP(optarg, "none", 4) == 0)) {
					empty_contact = 1;
				}
				else if ((strlen(optarg) == 1 && STRNCASECMP(optarg, "*", 1) == 0) ||
						(strlen(optarg) == 4 && STRNCASECMP(optarg, "star", 4) == 0)) {
					contact_uri=str_alloc(2);
					memcpy(contact_uri, "*", 1);
				}
				else {
					backup=str_alloc(strlen(optarg)+1);
					strncpy(backup, optarg, strlen(optarg));
					parse_uri(backup, &scheme, &user, &host, &port);
					if (scheme == NULL) {
					    fprintf(stderr, "error: REGISTER Contact uri doesn't not contain "
						   "sip:, sips:, *, or is not empty\n");
				    	exit_code(2, __PRETTY_FUNCTION__, "unsupported Contact for registration");
					}
					/*else if (user == NULL) {
						fprintf(stderr, "error: missing username in Contact uri\n");
						exit_code(2);
					}*/
					else if (host == NULL) {
						fprintf(stderr, "error: missing host in Contact uri\n");
						exit_code(2, __PRETTY_FUNCTION__, "missing host in Contact");
					}
					else {
						contact_uri=str_alloc(strlen(optarg)+1);
						strncpy(contact_uri, optarg, strlen(optarg));
					}
					free(backup);
				}
				break;
			case 'd':
				redirects=0;
				break;
			case 'D':
				timer_final = str_to_int(0, optarg);
				if (timer_final <= 0) {
					fprintf(stderr, "error: option D has to be above 0\n");
					exit_code(2, __PRETTY_FUNCTION__, "option D has to be above 0");
				}
				break;
			case 'e':
				nameend=str_to_int(0, optarg);
				break;
			case 'E':
				if (strlen(optarg) == 3 && 
					STRNCASECMP(optarg, "udp", 3) == 0) {
					transport = SIP_UDP_TRANSPORT;
				}
				else if (strlen(optarg) == 3 &&
						STRNCASECMP(optarg, "tcp", 3) == 0) {
					transport = SIP_TCP_TRANSPORT;
				}
#ifdef WITH_TLS_TRANSP
				else if (strlen(optarg) == 3 &&
						STRNCASECMP(optarg, "tls", 3) == 0) {
					transport = SIP_TLS_TRANSPORT;
				}
#endif
				else {
					fprintf(stderr, "error: unsupported transport '%s', supported values: udp, tcp\n", optarg);
					exit_code(2, __PRETTY_FUNCTION__, "unsupported transport");
				}
				break;
			case 'F':
				flood=1;
				break;
			case 'f':
				if (strlen(optarg) != 1 && STRNCASECMP(optarg, "-", 1) != 0) {
					/* file is opened in binary mode so that the cr-lf is 
					   preserved */
					pf = fopen(optarg, "rb");
					if (!pf){
						fprintf(stderr, "error: unable to open the file '%s'.\n", optarg);
						exit_code(2, __PRETTY_FUNCTION__, "failed to open file from the f option");
					}
					if (fread(buff, 1, sizeof(buff), pf) >= sizeof(buff)){
						fprintf(stderr, "error:the file is too big. try files of less "
							"than %i bytes.\n", BUFSIZE);
						fprintf(stderr, "      or recompile the program with bigger "
							"BUFSIZE defined.\n");
						exit_code(2, __PRETTY_FUNCTION__, "file to big for buffer");
					}
					fclose(pf);
				}
				else if (strlen(optarg) == 1 && STRNCASECMP(optarg, "-", 1) == 0) {
					if (read_stdin(&buff[0], sizeof(buff), 0) == 0) {
						exit_code(0, __PRETTY_FUNCTION__, NULL);
					}
				}
				else {
					fprintf(stderr, "error: unable to handle input file name: %s\n", optarg);
					exit_code(2, __PRETTY_FUNCTION__, "unsupported input file name");
				}
				file_b=1;
				break;
			case 'g':
				replace_str=optarg;
				break;
			case 'G':
				replace_b=1;
				break;
			case 'h':
				print_help();
				break;
			case 'H':
				hostname=optarg;
				break;
			case 'i':
				via_ins=0;
				break;
			case 'I':
				invite=1;
				break;
			case 'j':
				headers=optarg;
				break;
			case 'J':
				if (strlen(optarg) < SIPSAK_HASHHEXLEN_MD5) {
					fprintf(stderr, "error: authhash string is too short\n");
					exit_code(2, __PRETTY_FUNCTION__, "authhash string is too short");
				}
				authhash=optarg;
				break;
			case 'k':
				local_ip=optarg;
				break;
			case 'K':
				sysl=str_to_int(0, optarg);
				if (sysl < LOG_ALERT || sysl > LOG_DEBUG) {
					fprintf(stderr, "error: syslog value '%s' must be between ALERT (1) and DEBUG (7)\n", optarg);
					exit_code(2, __PRETTY_FUNCTION__, "unsupported syslog value for option K");
				}
#ifdef HAVE_SYSLOG_H
				openlog(PACKAGE_NAME, LOG_CONS|LOG_NOWAIT|LOG_PID, LOG_USER);
#endif
				break;
			case 'l':
				lport=str_to_int(0, optarg);
				break;
			case 'L':
				fix_crlf=0;
				break;
			case 'm':
				maxforw=str_to_int(0, optarg);
				break;
			case 'M':
				message=1;
				break;
			case 'n':
				numeric = 0;
				break;
			case 'N':
				exit_mode=EM_NAGIOS;
				break;
			case 'o':
				sleep_ms = 0;
				if (strlen(optarg) == 4 && STRNCASECMP(optarg, "rand", 4) == 0) {
					sleep_ms = -2;
				}
				else {
					sleep_ms = str_to_int(0, optarg);
				}
				break;
			case 'O':
				con_dis=str_alloc(strlen(optarg) + 1);
				strncpy(con_dis, optarg, strlen(optarg));
				break;
			case 'p':
				parse_uri(optarg, &scheme, &user, &host, &port);
				if (host == NULL) {
					fprintf(stderr, "error: missing in host in outbound proxy\n");
					exit_code(2, __PRETTY_FUNCTION__, "missing host in outbound proxy");
				}
				if (is_ip(host)) {
					address = getaddress(host);
					if (transport == 0)
						transport = SIP_UDP_TRANSPORT;
				}
				else {
					if (!port) {
						address = getsrvadr(host, &rport, &tsp);
						if (tsp != 0)
							transport = tsp;
					}
					if (!address) {
						address = getaddress(host);
						if (address && verbose > 1)
							printf("using A record: %s\n", host);
					}
					if (!address){
						fprintf(stderr, "error:unable to determine the outbound proxy "
							"address\n");
						exit_code(2, __PRETTY_FUNCTION__, "failed to resolve the outbound proxy");
					}
				}
				if (port && !rport) {
					rport = port;
				}
				outbound_proxy=1;
#ifdef DEBUG
				printf("address: %lu, rport: %i\n", address, rport);
#endif
				break;
			case 'P':
				processes=str_to_int(0, optarg);
				break;
			case 'q':
				if (re) {
					/* previously allocated -- free */
					regfree(re);
				} else {
					/* never tried -- allocate */
					re=malloc(sizeof(regex_t));
				};
				if (!re) {
					fprintf(stderr, "Error: can't allocate RE\n");
					exit_code(2, __PRETTY_FUNCTION__, "failed to allocate memory for regualr expression");
				};
				if (regcomp(re, optarg, REG_EXTENDED|REG_ICASE|REG_NEWLINE )!=0) {
					fprintf(stderr, "Error: compiling RE: %s\n", optarg );
					exit_code(2, __PRETTY_FUNCTION__, "failed to compile regular expression");
				};
				break;
			case 'r':
				port=str_to_int(0, optarg);
				if (rport) {
					fprintf(stderr, "warning: you are overwritting the destination port with the r argument\n");
				}
				rport = port;
				break;
			case 'R':
				randtrash=1;
				break;
			case 's':
				parse_uri(optarg, &scheme, &user, &host, &port);
				if (scheme == NULL) {
					fprintf(stderr, "error: missing scheme in sip uri\n");
					exit_code(2, __PRETTY_FUNCTION__, "missing scheme in target SIP URI");
				}
				if (strlen(optarg) == 4 && STRNCASECMP(optarg,"sips",4) == 0){
					fprintf(stderr, "error: sips is not supported yet\n");
					exit_code(2, __PRETTY_FUNCTION__, "unsupported scheme SIPS in target URI");
				}
				else if (strlen(optarg) != 3 || STRNCASECMP(optarg,"sip",3) != 0){
					fprintf(stderr, "error: scheme of sip uri has to be sip\n");
					exit_code(2, __PRETTY_FUNCTION__, "unsupported scheme in target URI");
				}
				if (user != NULL) {
					username = user;
				}
				if (host != NULL) {
					domainname = host;
				}
				else {
					fprintf(stderr, "error: missing hostname in sip uri\n");
					exit_code(2, __PRETTY_FUNCTION__, "missing host name in target URI");
				}
				if (port && !rport) {
					rport = port;
				}
				if (is_ip(domainname) && !address) {
					address = getaddress(domainname);
					if (transport == 0)
						transport = SIP_UDP_TRANSPORT;
				}
				else {
					if (!rport && !address) {
						address = getsrvadr(domainname, &rport, &tsp);
						if (tsp != 0 && transport == 0)
							transport = tsp;
					}
					if (!address) {
						address = getaddress(domainname);
						if (address && verbose > 1)
							printf("using A record: %s\n", domainname);
					}
					if (!address){
						fprintf(stderr, "error:unable to determine the IP address for: %s\n", domainname);
						exit_code(2, __PRETTY_FUNCTION__, "failed to resolve host from target URI");
					}
				}
				if (port != 0) {
					backup = str_alloc(strlen(domainname)+1+6);
					snprintf(backup, strlen(domainname)+6, "%s:%i", domainname, port);
					domainname = backup;
				}
				uri_b=1;
#ifdef DEBUG
				printf("address: %lu, rport: %i, username: '%s', domain: '%s'\n", address, rport, username, domainname);
#endif
				break;
			case 'S':
				fprintf(stderr, "warning: symmetric does not work with a-symmetric servers\n");
				symmetric=1;
				break;
			case 't':
				trashchar=str_to_int(0, optarg);
				break;
			case 'T':
				trace=1;
				break;
			case 'X':
				monitor_mode=1;
				break;
			case 'U':
				usrloc=1;
				break;
			case 'u':
				auth_username=str_alloc(strlen(optarg) + 1);
				strncpy(auth_username, optarg, strlen(optarg));
				break;
			case 'v':
				verbose++;
				break;
			case 'V':
				printf("sipsak %s  by Nils Ohlmeier\n Copyright (C) 2002-2004"
						" FhG Fokus\n Copyright (C) 2004-2005 Nils Ohlmeier\n", 
						SIPSAK_VERSION);
				printf(" compiled with DEFAULT_TIMEOUT=%i, FQDN_SIZE=%i",
						DEFAULT_TIMEOUT, FQDN_SIZE);
#ifdef RAW_SUPPORT
				printf(", RAW_SUPPORT");
#endif
#ifdef HAVE_GETOPT_LONG
				printf(", LONG_OPTS");
#endif
#ifdef HAVE_FULL_OPENSSL
				printf(", OPENSSL_MD5");
#else
				printf(", INTERNAL_MD5");
#endif
#ifdef HAVE_OPENSSL_SHA1
				printf(", OPENSSL_SHA1");
#endif
#ifdef WITH_TLS_TRANSP
# ifdef USE_GNUTLS
				printf(", TLS_SUPPORT(GNUTLS)");
# else
#  ifdef USE_OPENSSL
				printf(", TLS_SUPPORT(OPENSSL)");
#  endif
# endif
#endif
#ifdef HAVE_CARES_H
				printf(", SRV_SUPPORT(ARES)");
#else
# ifdef HAVE_RULI_H
				printf(", SRV_SUPPORT(RULI)");
# endif
#endif
#ifdef HAVE_STRCASESTR
				printf(", STR_CASE_INSENSITIVE");
#endif
#ifdef HAVE_STRNCASECMP
				printf(", CMP_CASE_INSENSITIVE");
#endif
#ifdef DEBUG
				printf(", DEBUG");
#endif
				printf("\n");
				exit_code(0, __PRETTY_FUNCTION__, NULL);
				break;
			case 'w':
				warning_ext=1;
				break;
			case 'W':
				nagios_warn = str_to_int(0, optarg);
				break;
			case 'x':
				expires_t=str_to_int(0, optarg);
				break;
			case 'z':
				rand_rem=str_to_int(0, optarg);
				if (rand_rem < 0 || rand_rem > 100) {
					fprintf(stderr, "error: z option must between 0 and 100\n");
					exit_code(2, __PRETTY_FUNCTION__, "value for option z out of range");
				}
				break;
			case 'Z':
				timer_t1 = str_to_int(0, optarg);
				if (timer_t1 <= 0) {
					fprintf(stderr, "error: Z option must be above 0\n");
					exit_code(2, __PRETTY_FUNCTION__, "value for option Z must be above 0");
				}
				break;
			default:
				fprintf(stderr, "error: unknown parameter '%c'\n", c);
				exit_code(2, __PRETTY_FUNCTION__, "unknown parameter");
				break;
		}
	}

	if (rport == 0) {
		rport =  5060;
	}
	if (rport > 65535 || rport <= 0) {
		fprintf(stderr, "error: invalid remote port: %i\n", rport);
		exit_code(2, __PRETTY_FUNCTION__, "remote port out of range");
	}
	if (transport == 0) {
		transport = SIP_UDP_TRANSPORT;
	}

	timer_t2 = timer_t2 * timer_t1;
	timer_final = timer_final * timer_t1;

	/* replace LF with CRLF if we read from a file */
	if ((file_b) && (fix_crlf)) {
		insert_cr(buff);
	}
	if (headers) {
		backup = str_alloc(strlen(headers) + 30); // FIXME
		strcpy(backup, headers);
		headers = backup;
		replace_string(headers, "\\n", "\r\n");
		backup = headers + strlen(headers) - 1;
		if (*backup != '\n') {
			strcpy(backup + 1, "\r\n");
		}
		if (file_b)
			insert_header(buff, headers, 1);
	}
	/* lots of conditions to check */
	if (monitor_mode) {
		if (usrloc || flood || randtrash ) {
			fprintf(stderr, "error: monitor can't be combined with usrloc, random or "
				"flood\n");
			exit_code(2, __PRETTY_FUNCTION__, "monitor mode can't be combined with other modes");
		}
		if (!uri_b) {
			fprintf(stderr, "error: for monitor mode a SIPURI is really needed\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing URI for trace mode");
		}
		if (!via_ins){
			fprintf(stderr, "warning: Via-Line is needed for tracing. Ignoring -i\n");
			via_ins=1;
		}
	}	
	if (trace) {
		if (usrloc || flood || randtrash) {
			fprintf(stderr, "error: trace can't be combined with usrloc, random or "
				"flood\n");
			exit_code(2, __PRETTY_FUNCTION__, "trace mode can't be combined with other modes");
		}
		if (!uri_b) {
			fprintf(stderr, "error: for trace mode a SIPURI is really needed\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing URI for trace mode");
		}
		if (file_b) {
			fprintf(stderr, "warning: file will be ignored for tracing.");
		}
		if (!username) {
			fprintf(stderr, "error: for trace mode without a file the SIPURI have to "
				"contain a username\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing username in target URI");
		}
		if (!via_ins){
			fprintf(stderr, "warning: Via-Line is needed for tracing. Ignoring -i\n");
			via_ins=1;
		}
		if (!warning_ext) {
			fprintf(stderr, "warning: IP extract from warning activated to be more "
				"informational\n");
			warning_ext=1;
		}
		if (maxforw==-1) maxforw=255;
	}
	else if (usrloc || invite || message) {
		if (trace || flood || randtrash) {
			fprintf(stderr, "error: usrloc can't be combined with trace, random or "
				"flood\n");
			exit_code(2, __PRETTY_FUNCTION__, "usrloc mode can't be combined with other modes");
		}
		if (!username || !uri_b) {
			fprintf(stderr, "error: for the USRLOC mode you have to give a SIPURI with "
				"a username\n       at least\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing target URI or username in URI");
		}
		if (namebeg>0 && nameend==-1) {
			fprintf(stderr, "error: if a starting numbers is given also an ending "
				"number have to be specified\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing end number");
		}
		if (invite && message) {
			fprintf(stderr, "error: invite and message tests are XOR\n");
			exit_code(2, __PRETTY_FUNCTION__, "INVITE and MESSAGE tests are XOR");
		}
		if (!usrloc && invite && !lport) {
			fprintf(stderr, "warning: Do NOT use the usrloc invite mode without "
				"registering sipsak before.\n         See man page for "
				"details.\n");
			exit_code(2, __PRETTY_FUNCTION__, "don't use usrloc INVITE mode without registerting before");
		}
		if (contact_uri!=NULL) {
			if (invite || message) {
				fprintf(stderr, "error: Contact uri is not support for invites or "
					"messages\n");
				exit_code(2, __PRETTY_FUNCTION__, "Contact URI not supported for INVITE or MESSAGE mode");
			}
			if (nameend!=-1 || namebeg!=-1) {
				fprintf(stderr, "warning: ignoring starting or ending number if Contact"
					" is given\n");
				nameend=namebeg=0;
			}
			if (rand_rem) {
				fprintf(stderr, "warning: ignoring -z option when Contact is given\n");
				rand_rem=0;
			}
		}
		if (via_ins) {
			if (verbose > 1) {
				fprintf(stderr, "warning: Deactivated Via insertion in usrloc mode.\n         Please use option -i to suppress this warning.\n");
			}
			via_ins=0;
		}
		if (nameend==-1)
			nameend=0;
		if (namebeg==-1)
			namebeg=0;
	}
	else if (flood) {
		if (trace || usrloc || randtrash) {
			fprintf(stderr, "error: flood can't be combined with trace, random or "
				"usrloc\n");
			exit_code(2, __PRETTY_FUNCTION__, "flood mode can't be combined with other modes");
		}
		if (!uri_b) {
			fprintf(stderr, "error: we need at least a sip uri for flood\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing target URI");
		}
		if (redirects) {
			fprintf(stderr, "warning: redirects are not expected in flood. "
				"disableing\n");
			redirects=0;
		}
	}
	else if (randtrash) {
		if (trace || usrloc || flood) {
			fprintf(stderr, "error: random can't be combined with trace, flood or "
				"usrloc\n");
			exit_code(2, __PRETTY_FUNCTION__, "random mode can't be combined with other modes");
		}
		if (!uri_b) {
			fprintf(stderr, "error: need at least a sip uri for random\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing target URI");
		}
		if (redirects) {
			fprintf(stderr, "warning: redirects are not expected in random. "
				"disableing\n");
			redirects=0;
		}
		if (verbose) {
			fprintf(stderr, "warning: random characters may destroy your terminal "
				"output\n");
		}
	}
	else if (mes_body) {
		if (!message) {
			fprintf(stderr, "warning: to send a message mode (-M) is required. activating\n");
			message=1;
		}
		if (!uri_b) {
			fprintf(stderr, "error: need at least a sip uri to send a meesage\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing target SIP URI");
		}
		if (nameend==-1)
			nameend=0;
		if (namebeg==-1)
			namebeg=0;
	}
	else {
		if (!uri_b) {
			fprintf(stderr, "error: a spi uri is needed at least\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing target SIP URI");
		}
	}

	switch (transport) {
#ifdef WITH_TLS_TRANSP
		case SIP_TLS_TRANSPORT:
			transport_str = TRANSPORT_TLS_STR;
			break;
#endif /* WITH_TLS_TRANSP */
		case SIP_TCP_TRANSPORT:
			transport_str = TRANSPORT_TCP_STR;
			break;
		case SIP_UDP_TRANSPORT:
			transport_str = TRANSPORT_UDP_STR;
			break;
		default:
			fprintf(stderr, "unknown transport: %u\n", transport);
			exit_code(2, __PRETTY_FUNCTION__, "unknown transport");
	}

#ifdef WITH_TLS_TRANSP
	if (transport == SIP_TLS_TRANSPORT) {
# ifdef USE_GNUTLS
		gnutls_global_init();
		//gnutls_anon_allocate_client_credentials(&anoncred);
		gnutls_certificate_allocate_credentials(&xcred);
		if (ca_file != NULL) {
			// set the trusted CA file
			gnutls_certificate_set_x509_trust_file(xcred, ca_file, GNUTLS_X509_FMT_PEM);
		}
# else
#  ifdef USE_OPENSSL
		SSL_library_init();
		SSL_load_error_strings();
#  endif
# endif
	}
#endif /* WITH_TLS_TRANSP */

	/* determine our hostname */
	get_fqdn();
	
	/* this is not a cryptographic random number generator,
	   but hey this is only a test-tool => should be satisfying*/
	srand(time(0) ^ (getpid() + (getpid() << 15)));
	
	if (processes > 1) {
		if (signal(SIGCHLD , sigchld_handler)  == SIG_ERR ) {
			fprintf(stderr, "error: Could not install SIGCHLD handler\n");
			exit_code(2, __PRETTY_FUNCTION__, "failed to install SIGCHLD handler");
		}
	}

	for(i = 0; i < processes - 1; i++) {
		if ((pid = fork()) < 0) {
			fprintf(stderr, "error: Cannot fork\n");
			exit_code(2, __PRETTY_FUNCTION__, "failed to fork");
		}
		
		if (pid == 0){
	    	/* child */
			upp = (nameend - namebeg + 1) / processes;
			namebeg = namebeg + upp * i;
			nameend = namebeg + upp;
			shoot(&buff[0], sizeof(buff));
		} else {
			if (lport) {
				lport++;
			}
		}
		
		/* Delay execution of children so that the
		 * time of the first transmission gets spread over
		 * the retransmission interval evenly
		 */
		ts.tv_sec = 0;
		ts.tv_nsec = (float)DEFAULT_TIMEOUT / (float)processes * (float)1000 * (float)1000;
		nanosleep(&ts, 0);
	}

	/* here we go...*/
	if (processes > 1) {
		upp = (nameend - namebeg + 1) / processes;
		namebeg = namebeg + upp * i;
		nameend = namebeg + upp;
	}
	shoot(&buff[0], sizeof(buff));

	/* normaly we won't come back here, but to satisfy the compiler */
	return 0;
}

