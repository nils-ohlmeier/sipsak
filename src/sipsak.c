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

int verbose;

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
		"  --sip-uri=SIPURI           the destination server URI in form\n"
		"                               sip:[user@]servername[:port]\n"
		"  --traceroute               activates the traceroute mode\n"
		);
	printf("  --usrloc-mode              activates the usrloc mode\n"
		"  --invite-mode              simulates a successful calls with itself\n"
		"  --message-mode             sends messages to itself\n"
		"  --contact=SIPURI           use the given URI as Contact in REGISTER\n"
		"  --appendix-begin=NUMBER    the starting number appendix to the user name (default: 0)\n"
		"  --appendix-end=NUMBER      the ending number of the appendix to the user name\n"
		"  --sleep=NUMBER             sleep number ms before sending next request\n"
		);
	printf("  --expires=NUMBER           the expires header field value (default: 15)\n"
		"  --remove-bindings=NUMBER   activates randomly removing of user bindings\n"
		"  --flood-mode               activates the flood mode\n"
		"  --random-mode              activates the random mode (dangerous)\n"
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
		"                             on failure\n"
		"  --timing=NUMBER            number of test runs and print just the timings\n"
		"  --symmetric                send and received on the same port\n"
		"  --from=SIPURI              use the given URI as From in MESSAGE\n"
		"  --timeout-factor=NUMBER    timeout multiplier for INVITE transactions\n"
		"                             on non-reliable transports (default: 64)\n"
		"  --timer-t1=NUMBER          timeout T1 in ms (default: %i)\n"
		"  --transport=STRING         specify transport to be used\n"
		"  --headers=STRING           adds additional headers to the request\n"
		"  --local-ip=STRING          specify local ip address to be used\n"
		"  --authhash=STRING          HA1 hash for authentication instead of password\n"
		"  --syslog=NUMBER            log exit message to syslog with given log level\n"
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
		"  -s SIPURI         the destination server URI in form\n"
		"                      sip:[user@]servername[:port]\n"
		"  -T                activates the traceroute mode\n"
		"  -U                activates the usrloc mode\n"
		"  -I                simulates a successful calls with itself\n"
		"  -M                sends messages to itself\n"
		);
	printf(
		"  -C SIPURI         use the given URI as Contact in REGISTER\n"
		"  -b NUMBER         the starting number appendix to the user name (default: 0)\n"
		"  -e NUMBER         the ending number of the appendix to the user name\n"
		"  -o NUMBER         sleep number ms before sending next request\n"
		"  -x NUMBER         the expires header field value (default: 15)\n"
		"  -z NUMBER         activates randomly removing of user bindings\n"
		"  -F                activates the flood mode\n"
		);
	printf(
		"  -R                activates the random mode (dangerous)\n"
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
		"  -c SIPURI         use the given URI as From in MESSAGE\n"
		"  -D NUMBER         timeout multiplier for INVITE transactions\n"
		"                    on non-reliable transports (default: 64)\n"
		"  -Z NUMBER         timeout T1 in ms (default: %i)\n"
		"  -E STRING         specify transport to be used\n"
		"  -j STRING         adds additional headers to the request\n"
		"  -J STRING         HA1 hash for authentication instead of password\n"
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
  struct sipsak_options options;

#ifdef HAVE_GETOPT_LONG
	int option_index = 0;
	static struct option l_opts[] = {
		{"help", 0, 0, 0},
		{"version", 0, 0, 'V'},
		{"filename", 1, 0, 'f'},
		{"sip-uri", 1, 0, 's'},
		{"traceroute-mode", 0, 0, 'T'},
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
  verbose = 0;
	memset(&options, 0, sizeof(struct sipsak_options));
	options.namebeg = -1;
  options.nameend = -1;
  options.maxforw = -1;
#ifdef OLDSTYLE_FQDN
	options.numeric = 0;
#else
	options.numeric = 1;
#endif
	options.via_ins = 1;
  options.redirects = 1;
  options.fix_crlf = 1;
  options.processes = 1;
	options.expires_t = USRLOC_EXP_DEF;
	options.timer_t1 = SIP_T1;
	options.timer_final = 64;
	tsp = 0;
	memset(buff, 0, BUFSIZE);

	if (argc==1) {
		print_help();
	}

	/* lots of command line switches to handle*/
#ifdef HAVE_GETOPT_LONG
	while ((c=getopt_long(argc, argv, "a:A:b:B:c:C:dD:e:E:f:Fg:GhH:iIj:J:k:K:l:Lm:MnNo:O:p:P:q:r:Rs:St:Tu:UvVwW:x:z:Z:", l_opts, &option_index)) != EOF){
#else
	while ((c=getopt(argc, argv, "a:A:b:B:c:C:dD:e:E:f:Fg:GhH:iIj:J:k:K:l:Lm:MnNo:O:p:P:q:r:Rs:St:Tu:UvVwW:x:z:Z:")) != EOF){
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
					options.ca_file=optarg;
					break;
				}
				else if (STRNCASECMP("tls-ignore-cert-failure", l_opts[option_index].name, 22) == 0) {
					options.ignore_ca_fail = 1;
					break;
				}
				else if (STRNCASECMP("tls-client-cert", l_opts[option_index].name, 14) == 0) {
					pf = fopen(optarg, "rb");
					if (!pf){
						fprintf(stderr, "error: unable to open the client cert file '%s'.\n", optarg);
						exit_code(2, __PRETTY_FUNCTION__, "failed to open client cert file");
					}
					fclose(pf);
					options.cert_file=optarg;
					break;
				}
#endif
				break;
#endif
			case 'a':
				if (strlen(optarg) == 1 && STRNCASECMP(optarg, "-", 1) == 0) {
					options.password = str_alloc(SIPSAK_MAX_PASSWD_LEN);
					printf("Please enter the password (max. length %i): ", SIPSAK_MAX_PASSWD_LEN);
					if (read_stdin(options.password, SIPSAK_MAX_PASSWD_LEN, 1) == 0) {
						exit_code(0, __PRETTY_FUNCTION__, NULL);
					}
				}
				else {
					options.password=str_alloc(strlen(optarg) + 1);
					strncpy(options.password, optarg, strlen(optarg));
				}
				break;
			case 'A':
				options.timing=str_to_int(0, optarg);
				break;
			case 'b':
				options.namebeg=str_to_int(0, optarg);
				break;
			case 'B':
				options.mes_body=str_alloc(strlen(optarg) + 1);
				strncpy(options.mes_body, optarg, strlen(optarg));
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
					options.from_uri=str_alloc(strlen(optarg)+1);
					strncpy(options.from_uri, optarg, strlen(optarg));
				}
				free(backup);
				break;
			case 'C':
				if ((strlen(optarg) == 5 && STRNCASECMP(optarg, "empty", 5) == 0) || 
					(strlen(optarg) == 4 && STRNCASECMP(optarg, "none", 4) == 0)) {
					options.empty_contact = 1;
				}
				else if ((strlen(optarg) == 1 && STRNCASECMP(optarg, "*", 1) == 0) ||
						(strlen(optarg) == 4 && STRNCASECMP(optarg, "star", 4) == 0)) {
					options.contact_uri=str_alloc(2);
					memcpy(options.contact_uri, "*", 1);
				}
				else {
					backup=str_alloc(strlen(optarg)+1);
					strncpy(backup, optarg, strlen(optarg));
					parse_uri(backup, &scheme, &user, &host, &port);
					if (scheme == NULL) {
					    fprintf(stderr, "error: REGISTER Contact URI doesn't not contain "
						   "sip:, sips:, *, or is not empty\n");
				    	exit_code(2, __PRETTY_FUNCTION__, "unsupported Contact for registration");
					}
					/*else if (user == NULL) {
						fprintf(stderr, "error: missing username in Contact uri\n");
						exit_code(2);
					}*/
					else if (host == NULL) {
						fprintf(stderr, "error: missing host in Contact URI\n");
						exit_code(2, __PRETTY_FUNCTION__, "missing host in Contact");
					}
					else {
						options.contact_uri=str_alloc(strlen(optarg)+1);
						strncpy(options.contact_uri, optarg, strlen(optarg));
					}
					free(backup);
				}
				break;
			case 'd':
				options.redirects=0;
				break;
			case 'D':
				options.timer_final = str_to_int(0, optarg);
				if (options.timer_final <= 0) {
					fprintf(stderr, "error: option D has to be above 0\n");
					exit_code(2, __PRETTY_FUNCTION__, "option D has to be above 0");
				}
				break;
			case 'e':
				options.nameend=str_to_int(0, optarg);
				break;
			case 'E':
				if (strlen(optarg) == 3 && 
					STRNCASECMP(optarg, "udp", 3) == 0) {
					options.transport = SIP_UDP_TRANSPORT;
				}
				else if (strlen(optarg) == 3 &&
						STRNCASECMP(optarg, "tcp", 3) == 0) {
					options.transport = SIP_TCP_TRANSPORT;
				}
#ifdef WITH_TLS_TRANSP
				else if (strlen(optarg) == 3 &&
						STRNCASECMP(optarg, "tls", 3) == 0) {
					options.transport = SIP_TLS_TRANSPORT;
				}
#endif
				else {
					fprintf(stderr, "error: unsupported transport '%s', supported values: udp, tcp\n", optarg);
					exit_code(2, __PRETTY_FUNCTION__, "unsupported transport");
				}
				break;
			case 'F':
				options.mode = SM_FLOOD;
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
				options.file_b=1;
				break;
			case 'g':
				options.replace_str=optarg;
				break;
			case 'G':
				options.replace_b=1;
				break;
			case 'h':
				print_help();
				break;
			case 'H':
				options.hostname=optarg;
				break;
			case 'i':
				options.via_ins=0;
				break;
			case 'I':
        if (options.mode == SM_USRLOC) {
          options.mode = SM_USRLOC_INVITE;
        } else {
				  options.mode = SM_INVITE;
        }
				break;
			case 'j':
				options.headers=optarg;
				break;
			case 'J':
				if (strlen(optarg) < SIPSAK_HASHHEXLEN_MD5) {
					fprintf(stderr, "error: authhash string is too short\n");
					exit_code(2, __PRETTY_FUNCTION__, "authhash string is too short");
				}
				options.authhash=optarg;
				break;
			case 'k':
				options.local_ip=optarg;
				break;
			case 'K':
				sysl=str_to_int(0, optarg);
#ifdef HAVE_SYSLOG_H
				openlog(PACKAGE_NAME, LOG_CONS|LOG_NOWAIT|LOG_PID, LOG_USER);
#endif
				if (sysl < LOG_ALERT || sysl > LOG_DEBUG) {
					fprintf(stderr, "error: syslog value '%s' must be between ALERT (1) and DEBUG (7)\n", optarg);
					exit_code(2, __PRETTY_FUNCTION__, "unsupported syslog value for option K");
				}
				break;
			case 'l':
				options.lport=str_to_int(0, optarg);
				break;
			case 'L':
				options.fix_crlf=0;
				break;
			case 'm':
				options.maxforw=str_to_int(0, optarg);
				break;
			case 'M':
        if (options.mode == SM_USRLOC) {
          options.mode = SM_USRLOC_MESSAGE;
        } else {
				  options.mode = SM_MESSAGE;
        }
				break;
			case 'n':
				options.numeric = 0;
				break;
			case 'N':
				exit_mode = EM_NAGIOS;
				break;
			case 'o':
				options.sleep_ms = 0;
				if (strlen(optarg) == 4 && STRNCASECMP(optarg, "rand", 4) == 0) {
					options.sleep_ms = -2;
				}
				else {
					options.sleep_ms = str_to_int(0, optarg);
				}
				break;
			case 'O':
				options.con_dis=str_alloc(strlen(optarg) + 1);
				strncpy(options.con_dis, optarg, strlen(optarg));
				break;
			case 'p':
				parse_uri(optarg, &scheme, &user, &host, &port);
				if (host == NULL) {
					fprintf(stderr, "error: missing in host in outbound proxy\n");
					exit_code(2, __PRETTY_FUNCTION__, "missing host in outbound proxy");
				}
				if (is_ip(host)) {
					options.address = getaddress(host);
					if (options.transport == 0)
						options.transport = SIP_UDP_TRANSPORT;
				}
				else {
					if (!port) {
						options.address = getsrvadr(host, &options.rport, &tsp);
						if (tsp != 0)
							options.transport = tsp;
					}
					if (!options.address) {
						options.address = getaddress(host);
						if (options.address && verbose > 1)
							printf("using A record: %s\n", host);
					}
					if (!options.address){
						fprintf(stderr, "error:unable to determine the outbound proxy "
							"address\n");
						exit_code(2, __PRETTY_FUNCTION__, "failed to resolve the outbound proxy");
					}
				}
				if (port && !options.rport) {
					options.rport = port;
				}
				options.outbound_proxy=1;
#ifdef DEBUG
				printf("address: %lu, rport: %i\n", options.address, options.rport);
#endif
				break;
			case 'P':
				options.processes=str_to_int(0, optarg);
				break;
			case 'q':
				if (options.regex) {
					/* previously allocated -- free */
					regfree(options.regex);
				} else {
					/* never tried -- allocate */
					options.regex=malloc(sizeof(regex_t));
				};
				if (!options.regex) {
					fprintf(stderr, "Error: can't allocate RE\n");
					exit_code(2, __PRETTY_FUNCTION__, "failed to allocate memory for regualr expression");
				};
				if (regcomp(options.regex, optarg, REG_EXTENDED|REG_ICASE|REG_NEWLINE )!=0) {
					fprintf(stderr, "Error: compiling RE: %s\n", optarg );
					exit_code(2, __PRETTY_FUNCTION__, "failed to compile regular expression");
				};
				break;
			case 'r':
				port=str_to_int(0, optarg);
				if (options.rport) {
					fprintf(stderr, "warning: you are overwritting the destination port with the r argument\n");
				}
				options.rport = port;
				break;
			case 'R':
				options.mode = SM_RANDTRASH;
				break;
			case 's':
				parse_uri(optarg, &scheme, &user, &host, &port);
				if (scheme == NULL) {
					fprintf(stderr, "error: missing scheme in SIP URI\n");
					exit_code(2, __PRETTY_FUNCTION__, "missing scheme in target SIP URI");
				}
				if (strlen(optarg) == 4 && STRNCASECMP(optarg,"sips",4) == 0){
					fprintf(stderr, "error: sips is not supported yet\n");
					exit_code(2, __PRETTY_FUNCTION__, "unsupported scheme SIPS in target URI");
				}
				else if (strlen(optarg) != 3 || STRNCASECMP(optarg,"sip",3) != 0){
					fprintf(stderr, "error: scheme of SIP URI has to be sip\n");
					exit_code(2, __PRETTY_FUNCTION__, "unsupported scheme in target URI");
				}
				if (user != NULL) {
					options.username = user;
				}
				if (host != NULL) {
					options.domainname = host;
				}
				else {
					fprintf(stderr, "error: missing hostname in SIP URI\n");
					exit_code(2, __PRETTY_FUNCTION__, "missing host name in target URI");
				}
				if (port && !options.rport) {
					options.rport = port;
				}
				if (is_ip(options.domainname) && !options.address) {
					options.address = getaddress(options.domainname);
					if (options.transport == 0)
						options.transport = SIP_UDP_TRANSPORT;
				}
				else {
					if (!options.rport && !options.address) {
						options.address = getsrvadr(options.domainname, &options.rport, &tsp);
						if (tsp != 0 && options.transport == 0)
							options.transport = tsp;
					}
					if (!options.address) {
						options.address = getaddress(options.domainname);
						if (options.address && verbose > 1)
							printf("using A record: %s\n", options.domainname);
					}
					if (!options.address){
						fprintf(stderr, "error:unable to determine the IP address for: %s\n", options.domainname);
						exit_code(2, __PRETTY_FUNCTION__, "failed to resolve host from target URI");
					}
				}
				if (port != 0) {
					backup = str_alloc(strlen(options.domainname)+1+6);
					snprintf(backup, strlen(options.domainname)+6, "%s:%i",
                   options.domainname, port);
					options.domainname = backup;
				}
				options.uri_b=1;
#ifdef DEBUG
				printf("address: %lu, rport: %i, username: '%s', domain: '%s'\n", options.address, options.rport, options.username, options.domainname);
#endif
				break;
			case 'S':
				fprintf(stderr, "warning: symmetric does not work with a-symmetric servers\n");
				options.symmetric=1;
				break;
			case 't':
				options.trashchar=str_to_int(0, optarg);
				break;
			case 'T':
				options.mode = SM_TRACE;
				break;
			case 'U':
        if (options.mode == SM_INVITE) {
          options.mode = SM_USRLOC_INVITE;
        } else if (options.mode == SM_MESSAGE) {
          options.mode = SM_USRLOC_MESSAGE;
        } else {
				  options.mode = SM_USRLOC;
        }
				break;
			case 'u':
				options.auth_username=str_alloc(strlen(optarg) + 1);
				strncpy(options.auth_username, optarg, strlen(optarg));
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
				options.warning_ext=1;
				break;
			case 'W':
				options.nagios_warn = str_to_int(0, optarg);
				break;
			case 'x':
				options.expires_t=str_to_int(0, optarg);
				break;
			case 'z':
				options.rand_rem=str_to_int(0, optarg);
				if (options.rand_rem < 0 || options.rand_rem > 100) {
					fprintf(stderr, "error: z option must between 0 and 100\n");
					exit_code(2, __PRETTY_FUNCTION__, "value for option z out of range");
				}
				break;
			case 'Z':
				options.timer_t1 = str_to_int(0, optarg);
				if (options.timer_t1 <= 0) {
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

	if (options.rport == 0) {
		options.rport = 5060;
	}
	if (options.rport > 65535 || options.rport <= 0) {
		fprintf(stderr, "error: invalid remote port: %i\n", options.rport);
		exit_code(2, __PRETTY_FUNCTION__, "remote port out of range");
	}
	if (options.transport == 0) {
		options.transport = SIP_UDP_TRANSPORT;
	}

	/* replace LF with CRLF if we read from a file */
	if ((options.file_b) && (options.fix_crlf)) {
		insert_cr(buff);
	}
	if (options.headers) {
		backup = str_alloc(strlen(options.headers) + 30); // FIXME
		strcpy(backup, options.headers);
		options.headers = backup;
		replace_string(options.headers, "\\n", "\r\n");
		backup = options.headers + strlen(options.headers) - 1;
		if (*backup != '\n') {
			strcpy(backup + 1, "\r\n");
		}
		if (options.file_b)
			insert_header(buff, options.headers, 1);
	}
	/* lots of conditions to check */
	if (options.mode == SM_TRACE) {
		if (!options.uri_b) {
			fprintf(stderr, "error: for trace mode a SIPURI is really needed\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing URI for trace mode");
		}
		if (options.file_b) {
			fprintf(stderr, "warning: file will be ignored for tracing.");
		}
		if (!options.username) {
			fprintf(stderr, "error: for trace mode without a file the SIPURI have to "
				"contain a username\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing username in target URI");
		}
		if (!options.via_ins){
			fprintf(stderr, "warning: Via-Line is needed for tracing. Ignoring -i\n");
			options.via_ins=1;
		}
		if (!options.warning_ext) {
			fprintf(stderr, "warning: IP extract from warning activated to be more "
				"informational\n");
			options.warning_ext=1;
		}
		if (options.maxforw==-1) {
      options.maxforw=255;
    }
	}
	else if (options.mode == SM_USRLOC ||
           options.mode == SM_USRLOC_INVITE ||
           options.mode == SM_USRLOC_MESSAGE ||
           options.mode == SM_INVITE ||
           options.mode == SM_MESSAGE) {
		if (!options.username || !options.uri_b) {
			fprintf(stderr, "error: for the USRLOC mode you have to give a SIPURI with "
				"a username\n       at least\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing target URI or username in URI");
		}
		if (options.namebeg>0 && options.nameend==-1) {
			fprintf(stderr, "error: if a starting numbers is given also an ending "
				"number have to be specified\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing end number");
		}
		if (options.mode == SM_USRLOC_INVITE && !options.lport) {
			fprintf(stderr, "warning: Do NOT use the usrloc invite mode without "
				"registering sipsak before.\n         See man page for "
				"details.\n");
			exit_code(2, __PRETTY_FUNCTION__, "don't use usrloc INVITE mode without registerting before");
		}
		if (options.contact_uri!=NULL) {
			if (options.mode == SM_USRLOC_INVITE ||
          options.mode == SM_USRLOC_MESSAGE ||
          options.mode == SM_INVITE ||
          options.mode == SM_MESSAGE) {
				fprintf(stderr, "error: Contact URI is not support for invites or "
					"messages\n");
				exit_code(2, __PRETTY_FUNCTION__, "Contact URI not supported for INVITE or MESSAGE mode");
			}
			if (options.nameend!=-1 || options.namebeg!=-1) {
				fprintf(stderr, "warning: ignoring starting or ending number if Contact"
					" is given\n");
				options.nameend = 0;
        options.namebeg = 0;
			}
			if (options.rand_rem) {
				fprintf(stderr, "warning: ignoring -z option when Contact is given\n");
				options.rand_rem=0;
			}
		}
		if (options.via_ins) {
			if (verbose > 1) {
				fprintf(stderr, "warning: Deactivated Via insertion in usrloc mode.\n         Please use option -i to suppress this warning.\n");
			}
			options.via_ins=0;
		}
		if (options.nameend==-1)
			options.nameend=0;
		if (options.namebeg==-1)
			options.namebeg=0;
	}
	else if (options.mode == SM_FLOOD) {
		if (!options.uri_b) {
			fprintf(stderr, "error: we need at least a SIP URI for flood\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing target URI");
		}
		if (options.redirects) {
			fprintf(stderr, "warning: redirects are not expected in flood. "
				"disabling\n");
			options.redirects=0;
		}
	}
	else if (options.mode == SM_RANDTRASH) {
		if (!options.uri_b) {
			fprintf(stderr, "error: need at least a SIP URI for random\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing target URI");
		}
		if (options.redirects) {
			fprintf(stderr, "warning: redirects are not expected in random. "
				"disableing\n");
			options.redirects=0;
		}
		if (verbose) {
			fprintf(stderr, "warning: random characters may destroy your terminal "
				"output\n");
		}
	}
	else if (options.mes_body) {
		if (!(options.mode == SM_MESSAGE ||
          options.mode == SM_USRLOC_MESSAGE)) {
			fprintf(stderr, "warning: to send a message mode (-M) is required. activating\n");
			options.mode = SM_MESSAGE;
		}
		if (!options.uri_b) {
			fprintf(stderr, "error: need at least a SIP URI to send a meesage\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing target SIP URI");
		}
		if (options.nameend==-1)
			options.nameend=0;
		if (options.namebeg==-1)
			options.namebeg=0;
	}
	else {
		if (!options.uri_b) {
			fprintf(stderr, "error: a SIP URI is needed at least\n");
			exit_code(2, __PRETTY_FUNCTION__, "missing target SIP URI");
		}
	}

	/* this is not a cryptographic random number generator,
	   but hey this is only a test-tool => should be satisfying*/
	srand(time(0) ^ (getpid() + (getpid() << 15)));
	
	if (options.processes > 1) {
		if (signal(SIGCHLD , sigchld_handler)  == SIG_ERR ) {
			fprintf(stderr, "error: Could not install SIGCHLD handler\n");
			exit_code(2, __PRETTY_FUNCTION__, "failed to install SIGCHLD handler");
		}
	}

	for(i = 0; i < options.processes - 1; i++) {
		if ((pid = fork()) < 0) {
			fprintf(stderr, "error: Cannot fork\n");
			exit_code(2, __PRETTY_FUNCTION__, "failed to fork");
		}
		
		if (pid == 0){
	    	/* child */
			upp = (options.nameend - options.namebeg + 1) / options.processes;
			options.namebeg = options.namebeg + upp * i;
			options.nameend = options.namebeg + upp;
			shoot(&buff[0], sizeof(buff), &options);
		} else {
			if (options.lport) {
				options.lport++;
			}
		}
		
		/* Delay execution of children so that the
		 * time of the first transmission gets spread over
		 * the retransmission interval evenly
		 */
		ts.tv_sec = 0;
		ts.tv_nsec = (float)DEFAULT_TIMEOUT / (float)options.processes * (float)1000 * (float)1000;
		nanosleep(&ts, 0);
	}

	/* here we go...*/
	if (options.processes > 1) {
		upp = (options.nameend - options.namebeg + 1) / options.processes;
		options.namebeg = options.namebeg + upp * i;
		options.nameend = options.namebeg + upp;
	}
	shoot(&buff[0], sizeof(buff), &options);

	/* normaly we won't come back here, but to satisfy the compiler */
	return 0;
}

