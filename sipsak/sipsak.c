/*
 * $Id: sipsak.c,v 1.75 2004/10/08 17:30:52 calrissian Exp $
 *
 * Copyright (C) 2002-2004 Fhg Fokus
 * Copyright (C) 2004 Nils Ohlmeier
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <regex.h>
#include <sys/wait.h>

#include "config.h"

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include "sipsak.h"
#include "helper.h"
#include "shoot.h"
#include "exit_code.h"

/* regular expression for matching received replies */
regex_t* re;


static void sigchld_handler(int signo)
{
	int chld_status;
	pid_t chld;

	while ((chld = waitpid(-1, &chld_status, WNOHANG)) > 0);
}


void print_version() {
	printf("%s %s by Nils Ohlmeier\n", PACKAGE_NAME, PACKAGE_VERSION);
	printf(" Copyright (C) 2002-2004 FhG Fokus\n");
	printf(" Copyright (C) 2004 Nils Ohlmeier\n");
	printf(" report bugs to %s\n\n", PACKAGE_BUGREPORT);
	printf(
		" shoot  : sipsak [-f FILE] [-L] -s SIPURI\n"
		" trace  : sipsak -T -s SIPURI\n"
		" usrloc : sipsak -U [-I|M] [-b NUMBER] [-e NUMBER] [-x NUMBER] [-z] -s SIPURI\n"
		" usrloc : sipsak -I|M [-b NUMBER] [-e NUMBER] -s SIPURI\n"
		" usrloc : sipsak -U [-C SIPURI] [-x NUMBER] -s SIPURI\n"
		" message: sipsak -M [-B STRING] [-O STRING] -s SIPURI\n"
		" flood  : sipsak -F [-c NUMBER] -s SIPURI\n"
		" random : sipsak -R [-t NUMBER] -s SIPURI\n\n"
		" additional parameter in every mode:\n"
		);
	printf("   [-a PASSWORD] [-d] [-i] [-H HOSTNAME] [-l PORT] [-m NUMBER] [-n] "
			"[-N]\n"
		"   [-r PORT] [-v] [-V] [-w]\n\n"
		);
}

void print_long_help() {
	print_version();
	printf(
		"  --help                     displays this help message\n"
		"  --version                  prints version string only\n"
		"  --filename=FILE            the file which contains the SIP message to send\n"
		"                               use - for standard input\n"
		"  --sip-uri=SIPURI           the destination server uri in form\n"
		"                               sip:[user@]servername[:port]\n"
		"  --traceroute               activates the traceroute mode\n"
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
		"  --remove-bindings          activates randomly removing of user bindings\n"
		"  --flood-mode               activates the flood mode\n"
		"  --cseq-max=NUMBER          the maximum CSeq number for flood mode "
			"(default: 2^31)\n"
		"  --random-mode              activates the random modues (dangerous)\n"
		"  --trash-chars=NUMBER       the maximum number of trashed character in random mode\n"
		"                               (default: request length)\n"
		);
	printf("  --local-port=PORT          the local port to use (default: any)\n"
		"  --remote-port=PORT         the remote port to use (default: 5060)\n"
		"  --outbound-proxy=HOSTNAME  request target (outbound proxy)\n"
		"  --hostname=HOSTNAME        overwrites the local hostname in all headers\n"
		"  --max-forwards=NUMBER      the value for the max-forwards header field\n"
		"  --numeric                  use IPs instead of FQDN in the Via-Line\n");
	printf("  --processes                Divide the workflow among the number of processes\n"
		"  --auth-username            Authentication username\n"
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
		"  --search                   search for a RegExp in replies and return error\n"
		"                             on failfure\n"
		"  --no-crlf                  de-activate CR (\\r) insertion\n"
		);
}

/* prints out some usage help and exits */
void print_help() {
	print_version();
	printf(
		"  -h                displays this help message\n"
		"  -V                prints version string only\n"
		"  -f FILE           the file which contains the SIP message to send\n"
		"  -s SIPURI         the destination server uri in form\n"
		"                      sip:[user@]servername[:port]\n"
		"  -T                activates the traceroute mode\n"
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
		"  -z                activates randomly removing of user bindings\n"
		"  -F                activates the flood mode\n"
		);
	printf(
		"  -c NUMBER         the maximum CSeq number for flood mode (default: 2^31)\n"
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
		"  -n                use IPs instead of FQDN in the Via-Line\n"
		"  -i                deactivate the insertion of a Via-Line\n"
		"  -a PASSWORD       password for authentication\n"
		"                      (if omitted password=username)\n"
		);
	printf(
		"  -d                ignore redirects\n"
		"  -v                each v produces more verbosity (max. 3)\n"
		"  -w                extract IP from the warning in reply\n"
		"  -g STRING         replacement for a special mark in the message\n"
		"  -G                activates replacement of variables\n"
		"  -N                returns exit codes Nagios compliant\n"
		"  -q                search for a RegExp in replies and return error\n"
		"                    on failure\n");
	printf("  -W NUMBER         return Nagios warning if retrans > number\n"
		"  -B STRING         send a message with string as body\n"
		"  -O STRING         Content-Disposition value\n"
		"  -P NUMBER         Number of processes to start\n"
		"  -u STRING         Authentication username\n"
		"  -L                de-activate CR (\\r) insertion in files\n"
		);
		exit(0);
}

int main(int argc, char *argv[])
{
	FILE	*pf;
	char	buff[BUFSIZE];
	int		length, c, i, j;
	char	*delim, *delim2;
#ifdef HAVE_GETOPT_LONG
	int option_index = 0;
	static struct option l_opts[] = {
		{"help", 0, 0, 'X'},
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
		{"remove-bindings", 0, 0, 'z'},
		{"flood-mode", 0, 0, 'F'},
		{"cseq-max", 1, 0, 'c'},
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
		{0, 0, 0, 0}
	};
#endif
	/* some initialisation to be shure */
	file_b=uri_b=trace=lport=usrloc=flood=verbose=randtrash=trashchar = 0;
	numeric=warning_ext=rand_rem=nonce_count=replace_b=invite=message = 0;
	sleep_ms=empty_contact=nagios_warn = 0;
	namebeg=nameend=maxforw= -1;
	via_ins=redirects=crlf=processes  = 1;
	username=password=replace_str=hostname=contact_uri=mes_body = NULL;
	con_dis=auth_username = NULL;
	re = NULL;
	address = 0;
	rport = 5060;
	expires_t = USRLOC_EXP_DEF;
	memset(buff, 0, BUFSIZE);
	memset(confirm, 0, BUFSIZE);
	memset(ack, 0, BUFSIZE);
	memset(fqdn, 0, FQDN_SIZE);
	memset(messusern, 0, FQDN_SIZE);
	pid_t pid;
	struct timespec ts;
	int upp;

	if (argc==1) print_help();

	/* lots of command line switches to handle*/
#ifdef HAVE_GETOPT_LONG
	while ((c=getopt_long(argc, argv, "a:B:b:c:C:de:f:Fg:GhH:iIl:Lm:MnNo:O:p:P:q:r:Rs:t:Tu:UvVwW:x:z", l_opts, &option_index)) != EOF){
#else
	while ((c=getopt(argc,argv,"a:B:b:c:C:de:f:Fg:GhH:iIl:Lm:MnNo:O:p:P:q:r:Rs:t:Tu:UvVwW:x:z")) != EOF){
#endif
		switch(c){
			case 'a':
				password=malloc(strlen(optarg));
				strncpy(password, optarg, strlen(optarg));
				*(password+strlen(optarg)) = '\0';
				break;
			case 'b':
				if ((namebeg=atoi(optarg))==-1) {
					printf("error: non-numerical appendix begin for the "
						"username\n");
					exit_code(2);
				}
				break;
			case 'B':
				mes_body=malloc(strlen(optarg));
				strncpy(mes_body, optarg, strlen(optarg));
				*(mes_body+strlen(optarg)) = '\0';
				break;
			case 'C':
				if (!strncmp(optarg, "empty", 5) || !strncmp(optarg, "none", 4)) {
					empty_contact = 1;
				}
				else if (!strncmp(optarg,"sip",3)){
					if ((delim=strchr(optarg,':'))!=NULL){
						delim++;
						if ((delim2=strchr(delim,'@'))==NULL){
							printf("error: missing '@' in Contact uri\n");
							exit_code(2);
						}
						else{
							if ((delim2-delim)==0){
								printf("error: REGISTER Contact requires a"
									" username\n");
								exit_code(2);
							}
							else{
								contact_uri=malloc(strlen(optarg)+1);
								memset(contact_uri, 0, strlen(optarg)+1);
								strncpy(contact_uri, optarg, strlen(optarg));
							}
						}
					}
					else{
						printf("error: missing ':' in REGISTER Contact uri\n");
						exit_code(2);
					}
				}
				else{
					printf("error: REGISTER Contact uri doesn't not begin "
						"with sip or empty\n");
					exit_code(2);
				}
				break;
			case 'c':
				if ((namebeg=atoi(optarg))==-1) {
					printf("error: non-numerical CSeq maximum\n");
					exit_code(2);
				}
				break;
			case 'd':
				redirects=0;
				break;
			case 'e':
				if ((nameend=atoi(optarg))==-1) {
					printf("error: non-numerical appendix end for the "
						"username\n");
					exit_code(2);
				}
				break;
			case 'F':
				flood=1;
				break;
			case 'f':
				if strncmp(optarg, "-", 1) {
					/* file is opened in binary mode so that the cr-lf is 
					   preserved */
					pf = fopen(optarg, "rb");
					if (!pf){
						printf("error: unable to open the file '%s'.\n", optarg);
						exit_code(2);
					}
					length  = fread(buff, 1, sizeof(buff), pf);
					if (length >= sizeof(buff)){
						printf("error:the file is too big. try files of less "
							"than %i bytes.\n", BUFSIZE);
						printf("      or recompile the program with bigger "
							"BUFSIZE defined.\n");
						exit_code(2);
					}
					fclose(pf);
				}
				else {
					for(i = 0; i < BUFSIZE - 1; i++) {
						j = getchar();
						if (j == EOF)
							break;
						else
							buff[i] = j;
					}
					length = i;
				}
				buff[length] = '\0';
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
			case 'l':
				lport=atoi(optarg);
				if (!lport) {
					printf("error: non-numerical local port number");
					exit_code(2);
				}
				break;
			case 'L':
				crlf=0;
				break;
			case 'm':
				maxforw=atoi(optarg);
				if (maxforw==-1) {
					printf("error: non-numerical number of max-forwards\n");
					exit_code(2);
				}
				break;
			case 'M':
				message=1;
				break;
			case 'n':
				numeric = 1;
				break;
			case 'N':
				exit_mode=EM_NAGIOS;
				break;
			case 'o':
				sleep_ms = 0;
				if (strncmp(optarg, "rand", 4)==0) {
					sleep_ms = -2;
				}
				else {
					sleep_ms = atoi(optarg);
					if (!sleep_ms) {
						printf("error: non-numerical sleep value\n");
						exit_code(2);
					}
				}
				break;
			case 'O':
				con_dis=malloc(strlen(optarg));
				strncpy(con_dis, optarg, strlen(optarg));
				*(con_dis+strlen(optarg)) = '\0';
				break;
			case 'p':
				address = getaddress(optarg);
				break;
		        case 'P':
				processes=atoi(optarg);
				if (!processes) {
					printf("error: non-numerical number of processes\n");
					exit_code(2);
				}
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
					exit_code(2);
				};
				if (regcomp(re, optarg, REG_EXTENDED|REG_ICASE|REG_NEWLINE )!=0) {
					fprintf(stderr, "Error: compiling RE: %s\n", optarg );
					exit_code(2);
				};
				break;
			case 'r':
				rport=atoi(optarg);
				if (!rport) {
					printf("error: non-numerical remote port number\n");
					exit_code(2);
				}
				break;
			case 'R':
				randtrash=1;
				break;
			case 's':
				/* we try to extract as much informationas we can from the uri*/
				if (!strncmp(optarg,"sip",3)){
					if ((delim=strchr(optarg,':'))!=NULL){
						delim++;
						if ((delim2=strchr(delim,'@'))!=NULL){
							username=malloc(delim2-delim+1);
							strncpy(username, delim, delim2-delim);
							*(username+(delim2-delim)) = '\0';
							delim2++;
							delim=delim2;
						}
						if ((delim2=strchr(delim,':'))!=NULL){
							domainname=malloc(strlen(delim)+1);
							strncpy(domainname, delim, strlen(delim));
							*(domainname+strlen(delim)) = '\0';
							*delim2 = '\0';
							delim2++;
							rport = atoi(delim2);
							if (!rport) {
								printf("error: non-numerical remote port "
									"number\n");
								exit_code(2);
							}
						}
						else {
							domainname=malloc(strlen(delim)+1);
							strncpy(domainname, delim, strlen(delim));
							*(domainname+strlen(delim)) = '\0';
						}
						if (!address)
							address = getaddress(delim);
						if (!address){
							printf("error:unable to determine the remote host "
								"address\n");
							exit_code(2);
						}
					}
					else{
						printf("error: SIPURI doesn't contain a : ?!\n");
						exit_code(2);
					}
				}
				else{
					printf("error: SIPURI doesn't not begin with sip\n");
					exit_code(2);
				}
				uri_b=1;
				break;			break;
			case 't':
				trashchar=atoi(optarg);
				if (!trashchar) {
					printf("error: non-numerical number of trashed "
						"character\n");
					exit_code(2);
				}
				break;
			case 'T':
				trace=1;
				break;
			case 'U':
				usrloc=1;
				break;
			case 'u':
				auth_username=malloc(strlen(optarg));
				strncpy(auth_username, optarg, strlen(optarg));
				*(auth_username+strlen(optarg)) = '\0';
				break;
			case 'v':
				verbose++;
				break;
			case 'V':
				printf("sipsak %s  by Nils Ohlmeier\n Copyright (C) 2002-2004"
						" FhG Fokus\n Copyright (C) 2004 Nils Ohlmeier\n", 
						SIPSAK_VERSION);
				printf(" compiled with DEFAULT_RETRYS=%i, DEFAULT_TIMEOUT=%i, FQDN_SIZE=%i",
						DEFAULT_RETRYS, DEFAULT_TIMEOUT, FQDN_SIZE);
#ifdef RAW_SUPPORT
				printf(", RAW_SUPPORT");
#endif
#ifdef HAVE_GETOPT_LONG
				printf(", LONG_OPTS");
#endif
				printf("\n");
				exit_code(0);
				break;
			case 'w':
				warning_ext=1;
				break;
			case 'W':
				nagios_warn = atoi(optarg);
				break;
			case 'x':
				expires_t=atoi(optarg);
				break;
#ifdef HAVE_GETOPT_LONG
			case 'X':
				print_long_help();
				break;
#endif
			case 'z':
				rand_rem=1;
				break;
			default:
				printf("error: unknown parameter %c\n", c);
				exit_code(2);
				break;
		}
	}

	/* replace LF with CRLF if we read from a file */
	if ((file_b) && (crlf)) {
		insert_cr(buff);
	}
	/* lots of conditions to check */
	if (trace) {
		if (usrloc || flood || randtrash) {
			printf("error: trace can't be combined with usrloc, random or "
				"flood\n");
			exit_code(2);
		}
		if (!uri_b) {
			printf("error: for trace mode a SIPURI is realy needed\n");
			exit_code(2);
		}
		if (file_b) {
			printf("warning: file will be ignored for tracing.");
		}
		if (!username) {
			printf("error: for trace mode without a file the SIPURI have to "
				"contain a username\n");
			exit_code(2);
		}
		if (!via_ins){
			printf("warning: Via-Line is needed for tracing. Ignoring -i\n");
			via_ins=1;
		}
		if (!warning_ext) {
			printf("warning: IP extract from warning activated to be more "
				"informational\n");
			warning_ext=1;
		}
		if (maxforw==-1) maxforw=255;
	}
	else if (usrloc || invite || message) {
		if (trace || flood || randtrash) {
			printf("error: usrloc can't be combined with trace, random or "
				"flood\n");
			exit_code(2);
		}
		if (!username || !uri_b) {
			printf("error: for the USRLOC mode you have to give a SIPURI with "
				"a username\n       at least\n");
			exit_code(2);
		}
		if (namebeg>0 && nameend==-1) {
			printf("error: if a starting numbers is given also an ending "
				"number have to be specified\n");
			exit_code(2);
		}
		if (invite && message) {
			printf("error: invite and message tests are XOR\n");
			exit_code(2);
		}
		if (!usrloc && invite && !lport) {
			printf("WARNING: Do NOT use the usrloc invite mode without "
				"registering sipsak before.\n         See man page for "
				"details.\n");
			exit_code(2);
		}
		if (contact_uri!=NULL) {
			if (invite || message) {
				printf("error: Contact uri is not support for invites or "
					"messages\n");
				exit_code(2);
			}
			if (nameend!=-1 || namebeg!=-1) {
				printf("warning: ignoring starting or ending number if Contact"
					" is given\n");
				nameend=namebeg=0;
			}
			if (rand_rem) {
				printf("warning: ignoring -z option when Contact is given\n");
				rand_rem=0;
			}
		}
		if (via_ins) {
			via_ins=0;
		}
		if (nameend==-1)
			nameend=0;
		if (namebeg==-1)
			namebeg=0;
	}
	else if (flood) {
		if (trace || usrloc || randtrash) {
			printf("error: flood can't be combined with trace, random or "
				"usrloc\n");
			exit_code(2);
		}
		if (!uri_b) {
			printf("error: we need at least a sip uri for flood\n");
			exit_code(2);
		}
		if (redirects) {
			printf("warning: redirects are not expected in flood. "
				"disableing\n");
			redirects=0;
		}
	}
	else if (randtrash) {
		if (trace || usrloc || flood) {
			printf("error: random can't be combined with trace, flood or "
				"usrloc\n");
			exit_code(2);
		}
		if (!uri_b) {
			printf("error: need at least a sip uri for random\n");
			exit_code(2);
		}
		if (redirects) {
			printf("warning: redirects are not expected in random. "
				"disableing\n");
			redirects=0;
		}
		if (verbose) {
			printf("warning: random characters may destroy your terminal "
				"output\n");
		}
	}
	else if (mes_body) {
		if (!message) {
			printf("warning: to send a message mode (-M) is required. activating\n");
			message=1;
		}
		if (!uri_b) {
			printf("error: need at least a sip uri to send a meesage\n");
			exit_code(2);
		}
		if (nameend==-1)
			nameend=0;
		if (namebeg==-1)
			namebeg=0;
	}
	else {
		if (!uri_b) {
			printf("error: a spi uri is needed at least\n");
			exit_code(2);
		}
	}
	/* determine our hostname */
	get_fqdn();
	
	/* this is not a cryptographic random number generator,
	   but hey this is only a test-tool => should be satisfying*/
	srand(time(0));
	
	if (processes > 1) {
		if (signal(SIGCHLD , sigchld_handler)  == SIG_ERR ) {
			printf("error: Could not install SIGCHLD handler\n");
			exit_code(2);
		}
	}

	for(i = 0; i < processes - 1; i++) {
		if ((pid = fork()) < 0) {
			printf("error: Cannot fork\n");
			exit_code(2);
		}
		
		if (pid == 0){
	    	/* child */
			upp = (nameend - namebeg + 1) / processes;
			namebeg = namebeg + upp * i;
			nameend = namebeg + upp;
			shoot(buff);
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
	shoot(buff);

	/* normaly we won't come back here, but to satisfy the compiler */
	return 0;
}

