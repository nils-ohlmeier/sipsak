/*
 * $Id: sipsak.c,v 1.63 2004/06/15 10:46:52 calrissian Exp $
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

#include "sipsak.h"
#include "helper.h"
#include "shoot.h"
#include "exit_code.h"

/* prints out some usage help and exits */
void print_help() {
	printf("%s %s by Nils Ohlmeier\n", PACKAGE_NAME, PACKAGE_VERSION);
	printf(" Copyright (C) 2002-2004 FhG Fokus, 2004 Nils Ohlmeier\n");
	printf(" report bugs to %s\n\n", PACKAGE_BUGREPORT);
	printf(
		" shoot : sipsak [-f filename] -s sip:uri\n"
		" trace : sipsak -T -s sip:uri\n"
		" usrloc: sipsak -U [-I|M] [-b number] [-e number] [-x number] [-z] -s "
			"sip:uri\n"
		" usrloc: sipsak -I|M [-b number] [-e number] -s sip:uri\n"
		" usrloc: sipsak -U [-C sip:uri] [-x number] -s sip:uri\n"
		" flood : sipsak -F [-c number] -s sip:uri\n"
		" random: sipsak -R [-t number] -s sip:uri\n\n"
		" additional parameter in every mode:\n"
		"   [-a password] [-d] [-i] [-H hostname] [-l port] [-m number] [-n] "
		"[-N] [-r port]\n"
		"   [-v] [-V] [-w]\n\n"
		"   -h           displays this help message\n"
		"   -V           prints version string only\n"
		"   -f filename  the file which contains the SIP message to send\n"
		"   -s sip:uri   the destination server uri in form "
			"sip:[user@]servername[:port]\n"
		"   -T           activates the traceroute mode\n"
		"   -U           activates the usrloc mode\n"
		"   -I           simulates a successful calls with itself\n"
		"   -M           sends messages to itself\n"
		"   -C sip:uri   use the given uri as Contact in REGISTER\n"
		"   -b number    the starting number appendix to the user name in "
			"usrloc mode\n"
		"                (default: 0)\n"
		"   -e number    the ending numer of the appendix to the user name in "
			"usrloc\n"
		"                mode\n"
		"   -o number    sleep number ms before sending next request\n"
		"   -x number    the expires header field value (default: 15)\n"
		"   -z           activates randomly removing of user bindings\n"
		"   -F           activates the flood mode\n"
		"   -c number    the maximum CSeq number for flood mode "
			"(default: 2^31)\n"
		"   -R           activates the random modues (dangerous)\n"
		"   -t number    the maximum number of trashed character in random "
			"mode\n"
		"                (default: request length)\n"
		"   -l port      the local port to use (default: any)\n"
		"   -r port      the remote port to use (default: 5060)\n"
		"   -p hostname  request target (outgoing proxy)\n"
		"   -H hostname  overwrites the hostname in all headers\n"
		"                (usefull if the detection of the hostname fails)\n"
		"   -m number    the value for the max-forwards header field\n"
		"   -n           use IPs instead of fqdn in the Via-Line\n"
		"   -i           deactivate the insertion of a Via-Line\n"
		"   -a password  password for authentication\n"
		"                (if omitted password=username)\n"
		"   -d           ignore redirects\n"
		"   -v           each v's produces more verbosity (max. 3)\n"
		"   -w           extract IP from the warning in reply\n"
		"   -g string    replacement for a special mark in the message\n"
		"   -G           activates replacement of variables\n"
		"   -N           returns exit codes Nagios compliant\n"
		"   -W number    return Nagios warning if retrans > number\n"
		"   -B string    send a message with string as body\n"
		);
		exit(0);
};

int main(int argc, char *argv[])
{
	FILE	*pf;
	char	buff[BUFSIZE];
	int		length, c;
	char	*delim, *delim2;

	/* some initialisation to be shure */
	file_b=uri_b=trace=lport=usrloc=flood=verbose=randtrash=trashchar = 0;
	numeric=warning_ext=rand_rem=nonce_count=replace_b=invite=message = 0;
	sleep_ms, empty_contact, nagios_warn = 0;
	namebeg=nameend=maxforw= -1;
	via_ins=redirects = 1;
	username=password=replace_str=hostname=contact_uri=mes_body = NULL;
	address = 0;
	rport = 5060;
	expires_t = USRLOC_EXP_DEF;
	memset(buff, 0, BUFSIZE);
	memset(confirm, 0, BUFSIZE);
	memset(ack, 0, BUFSIZE);
	memset(fqdn, 0, FQDN_SIZE);
	memset(messusern, 0, FQDN_SIZE);

	if (argc==1) print_help();

	/* lots of command line switches to handle*/
	while ((c=getopt(argc,argv,"a:B:b:C:c:de:f:Fg:GhH:iIl:m:MnNo:p:r:Rs:t:TUvVwW:x:z")) != EOF){
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
				/* file is opened in binary mode so that the cr-lf is 
				   preserved */
				pf = fopen(optarg, "rb");
				if (!pf){
					puts("unable to open the file.\n");
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
					puts("error: non-numerical local port number");
					exit_code(2);
				}
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
			case 'p':
				address = getaddress(optarg);
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
						printf("error: sip:uri doesn't contain a : ?!\n");
						exit_code(2);
					}
				}
				else{
					printf("error: sip:uri doesn't not begin with sip\n");
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
			case 'v':
				verbose++;
				break;
			case 'V':
				printf("sipsak %s   by Nils Ohlmeier\n Copyright (C) 2002-2003"
						" FhG Fokus\n", SIPSAK_VERSION);
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
			case 'z':
				rand_rem=1;
				break;
			default:
				printf("error: unknown parameter %c\n", c);
				exit_code(2);
				break;
		}
	}

	/* lots of conditions to check */
	if (trace) {
		if (usrloc || flood || randtrash) {
			printf("error: trace can't be combined with usrloc, random or "
				"flood\n");
			exit_code(2);
		}
		if (!uri_b) {
			printf("error: for trace mode a sip:uri is realy needed\n");
			exit_code(2);
		}
		if (file_b) {
			printf("warning: file will be ignored for tracing.");
		}
		if (!username) {
			printf("error: for trace mode without a file the sip:uir have to "
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
			printf("error: for the USRLOC mode you have to give a sip:uri with "
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

	/* here we go...*/
	shoot(buff);

	/* normaly we won't come back here, but to satisfy the compiler */
	return 0;
}

