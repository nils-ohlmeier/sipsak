/*
 * $Id: shoot.c,v 1.9 2003/12/30 21:44:27 calrissian Exp $
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <regex.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>

#include "shoot.h"
#include "sipsak.h"
#include "request.h"
#include "auth.h"
#include "header_f.h"
#include "helper.h"

#ifndef DEFAULT_RETRYS
#define DEFAULT_RETRYS 5
#endif

#ifndef DEFAULT_TIMEOUT
#define DEFAULT_TIMEOUT 5000
#endif

/*
shot written by ashhar farhan, is not bound by any licensing at all.
you are free to use this code as you deem fit. just dont blame the author
for any problems you may have using it.
bouquets and brickbats to farhan@hotfoon.com
*/

/* this is the main function with the loops and modes */
void shoot(char *buff)
{
	struct sockaddr_in	addr;
	struct timeval	tv, sendtime, recvtime, firstsendt, delaytime;
	struct timezone tz;
	struct timespec sleep_ms_s, sleep_rem;
	struct pollfd sockerr;
	int redirected, retryAfter, nretries;
	int sock , i, len, ret, usrlocstep;
	int dontsend, cseqtmp, rand_tmp;
	int rem_rand, retrans_r_c, retrans_s_c;
	int randretrys = 0;
	int cseqcmp = 0;
	int rem_namebeg = 0;
	double big_delay, tmp_delay;
	char *contact, *foo, *bar, *lport_str;
	char *crlf = NULL;
	char reply[BUFSIZE];
	fd_set	fd;
	socklen_t slen;
	regex_t redexp, proexp, okexp, tmhexp, errexp, authexp;

	/* the vars are filled by configure */
	nretries = DEFAULT_RETRYS;
	retryAfter = DEFAULT_TIMEOUT;

	/* initalize some local vars */
	redirected = 1;
	usrlocstep=dontsend=retrans_r_c=retrans_s_c = 0;
	big_delay=tmp_delay = 0;
	delaytime.tv_sec = 0;
	delaytime.tv_usec = 0;

	/* create the socket */
	sock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock==-1) {
		perror("socket creation failed");
		exit(2);
	}

	addr.sin_family=AF_INET;
	addr.sin_addr.s_addr = htonl( INADDR_ANY );
	addr.sin_port = htons((short)lport);
	if (bind( sock, (struct sockaddr *) &addr, sizeof(addr) )==-1) {
		perror("socket binding failed");
		exit(2);
	}

	if (sleep_ms != 0) {
		if (sleep_ms == -2) {
			rand_tmp = rand();
			sleep_ms_s.tv_sec = rand_tmp / 1000;
			sleep_ms_s.tv_nsec = (rand_tmp % 1000) * 1000;
		}
		else {
			sleep_ms_s.tv_sec = sleep_ms / 1000;
			sleep_ms_s.tv_nsec = (sleep_ms % 1000) * 1000;
		}
	}

	/* for the via line we need our listening port number */
	if ((via_ins||usrloc||invite||message||replace_b) && lport==0){
		memset(&addr, 0, sizeof(addr));
		slen=sizeof(addr);
		getsockname(sock, (struct sockaddr *)&addr, &slen);
		lport=ntohs(addr.sin_port);
	}

	if (replace_b){
		replace_string(buff, "$dsthost$", domainname);
		replace_string(buff, "$srchost$", fqdn);
		lport_str=malloc(6);
		sprintf(lport_str, "%i", lport);
		replace_string(buff, "$port$", lport_str);
		free(lport_str);
		if (username)
			replace_string(buff, "$user$", username);
	}
	if (replace_str)
		replace_string(buff, "$replace$", replace_str);

	/* set all regular expression to simplfy the result code indetification */
	regcomp(&proexp, "^SIP/[0-9]\\.[0-9] 1[0-9][0-9] ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE); 
	regcomp(&okexp, "^SIP/[0-9]\\.[0-9] 200 ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE); 
	regcomp(&redexp, "^SIP/[0-9]\\.[0-9] 3[0-9][0-9] ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE);
	regcomp(&authexp, "^SIP/[0-9]\\.[0-9] 40[17] ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE);
	regcomp(&errexp, "^SIP/[0-9]\\.[0-9] 4[0-9][0-9] ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE); 
	regcomp(&tmhexp, "^SIP/[0-9]\\.[0-9] 483 ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE); 

	if (usrloc||invite||message){
		/* calculate the number of required steps and create initial mes */
		if (usrloc) {
			if (invite)
				nretries=4*(nameend-namebeg)+4;
			else if (message)
				nretries=3*(nameend-namebeg)+3;
			else
				nretries=nameend-namebeg+1;
			create_msg(buff, REQ_REG);
			usrlocstep=0;
		}
		else if (invite) {
			nretries=3*(nameend-namebeg)+3;
			create_msg(buff, REQ_INV);
			usrlocstep=1;
		}
		else {
			nretries=2*(nameend-namebeg)+2;
			create_msg(buff, REQ_MES);
			usrlocstep=4;
		}
		cseqcmp=1;
	}
	else if (trace){
		/* for trace we need some spezial initis */
		if (maxforw!=-1)
			nretries=maxforw;
		else
			nretries=255;
		namebeg=1;
		maxforw=0;
		create_msg(buff, REQ_OPT);
		add_via(buff);
	}
	else if (flood){
		/* this should be the max of an (32 bit) int without the sign */
		if (namebeg==-1) namebeg=2147483647;
		nretries=namebeg;
		namebeg=1;
		create_msg(buff, REQ_FLOOD);
	}
	else if (randtrash){
		randretrys=0;
		namebeg=1;
		create_msg(buff, REQ_RAND);
		nameend=strlen(buff);
		if (trashchar){
			if (trashchar < nameend)
				nameend=trashchar;
			else
				printf("warning: number of trashed chars to big. setting to "
					"request lenght\n");
		}
		nretries=nameend-1;
		trash_random(buff);
	}
	else {
		/* for non of the modes we also need some inits */
		if (!file_b) {
			namebeg=1;
			create_msg(buff, REQ_OPT);
		}
		retryAfter = retryAfter / 10;
		if(maxforw!=-1)
			set_maxforw(buff);
		if(via_ins)
			add_via(buff);
	}

	/* if we got a redirect this loop ensures sending to the 
	   redirected server*/
	while (redirected) {
		/* we don't want to send for ever */
		redirected=0;

		/* destination socket init here because it could be changed in a 
		   case of a redirect */
		addr.sin_addr.s_addr = address;
		addr.sin_port = htons((short)rport);
		addr.sin_family = AF_INET;
	
		/* we connect as per the RFC 2543 recommendations
		   modified from sendto/recvfrom */
		ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
		if (ret==-1) {
			perror("no connect");
			exit(2);
		}

		/* here we go for the number of nretries which strongly depends on the 
		   mode */
		for (i = 0; i <= nretries; i++)
		{
			if (trace) {
				set_maxforw(buff);
			}
			/* some initial output */
			else if ((usrloc||invite||message) && (verbose > 1) && !dontsend) {
				switch (usrlocstep) {
					case 0:
						if (nameend>0)
							printf("registering user %s%i... ", username, 
								namebeg);
						else
							printf("registering user %s... ", username);
						break;
					case 1:
						if (nameend>0)
							printf("inviting user %s%i... ", username, namebeg);
						else
							printf("invitng user %s... ", username);
						break;
					case 2:
						printf("sending invite reply... ");
						break;
					case 3:
						printf("sending invite ack... ");
						break;
					case 4:
						if (nameend>0)
							printf("sending message to %s%i... ", username,
								namebeg);
						else
							printf("sending message to %s... ", username);
						break;
					case 5:
						printf("sending message reply... ");
						break;
					case 6:
						if (nameend>0)
							printf("remove binding for %s%i...", username, 
								namebeg);
						else
							printf("remove binding for %s...", username);
						break;
				}
			}
			else if (flood && verbose) {
				printf("flooding message number %i\n", i+1);
			}
			else if (randtrash && verbose) {
				printf("message with %i randomized chars\n", i+1);
				if (verbose > 2)
					printf("request:\n%s\n", buff);
			}
			else if (!trace && !usrloc && !flood && !randtrash && (verbose > 1)
						&& !dontsend){
				printf("** request **\n%s\n", buff);
			}

			if (sleep_ms == -2) {
				rand_tmp = rand();
				sleep_ms_s.tv_sec = rand_tmp / 1000;
				sleep_ms_s.tv_nsec = (rand_tmp % 1000) * 1000;
			}

			if (! dontsend) {
				/* lets fire the request to the server and store when we did */
				ret = send(sock, buff, strlen(buff), 0);
				(void)gettimeofday(&sendtime, &tz);
				if (ret==-1) {
					printf("\n");
					perror("send failure");
					exit(2);
				}
			}
			else {
				i--;
				dontsend = 0;
			}

			/* in flood we are only interested in sending so skip the rest */
			if (!flood) {
				/* set the timeout and wait for a response */
				tv.tv_sec = retryAfter/1000;
				tv.tv_usec = (retryAfter % 1000) * 1000;

				FD_ZERO(&fd);
				FD_SET(sock, &fd); 

				ret = select(FD_SETSIZE, &fd, NULL, NULL, &tv);
				(void)gettimeofday(&recvtime, &tz);
				if (ret == 0)
				{
					/* store the time of our first send */
					if (i==0)
						memcpy(&firstsendt, &sendtime, sizeof(struct timeval));
					/* lets see if we at least received an icmp error */
					sockerr.fd=sock;
					sockerr.events=POLLERR;
					if ((poll(&sockerr, 1, 10))==1) {
						if (sockerr.revents && POLLERR) {
							recv(sock, reply, strlen(reply), 0);
							printf("\n");
							perror("send failure");
							if (randtrash) 
								printf ("last message before send failure:"
									"\n%s\n", buff);
							exit(3);
						}
					}
					/* printout that we did not received anything */
					if (trace) {
						printf("%i: timeout after %i ms\n", i, 
									retryAfter);
						i--;
					}
					else if (usrloc||invite||message) {
						printf("timeout after %i ms\n", retryAfter);
						i--;
					}
					else if (verbose) printf("** timeout after %i ms**\n", 
										retryAfter);
					if (randtrash) {
						printf("did not get a response on this request:"
							"\n%s\n", buff);
						if (i+1 < nameend) {
							if (randretrys == 2) {
								printf("sended the following message three "
									"times without getting a response:\n%s\n"
									"give up further retransmissions...\n", 
									buff);
								exit(3);
							}
							else {
								printf("resending it without additional "
									"random changes...\n\n");
								randretrys++;
							}
						}
					}
					retryAfter = retryAfter * 2;
					if (retryAfter > DEFAULT_TIMEOUT) 
						retryAfter = DEFAULT_TIMEOUT;
					retrans_s_c++;
					if (delaytime.tv_sec == 0)
						memcpy(&delaytime, &sendtime, sizeof(struct timeval));
					/* if we did not exit until here lets try another send */
					continue;
				}
				else if ( ret == -1 ) {
					perror("select error");
					exit(2);
				}
				else if (FD_ISSET(sock, &fd)) {
					/* no timeout, no error ... something has happened :-) */
				 	if (!trace && !usrloc && !invite && !message && !randtrash 
						&& (verbose > 1))
						printf ("\nmessage received:\n");
				}
				else {
					printf("\nselect returned succesfuly, nothing received\n");
					continue;
				}

				/* we are retrieving only the extend of a decent 
				   MSS = 1500 bytes */
				len = sizeof(addr);
				ret = recv(sock, reply, BUFSIZE, 0);
				if(ret > 0)
				{
					reply[ret] = 0;
					/* store the time of our first send */
					if (i==0)
						memcpy(&firstsendt, &sendtime, sizeof(struct timeval));
					/* store the biggest delay if one occured */
					if (delaytime.tv_sec != 0) {
						tmp_delay = deltaT(&delaytime, &recvtime);
						if (tmp_delay > big_delay) big_delay = tmp_delay;
						delaytime.tv_sec = 0;
						delaytime.tv_usec = 0;
					}
					/* if (usrloc) {
						switch (usrlocstep) {
							case 0: 
								cseqcmp = 3*namebeg+1;
								break;
							case 1:
							case 2:
								cseqcmp = 3*namebeg+2;
								break;
							case 3:
								cseqcmp = 3*namebeg+3;
								break;
							default:
								printf("error: unknown usrloc step on cseq"
									" compare\n");
								exit(2);
								break;
						}
					}
					else */
					/* check for old CSeq => ignore retransmission */
					if (!usrloc && !invite && !message)
						cseqcmp = namebeg;
					cseqtmp = cseq(reply);
					if ((0 < cseqtmp) && (cseqtmp < cseqcmp)) {
						if (verbose)
							printf("irgnoring retransmission\n");
						retrans_r_c++;
						dontsend = 1;
						continue;
					}
					/* lets see if received a redirect */
					if (redirects && regexec(&redexp, reply, 0, 0, 0)==0) {
						printf("** received redirect ");
						if (warning_ext) {
							printf("from ");
							warning_extract(reply);
							printf("\n");
						}
						else printf("\n");
						/* we'll try to handle 301 and 302 here, other 3xx 
						   are to complex */
						regcomp(&redexp, "^SIP/[0-9]\\.[0-9] 30[1-2] ", 
							REG_EXTENDED|REG_NOSUB|REG_ICASE);
						if (regexec(&redexp, reply, 0, 0, 0)==0) {
							/* try to find the contact in the redirect */
							if ((foo=strstr(reply, "Contact"))==NULL &&
								(foo=strstr(reply, "\nm:"))==NULL ) {
								printf("error: cannot find Contact in this "
									"redirect:\n%s\n", reply);
								exit(3);
							}
							crlf=strchr(foo, '\n');
							if ((contact=strchr(foo, '\r'))!=NULL 
							&& contact<crlf)
								crlf=contact;
							bar=malloc(crlf-foo+1);
							strncpy(bar, foo, crlf-foo);
							*(bar+(crlf-foo))='\0';
							if ((contact=strstr(bar, "sip"))==NULL) {
								printf("error: cannot find sip in the Contact "
									"of this redirect:\n%s\n", reply);
								exit(3);
							}
							if ((foo=strchr(contact, ';'))!=NULL)
								*foo='\0';
							if ((foo=strchr(contact, '>'))!=NULL)
								*foo='\0';
							if ((crlf=strchr(contact,':'))!=NULL){
								crlf++;
								/* extract the needed information*/
								if ((foo=strchr(crlf,':'))!=NULL){
									*foo='\0';
									foo++;
									rport = atoi(foo);
									if (!rport) {
										printf("error: cannot handle the port "
											"in the uri in Contact:\n%s\n", 
											reply);
										exit(3);
									}
								}
								/* correct our request */
								uri_replace(buff, contact);
								if ((foo=strchr(contact,'@'))!=NULL){
									foo++;
									crlf=foo;
								}
								/* get the new destination IP*/
								address = getaddress(crlf);
								if (!address){
									printf("error: cannot determine host "
										"address from Contact of redirect:"
										"\%s\n", reply);
									exit(2);
								}
							}
							else{
								printf("error: missing : in Contact of this "
									"redirect:\n%s\n", reply);
								exit(3);
							}
							free(bar);
							memset(&addr, 0, sizeof(addr));
							redirected=1;
							i=nretries;
						}
						else {
							printf("error: cannot handle this redirect:"
								"\n%s\n", reply);
							exit(2);
						}
					} /* if redircts... */
					else if (regexec(&authexp, reply, 0, 0, 0)==0) {
						if (!username) {
							printf("error: received 401 but cannot "
								"authentication without a username\n");
							exit(2);
						}
						/* prevents a strange error */
						regcomp(&authexp, "^SIP/[0-9]\\.[0-9] 401 ", 
							REG_EXTENDED|REG_NOSUB|REG_ICASE);
						insert_auth(buff, reply);
						i--;
					} /* if auth...*/
					else if (trace) {
						if (regexec(&tmhexp, reply, 0, 0, 0)==0) {
							/* we received 483 to many hops */
							printf("%i: ", i);
							if (verbose > 2) {
								printf("(%.3f ms)\n%s\n", 
									deltaT(&sendtime, &recvtime), reply);
							}
							else {
								warning_extract(reply);
								crlf=strchr(reply, '\n');
								*crlf='\0';
								printf("(%.3f ms) %s\n", 
									deltaT(&sendtime, &recvtime), reply);
							}
							namebeg++;
							cseqcmp++;
							maxforw++;
							create_msg(buff, REQ_OPT);
							add_via(buff);
							continue;
						}
						else if (regexec(&proexp, reply, 0, 0, 0)==0) {
							/* we received a provisional response */
							printf("%i: ", i);
							if (verbose > 2) {
								printf("(%.3f ms)\n%s\n", 
									deltaT(&sendtime, &recvtime), reply);
							}
							else {
								warning_extract(reply);
								crlf=strchr(reply, '\n');
								*crlf='\0';
								printf("(%.3f ms) %s\n", 
									deltaT(&sendtime, &recvtime), reply);
							}
							dontsend=1;
							continue;
						}
						else {
							/* anything else then 483 or provisional will
							   be treated as final */
							if (maxforw==i) printf("%i: ", i);
							else printf("\t");
							warning_extract(reply);
							crlf=strchr(reply,'\n');
							*crlf='\0';
							crlf++;
							contact=strstr(crlf, "Contact");
							if (!contact)
								contact=strstr(crlf, "\nm:");
							printf("(%.3f ms) %s\n", 
								deltaT(&sendtime, &recvtime), reply);
							if (contact){
								crlf=strchr(contact,'\n');
								*crlf='\0';
								printf("\t%s\n", contact);
							}
							else {
								printf("\twithout Contact header\n");
							}
							if (regexec(&okexp, reply, 0, 0, 0)==0)
								exit(0);
							else
								exit(1);
						}
					} /* if trace ... */
					else if (usrloc||invite||message) {
						switch (usrlocstep) {
							case 0:
								/* we have sent a register and look 
								   at the response now */
								if (regexec(&proexp, reply, 0, 0, 0)==0) {
									if (verbose > 2)
										printf("\nignoring provisinal "
											"response\n");
									dontsend = 1;
									break;
								}
								else if (regexec(&okexp, reply, 0, 0, 0)==0) {
									if (verbose > 1)
										printf ("\tOK\n");
									if (verbose > 2)
										printf("\n%s\n", reply);
									//strcpy(buff, confirm);
									//usrlocstep=1;
								}
								else {
									printf("\nreceived:\n%s\nerror: didn't "
										"received '200 OK' on register (see "
										"above). aborting\n", reply);
									exit(1);
								}
								if (!invite && !message) {
									if (namebeg==nameend) {
										printf("\nAll usrloc tests completed "
											"successful.\nreceived last message"
											" %.3f ms after first request (test"
											" duration).\n", deltaT(&firstsendt,
											 &recvtime));
										if (big_delay)
											printf("biggest delay between "
												"request and response was %.3f"
												" ms\n", big_delay);
										if (retrans_r_c)
											printf("%i retransmission(s) "
												"received from server.\n", 
												retrans_r_c);
										if (retrans_s_c)
											printf("%i time(s) the timeout of "
												"%i ms exceeded and request was"
												" retransmitted.\n", 
												retrans_s_c, retryAfter);
										exit(0);
									}
									/* lets see if we deceid to remove a 
									   binding (case 6)*/
									rem_rand=rand();
									if (!rand_rem ||
										((float)rem_rand/RAND_MAX) 
											> USRLOC_REMOVE_PERCENT) {
										namebeg++;
										create_msg(buff, REQ_REG);
										cseqcmp++;
									}
									else {
										/* to prevent only removing of low
										   user numbers new random number*/
										rem_rand = rand();
										rem_namebeg = namebeg;
										namebeg = ((float)rem_rand/RAND_MAX)
													* namebeg;
										cseqcmp++;
										trashchar=cseqcmp;
										create_msg(buff, REQ_REM);
										usrlocstep=6;
									}
								}
								else if (invite) {
									create_msg(buff, REQ_INV);
									cseqcmp++;
									usrlocstep=1;
								}
								else if (message) {
									create_msg(buff, REQ_MES);
									cseqcmp++;
									usrlocstep=4;
								}
								if (sleep_ms != 0) {
									nanosleep(&sleep_ms_s, &sleep_rem);
								}
								break;
							case 1:
								/* see if we received our invite */
								if (strncmp(reply, SIP100_STR, 
									SIP100_STR_LEN)==0) {
									if (verbose > 2)
										printf("ignoring 100.. ");
									dontsend=1;
									continue;
								}
								if (!strncmp(reply, messusern, 
									strlen(messusern))) {
									if (verbose > 1)
										printf("\t\treceived invite\n");
									if (verbose > 2)
										printf("\n%s\n", reply);
									cpy_vias(reply, confirm);
									cpy_to(reply, confirm);
									strcpy(buff, confirm);
									usrlocstep=2;
								}
								else {
									printf("\nreceived:\n%s\nerror: did not "
										"received the INVITE that was sent "
										"(see above). aborting\n", reply);
									exit(1);
								}
								break;
							case 2:
								/* did we received our ok ? */
								if (strncmp(reply, INV_STR, INV_STR_LEN)==0) {
									if (verbose)
										printf("ignoring INVITE "
											"retransmission\n");
									retrans_r_c++;
									dontsend=1;
									continue;
								}
								if (regexec(&okexp, reply, 0, 0, 0)==0) {
									if (verbose > 1)
										printf("\treply received\n");
									if (verbose > 2)
										printf("\n%s\n", reply);
									cpy_to(reply, ack);
									strcpy(buff, ack);
									usrlocstep=3;
								}
								else {
									printf("\nreceived:\n%s\nerror: did not "
										"received the '200 OK' that was sent "
										"as the reply on the INVITE (see "
										"above). aborting\n", reply);
									exit(1);
								}
								break;
							case 3:
								/* did we received our ack */
								if (nameend > 0)
									sprintf(messusern, "%s sip:%s%i", ACK_STR, 
										username, namebeg);
								else
									sprintf(messusern, "%s sip:%s", ACK_STR, 
										username);
								if (strncmp(reply, messusern, 
									strlen(messusern))==0) {
									if (verbose > 1)
										printf("\t\tack received\n");
									if (verbose > 2)
										printf("\n%s\n", reply);
									if (verbose && nameend>0)
										printf("usrloc for %s%i completed "
											"successful\n", username, namebeg);
									else if (verbose)
										printf("usrloc for %s completed "
											"successful\n", username);
									if (namebeg==nameend) {
										printf("\nAll usrloc tests completed "
											"successful.\nreceived last message"
											" %.3f ms after first request (test"
											" duration).\n", deltaT(&firstsendt,
											 &recvtime));
										if (big_delay)
											printf("biggest delay between "
												"request and response was %.3f"
												" ms\n", big_delay);
										if (retrans_r_c)
											printf("%i retransmission(s) "
												"received from server.\n", 
												retrans_r_c);
										if (retrans_s_c)
											printf("%i time(s) the timeout of "
												"%i ms exceeded and request was"
												" retransmitted.\n", 
												retrans_s_c, retryAfter);
										exit(0);
									}
									if (usrloc) {
										/* lets see if we deceid to remove a 
										   binding (case 6)*/
										rem_rand=rand();
										if (!rand_rem ||
											((float)rem_rand/RAND_MAX) 
												> USRLOC_REMOVE_PERCENT) {
											namebeg++;
											create_msg(buff, REQ_REG);
											cseqcmp=cseqcmp+2;
											usrlocstep=0;
										}
										else {
											/* to prevent only removing of low
											   user numbers new random number*/
											rem_rand = rand();
											rem_namebeg = namebeg;
											namebeg = ((float)rem_rand/RAND_MAX)
														* namebeg;
											cseqcmp++;
											trashchar=cseqcmp;
											create_msg(buff, REQ_REM);
											usrlocstep=6;
										}
									}
									else {
										namebeg++;
										create_msg(buff, REQ_INV);
										cseqcmp=cseqcmp+3;
										usrlocstep=1;
									}
								}
								else {
									printf("\nreceived:\n%s\nerror: did not "
										"received the 'ACK' that was sent "
										"as the reply on the '200 OK' (see "
										"above). aborting\n", reply);
									exit(1);
								}
								if (sleep_ms != 0)
									nanosleep(&sleep_ms_s, &sleep_rem);
								break;
							case 4:
								/* we sent the message and look if its 
								   forwarded to us */
								if (!strncmp(reply, messusern, 
									strlen(messusern))) {
									if (verbose > 1) {
										crlf=strstr(reply, "\r\n\r\n");
										crlf=crlf+4;
										printf("  received message\n  "
											"'%s'\n", crlf);
									}
									if (verbose > 2)
										printf("\n%s\n", reply);
									cpy_vias(reply, confirm);
									cpy_to(reply, confirm);
									strcpy(buff, confirm);
									usrlocstep=5;
								}
								else {
									printf("\nreceived:\n%s\nerror: did not "
										"received the 'MESSAGE' that was sent "
										"(see above). aborting\n", reply);
									exit(1);
								}
								break;
							case 5:
								/* we sent our reply on the message and
								   look if this is also forwarded to us */
								if (strncmp(reply, MES_STR, MES_STR_LEN)==0) {
									if (verbose)
										printf("ignoring MESSAGE "
											"retransmission\n");
									retrans_r_c++;
									dontsend=1;
									continue;
								}
								if (regexec(&okexp, reply, 0, 0, 0)==0) {
									if (verbose > 1)
										printf("  reply received\n\n");
									else if (verbose && nameend>0)
										printf("usrloc for %s%i completed "
											"successful\n", username, namebeg);
									else if (verbose)
										printf("usrloc for %s completed "
											"successful\n", username);
									if (namebeg==nameend) {
										printf("\nAll usrloc tests completed "
											"successful.\nreceived last message"
											" %.3f ms after first request (test"
											" duration).\n", deltaT(&firstsendt,
											 &recvtime));
										if (big_delay)
											printf("biggest delay between "
												"request and response was %.3f"
												" ms\n", big_delay);
										if (retrans_r_c)
											printf("%i retransmission(s) "
												"received from server.\n", 
												retrans_r_c);
										if (retrans_s_c)
											printf("%i time(s) the timeout of "
												"%i ms exceeded and request was"
												" retransmitted.\n", 
												retrans_s_c, retryAfter);
										exit(0);
									}
									if (usrloc) {
										/* lets see if we deceid to remove a 
										   binding (case 6)*/
										rem_rand=rand();
										if (!rand_rem ||
											((float)rem_rand/RAND_MAX) 
												> USRLOC_REMOVE_PERCENT) {
											namebeg++;
											create_msg(buff, REQ_REG);
											cseqcmp=cseqcmp+2;
											usrlocstep=0;
										}
										else {
											/* to prevent only removing of low
											   user numbers new random number*/
											rem_rand = rand();
											rem_namebeg = namebeg;
											namebeg = ((float)rem_rand/RAND_MAX)
														* namebeg;
											cseqcmp++;
											trashchar=cseqcmp;
											create_msg(buff, REQ_REM);
											usrlocstep=6;
										}
									}
									else {
										namebeg++;
										create_msg(buff, REQ_MES);
										cseqcmp=cseqcmp+3;
										usrlocstep=4;
									}
								}
								else {
									printf("\nreceived:\n%s\nerror: did not "
										"received the '200 OK' that was sent "
										"as the reply on the MESSAGE (see "
										"above). aborting\n", reply);
									exit(1);
								}
								if (sleep_ms != 0)
									nanosleep(&sleep_ms_s, &sleep_rem);
								break;
							case 6:
								if (strncmp(reply, MES_STR, MES_STR_LEN)==0) {
									if (verbose)
										printf("ignoring MESSAGE "
											"retransmission\n");
									retrans_r_c++;
									dontsend=1;
									continue;
								}
								if (regexec(&okexp, reply, 0, 0, 0)==0) {
									if (verbose > 1) printf("   OK\n\n");
									else if (verbose && nameend>0)
										printf("Binding removal for %s%i "
											"successful\n", username, namebeg);
									else if (verbose)
										printf("Binding removal for %s "
											"successful\n", username);
									namebeg = rem_namebeg;
									namebeg++;
									create_msg(buff, REQ_REG);
									cseqcmp++;
									usrlocstep = 0;
									i--;
								}
								else {
									printf("\nreceived:\n%s\nerror: did not "
										"received the expected 200 on the "
										"remove bindings request for %s%i (see"
										" above). aborting\n", reply, username, 
										namebeg);
									exit(1);
								}
								if (sleep_ms != 0)
									nanosleep(&sleep_ms_s, &sleep_rem);
								break;
							default:
								printf("error: unknown step in usrloc\n");
								exit(2);
								break;
						}
					}
					else if (randtrash) {
						/* in randomzing trash we are expexting 4?? error codes
						   everything else should not be normal */
						if (regexec(&errexp, reply, 0, 0, 0)==0) {
							if (verbose > 2)
								printf("received:\n%s\n", reply);
							if (verbose > 1) {
								printf("received expected 4xx ");
								if (warning_ext) {
									printf ("from ");
									warning_extract(reply);
									printf("\n");
								}
								else printf("\n");
							}
						}
						else {
							printf("warning: did not received 4xx\n");
							if (verbose > 1) 
								printf("sended:\n%s\nreceived:\n%s\n", buff, 
									reply);
						}
						if (nameend==(i+1)) {
							if (randretrys == 0) {
								printf("random end reached. server survived "
									":) respect!\n");
								exit(0);
							}
							else {
								printf("maximum sendings reached but did not "
									"get a response on this request:\n%s\n", 
									buff);
								exit(3);
							}
						}
						else trash_random(buff);
					}
					else {
						/* in the normal send and reply case anything other 
						   then 1xx will be treated as final response*/
						if (regexec(&proexp, reply, 0, 0, 0)==0) {
							if (verbose > 1) {
								printf("%s\n\n", reply);
								printf("** reply received ");
								if (i==0) 
									printf("after %.3f ms **\n", 
										deltaT(&sendtime, &recvtime));
								else 
									printf("%.3f ms after first send\n   and "
										"%.3f ms after last send **\n", 
										deltaT(&firstsendt, &recvtime), 
										deltaT(&sendtime, &recvtime));
								crlf=strchr(reply, '\n');
								*crlf='\0';
								printf("   %s\n   provisional received; still"
									" waiting for a final response\n", reply);
							}
							retryAfter = retryAfter * 2;
							if (retryAfter > DEFAULT_TIMEOUT) 
								retryAfter = DEFAULT_TIMEOUT;
							dontsend = 1;
							continue;
						} else {
							if (verbose > 1) {
								printf("%s\n\n", reply);
								printf("** reply received ");
								if (i==0) 
									printf("after %.3f ms **\n", 
										deltaT(&sendtime, &recvtime));
								else 
									printf("%.3f ms after first send\n   and "
										"%.3f ms after last send **\n", 
										deltaT(&firstsendt, &recvtime), 
										deltaT(&sendtime, &recvtime));
								crlf=strchr(reply, '\n');
								*crlf='\0';
								printf("   %s\n   final received\n", reply);
							}
							else if (verbose) printf("%s\n", reply);
							if (regexec(&okexp, reply, 0, 0, 0)==0)
								exit(0);
							else
								exit(1);
						}
					} /* redirect, auth, and modes */
		
				} /* ret > 0 */
				else {
					if (usrloc)
						printf("failed\n");
					perror("socket error");
					exit(2);
				}
			} /* !flood */
			else {
				if (i==0)
					memcpy(&firstsendt, &sendtime, sizeof(struct timeval));
				if (namebeg==nretries) {
					printf("flood end reached\n");
					printf("it took %.3f ms seconds to send %i request.\n", 
							deltaT(&firstsendt, &sendtime), namebeg);
					printf("so we sended %f requests per second.\n", 
							(namebeg/deltaT(&firstsendt, &sendtime))*1000);
					exit(0);
				}
				namebeg++;
				create_msg(buff, REQ_FLOOD);
			}
		} /* for nretries */

	} /* while redirected */
	if (randtrash) exit(0);
	printf("** give up retransmissioning....\n");
	if (retrans_r_c && (verbose > 1))
		printf("%i retransmissions received during test\n", retrans_r_c);
	if (retrans_s_c && (verbose > 1))
		printf("sent %i retransmissions during test\n", retrans_s_c);
	exit(3);
}

