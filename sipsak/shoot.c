/*
 * $Id: shoot.c,v 1.41 2005/03/27 15:34:15 calrissian Exp $
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <regex.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "shoot.h"

#ifdef RAW_SUPPORT
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define __FAVOR_BSD
#include <netinet/udp.h>
#endif

#include "sipsak.h"
#include "request.h"
#include "auth.h"
#include "header_f.h"
#include "helper.h"
#include "exit_code.h"

#include <string.h>

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

/* if a reply was received successfuly, return success, unless 
 * reply matching is enabled and no match occured
 */

inline static void on_success(char *reply)
{
	if ((reply != NULL) && re && regexec(re, reply, 0, 0, 0)==REG_NOMATCH) {
		fprintf(stderr, "error: RegExp failed\n");
		exit_code(32);
	} else {
		exit_code(0);
	}
}

/* this is the main function with the loops and modes */
void shoot(char *buff)
{
	struct sockaddr_in	addr;
	struct timeval	tv, sendtime, recvtime, firstsendt, delaytime, starttime;
	struct timezone tz;
	struct timespec sleep_ms_s, sleep_rem;
	struct pollfd 	sockerr;
	int redirected, retryAfter, nretries;
	int usock, csock, i, len, ret;
	int dontsend, dontrecv, cseqtmp, rand_tmp;
	int rem_rand, retrans_r_c, retrans_s_c;
	int randretrys = 0;
	int cseqcmp = 0;
	int rem_namebeg = 0;
	double big_delay, tmp_delay, senddiff;
	char *contact, *foo, *bar, *lport_str;
	char *crlf = NULL;
	char reply[BUFSIZE];
	fd_set	fd;
	socklen_t slen;
	regex_t redexp, proexp, okexp, tmhexp, errexp, authexp;
	enum usteps { REG_REP, INV_RECV, INV_OK_RECV, INV_ACK_RECV, MES_RECV, 
					MES_OK_RECV, UNREG_REP};
	enum usteps usrlocstep = REG_REP;
#ifdef RAW_SUPPORT
	struct sockaddr_in faddr;
	struct ip 		*r_ip_hdr, *s_ip_hdr;
	struct icmp 	*icmp_hdr;
	struct udphdr 	*udp_hdr;
	size_t r_ip_len, s_ip_len, icmp_len;
	int srcport, dstport, rawsock;
	unsigned int flen;
	char fstr[INET_ADDRSTRLEN];
#endif

	/* the vars are filled by configure */
	nretries = DEFAULT_RETRYS;
	/* retryAfter = DEFAULT_TIMEOUT; */
	retryAfter = SIP_T1;

	/* initalize some local vars */
	redirected = 1;
	dontsend=dontrecv=retrans_r_c=retrans_s_c = 0;
	big_delay=tmp_delay = 0;
	delaytime.tv_sec = 0;
	delaytime.tv_usec = 0;

	/* create the un-connected socket */
	usock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (usock==-1) {
		perror("unconnected UDP socket creation failed");
		exit_code(2);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family=AF_INET;
	addr.sin_addr.s_addr = htonl( INADDR_ANY );
	addr.sin_port = htons((short)lport);
	if (bind( usock, (struct sockaddr *) &addr, sizeof(addr) )==-1) {
		perror("unconnected UDP socket binding failed");
		exit_code(2);
	}

	/* for the via line we need our listening port number */
	if (lport==0){
		memset(&addr, 0, sizeof(addr));
		slen=sizeof(addr);
		getsockname(usock, (struct sockaddr *)&addr, &slen);
		lport=ntohs(addr.sin_port);
	}

#ifdef RAW_SUPPORT
	/* try to create the raw socket */
	rawsock = (int)socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (rawsock==-1) {
		if (verbose>0)
			printf("Warning: need raw socket (root privileges) to receive all ICMP errors\n");
#endif
		/* create the connected socket as a primitve alternative to the 
		   raw socket*/
		csock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (csock==-1) {
			perror("connected UDP socket creation failed");
			exit_code(2);
		}

		addr.sin_family=AF_INET;
		addr.sin_addr.s_addr = htonl( INADDR_ANY );
		addr.sin_port = htons((short)0);
		if (bind( csock, (struct sockaddr *) &addr, sizeof(addr) )==-1) {
			perror("connected UDP socket binding failed");
			exit_code(2);
		}
#ifdef RAW_SUPPORT
	}
	else {
		csock = -1;
	}
#endif

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

	if (replace_b == 1){
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

	if (usrloc == 1||invite == 1||message == 1){
		/* calculate the number of required steps and create initial mes */
		if (usrloc == 1) {
			if (invite == 1)
				nretries=4*(nameend-namebeg)+4;
			else if (message == 1)
				nretries=3*(nameend-namebeg)+3;
			else
				nretries=2*(nameend-namebeg)+2;
			create_msg(buff, REQ_REG);
			usrlocstep=REG_REP;
		}
		else if (invite == 1) {
			nretries=3*(nameend-namebeg)+3;
			create_msg(buff, REQ_INV);
			usrlocstep=INV_RECV;
		}
		else {
			nretries=2*(nameend-namebeg)+2;
			create_msg(buff, REQ_MES);
			if (mes_body)
				usrlocstep=MES_OK_RECV;
			else
				usrlocstep=MES_RECV;
		}
		cseqcmp=1;
	}
	else if (trace == 1){
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
	else if (flood == 1){
		/* this should be the max of an (32 bit) int without the sign */
		if (namebeg==-1) namebeg=INT_MAX;
		nretries=namebeg;
		namebeg=1;
		create_msg(buff, REQ_FLOOD);
	}
	else if (randtrash == 1){
		randretrys=0;
		namebeg=1;
		create_msg(buff, REQ_RAND);
		nameend=(int)strlen(buff);
		if (trashchar == 1){
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
		if (file_b == 0) {
			namebeg=1;
			create_msg(buff, REQ_OPT);
		}
		/* retryAfter = retryAfter / 10; */
		if(maxforw!=-1)
			set_maxforw(buff);
		if(via_ins == 1)
			add_via(buff);
	}

	/* if we got a redirect this loop ensures sending to the 
	   redirected server*/
	while (redirected == 1) {
		/* we don't want to send for ever */
		redirected=0;

		/* destination socket init here because it could be changed in a 
		   case of a redirect */
		memset(&addr, 0, sizeof(addr));
		addr.sin_addr.s_addr = address;
		addr.sin_port = htons((short)rport);
		addr.sin_family = AF_INET;
	
		if (csock != -1) {
			ret = connect(csock, (struct sockaddr *)&addr, sizeof(addr));
			if (ret==-1) {
				perror("connecting UDP socket failed");
				exit_code(2);
			}
		}

		/* here we go for the number of nretries which strongly depends on the 
		   mode */
		for (i = 0; i <= nretries; i++)
		{
			if (trace == 1) {
				set_maxforw(buff);
			}
			/* some initial output */
			else if ((usrloc == 1||invite == 1||message == 1) && (verbose > 1) && (dontsend == 0)) {
				switch (usrlocstep) {
					case REG_REP:
						if (nameend>0)
							printf("registering user %s%i... ", username, 
								namebeg);
						else
							printf("registering user %s... ", username);
						break;
					case INV_RECV:
						if (nameend>0)
							printf("inviting user %s%i... ", username, namebeg);
						else
							printf("inviting user %s... ", username);
						break;
					case INV_OK_RECV:
						printf("sending invite reply... ");
						break;
					case INV_ACK_RECV:
						printf("sending invite ack... ");
						break;
					case MES_RECV:
						if (nameend>0)
							printf("sending message to %s%i... ", username,
								namebeg);
						else
							printf("sending message to %s... ", username);
						break;
					case MES_OK_RECV:
						if (mes_body)
							printf("sending message ... \n");
						else
							printf("sending message reply... ");
						break;
					case UNREG_REP:
						if (nameend>0)
							printf("remove binding for %s%i...", username, 
								namebeg);
						else
							printf("remove binding for %s...", username);
						break;
				}
			}
			else if (flood == 1 && verbose > 0) {
				printf("flooding message number %i\n", i+1);
			}
			else if (randtrash == 1 && verbose > 0) {
				printf("message with %i randomized chars\n", i+1);
				if (verbose > 2)
					printf("request:\n%s\n", buff);
			}
			else if (trace == 0 && usrloc == 0 && flood == 0 && randtrash == 0 && (verbose > 1)	&& dontsend == 0){
				printf("** request **\n%s\n", buff);
			}

			if (sleep_ms == -2) {
				rand_tmp = rand();
				sleep_ms_s.tv_sec = rand_tmp / 1000;
				sleep_ms_s.tv_nsec = (rand_tmp % 1000) * 1000;
			}

			if (dontsend == 0) {
				/* lets fire the request to the server and store when we did */
				if (csock == -1) {
					ret = sendto(usock, buff, strlen(buff), 0, (struct sockaddr *)&addr, sizeof(addr));
				}
				else {
					ret = send(csock, buff, strlen(buff), 0);
				}
				(void)gettimeofday(&sendtime, &tz);
				if (ret==-1) {
					printf("\n");
					perror("send failure");
					exit_code(2);
				}
			}
			else {
				i--;
				dontsend = 0;
			}

			/* in flood we are only interested in sending so skip the rest */
			if (flood == 0) {
				if (! dontrecv) {
					/* set the timeout and wait for a response */
					tv.tv_sec = retryAfter/1000;
					tv.tv_usec = (retryAfter % 1000) * 1000;

					FD_ZERO(&fd);
					FD_SET(usock, &fd); 
					if (csock != -1)
						FD_SET(csock, &fd); 
#ifdef RAW_SUPPORT
					if (rawsock != -1)
						FD_SET(rawsock, &fd); 
#endif

					ret = select(FD_SETSIZE, &fd, NULL, NULL, &tv);
					(void)gettimeofday(&recvtime, &tz);
				}
				else {
					i--;
					dontrecv = 0;
					if (strncmp(buff, "ACK", 3) == 0) {
						swap_buffers(buff, ack);
						increase_cseq(buff);
					}
					if (usrlocstep == INV_OK_RECV) {
						increase_cseq(confirm);
						increase_cseq(ack);
						usrlocstep = INV_RECV;
					}
					continue;
				}

				if (ret == 0)
				{
					/* store the time of our first send */
					if (i==0)
						memcpy(&firstsendt, &sendtime, sizeof(struct timeval));
					if (retryAfter == SIP_T1)
						memcpy(&starttime, &sendtime, sizeof(struct timeval));
					/* lets see if we at least received an icmp error */
					if (csock == -1) 
						sockerr.fd=usock;
					else
						sockerr.fd=csock;
					sockerr.events=POLLERR;
					if ((poll(&sockerr, 1, 10))==1) {
						if (sockerr.revents && POLLERR) {
							if (csock == -1)
								recv(usock, reply, strlen(reply), 0);
							else
								recv(csock, reply, strlen(reply), 0);
							printf("\n");
							perror("send failure");
							if (randtrash == 1) 
								printf ("last message before send failure:"
									"\n%s\n", buff);
							exit_code(3);
						}
					}
					/* printout that we did not received anything */
					if (trace == 1) {
						printf("%i: timeout after %i ms\n", i, 
									retryAfter);
						i--;
					}
					else if (usrloc == 1||invite == 1||message == 1) {
						printf("timeout after %i ms\n", retryAfter);
						i--;
					}
					else if (verbose>0) printf("** timeout after %i ms**\n", 
										retryAfter);
					if (randtrash == 1) {
						printf("did not get a response on this request:"
							"\n%s\n", buff);
						if (i+1 < nameend) {
							if (randretrys == 2) {
								printf("sended the following message three "
									"times without getting a response:\n%s\n"
									"give up further retransmissions...\n", 
									buff);
								exit_code(3);
							}
							else {
								printf("resending it without additional "
									"random changes...\n\n");
								randretrys++;
							}
						}
					}
					senddiff = deltaT(&starttime, &recvtime);
					if (senddiff > (float)64 * (float)SIP_T1) {
						if (verbose>0)
							printf("*** giving up, no response after %.3f ms\n",
								senddiff);
						else if (timing)
							printf("%.3f ms\n", senddiff);
						exit_code(3);
					}
					/* set retry time according to RFC3261 */
					if (retryAfter *2 < SIP_T2)
						retryAfter = retryAfter * 2;
					else
						retryAfter = SIP_T2;
					retrans_s_c++;
					if (delaytime.tv_sec == 0)
						memcpy(&delaytime, &sendtime, sizeof(struct timeval));
					/* if we did not exit until here lets try another send */
					continue;
				}
				else if ( ret == -1 ) {
					perror("select error");
					exit_code(2);
				}
				else if (FD_ISSET(usock, &fd) || ((csock != -1) && FD_ISSET(csock, &fd))) {
					/* no timeout, no error ... something has happened :-) */
				 	if (trace == 0 && usrloc ==0 && invite == 0 && message == 0 && randtrash == 0 && (verbose > 1))
						printf ("\nmessage received:\n");
				}
#ifdef RAW_SUPPORT
				else if ((rawsock != -1) && FD_ISSET(rawsock, &fd)) {
					if (verbose > 1)
						printf("\nreceived ICMP packet");
				}
#endif
				else {
					printf("\nselect returned succesfuly, nothing received\n");
					continue;
				}

				/* we are retrieving only the extend of a decent 
				   MSS = 1500 bytes */
				len = sizeof(addr);
				if (FD_ISSET(usock, &fd)) {
					ret = recv(usock, reply, BUFSIZE, 0);
				}
				else if ((csock != -1) && (FD_ISSET(csock, &fd))) {
					ret = recv(csock, reply, BUFSIZE, 0);
				}
#ifdef RAW_SUPPORT
				else if ((rawsock != -1) && (FD_ISSET(rawsock, &fd))) {
					/* lets check if the ICMP message matches with our 
					   sent packet */
					flen = sizeof(faddr);
					memset(&faddr, 0, sizeof(addr));
					ret = recvfrom(rawsock, reply, BUFSIZE, 0, (struct sockaddr *)&faddr, &flen);
					if (ret == -1) {
						perror("error while trying to read from icmp raw socket");
						exit_code(2);
					}
					r_ip_hdr = (struct ip *) reply;
					r_ip_len = r_ip_hdr->ip_hl << 2;

					icmp_hdr = (struct icmp *) (reply + r_ip_len);
					icmp_len = ret - r_ip_len;

					if (icmp_len < 8) {
						if (verbose > 1)
							printf(": ignoring (ICMP header length below 8 bytes)\n");
						continue;
					}
					else if (icmp_len < 36) {
						if (verbose > 1)
							printf(": ignoring (ICMP message too short to contain IP and UDP header)\n");
						continue;
					}
					s_ip_hdr = (struct ip *) ((char *)icmp_hdr + 8);
					s_ip_len = s_ip_hdr->ip_hl << 2;
					if (s_ip_hdr->ip_p == IPPROTO_UDP) {
						udp_hdr = (struct udphdr *) ((char *)s_ip_hdr + s_ip_len);
						srcport = ntohs(udp_hdr->uh_sport);
						dstport = ntohs(udp_hdr->uh_dport);
						if ((srcport == lport) && (dstport == rport)) {
							inet_ntop(AF_INET, &faddr.sin_addr, fstr, INET_ADDRSTRLEN);
							printf(" (type: %u, code: %u): from %s\n", icmp_hdr->icmp_type, icmp_hdr->icmp_code, fstr);
							exit_code(3);
						}
						else {
							if (verbose > 2)
								printf(": ignoring (ICMP error does not match send data)\n");
							continue;
						}
					}
					else {
						if (verbose > 1)
							printf(": ignoring (ICMP data is not a UDP packet)\n");
						continue;
					}
				}
#endif
				if(ret > 0)
				{
					reply[ret] = '\0';
					/* store the time of our first send */
					if (i==0)
						memcpy(&firstsendt, &sendtime, sizeof(struct timeval));
					retryAfter = SIP_T1;
					/* store the biggest delay if one occured */
					if (delaytime.tv_sec != 0) {
						tmp_delay = deltaT(&delaytime, &recvtime);
						if (tmp_delay > big_delay) big_delay = tmp_delay;
						delaytime.tv_sec = 0;
						delaytime.tv_usec = 0;
					}
					/* check for old CSeq => ignore retransmission */
					if (usrloc == 0 && invite == 0 && message == 0)
						cseqcmp = namebeg;
					cseqtmp = cseq(reply);
					if ((0 < cseqtmp) && (cseqtmp < cseqcmp)) {
						if (verbose>0)
							printf("ignoring retransmission\n");
						retrans_r_c++;
						dontsend = 1;
						continue;
					}
					/* lets see if received a redirect */
					if (redirects == 1 && regexec(&redexp, reply, 0, 0, 0)==0) {
						printf("** received redirect ");
						if (warning_ext == 1) {
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
							if ((foo=strstr(reply, CONT_STR))==NULL &&
								(foo=strstr(reply, "\nCONT_SHORT_STR"))==NULL ) {
								printf("error: cannot find Contact in this "
									"redirect:\n%s\n", reply);
								exit_code(3);
							}
							crlf=strchr(foo, '\n');
							if ((contact=strchr(foo, '\r'))!=NULL 
							&& contact<crlf)
								crlf=contact;
							bar=malloc((size_t)(crlf-foo+1));
							strncpy(bar, foo, (size_t)(crlf-foo));
							*(bar+(crlf-foo))='\0';
							if ((contact=strstr(bar, "sip"))==NULL) {
								printf("error: cannot find sip in the Contact "
									"of this redirect:\n%s\n", reply);
								exit_code(3);
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
									if (rport == 0) {
										printf("error: cannot handle the port "
											"in the uri in Contact:\n%s\n", 
											reply);
										exit_code(3);
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
								if (address == 1){
									printf("error: cannot determine host "
										"address from Contact of redirect:"
										"\n%s\n", reply);
									exit_code(2);
								}
							}
							else{
								printf("error: missing : in Contact of this "
									"redirect:\n%s\n", reply);
								exit_code(3);
							}
							free(bar);
							memset(&addr, 0, sizeof(addr));
							redirected=1;
							i=nretries;
						}
						else {
							printf("error: cannot handle this redirect:"
								"\n%s\n", reply);
							exit_code(2);
						}
					} /* if redircts... */
					else if (regexec(&authexp, reply, 0, 0, 0)==0) {
						if (!username) {
							printf("%s\nerror: received 401 but cannot "
								"authentication without a username\n", reply);
							exit_code(2);
						}
						/* prevents a strange error */
						regcomp(&authexp, "^SIP/[0-9]\\.[0-9] 40[17] ", 
							REG_EXTENDED|REG_NOSUB|REG_ICASE);
						insert_auth(buff, reply);
						if (verbose > 2)
							printf("\nreceived:\n%s\n", reply);
						if (strncmp(buff, "INVITE", 6) == 0) {
							build_ack(buff, reply, ack);
							swap_buffers(buff, ack);
							dontrecv = 1;
						}
						else {
							increase_cseq(buff);
						}
					} /* if auth...*/
					else if (trace == 1) {
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
								if (!crlf) {
									printf("failed to find newline\n");
									exit_code(254);
								}
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
								if (!crlf) {
									printf("failed to find newline\n");
									exit_code(254);
								}
								*crlf='\0';
								printf("(%.3f ms) %s\n", 
									deltaT(&sendtime, &recvtime), reply);
							}
							retryAfter = SIP_T2;
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
							if (!crlf) {
								printf("failed to find newline\n");
								exit_code(254);
							}
							*crlf='\0';
							crlf++;
							printf("(%.3f ms) %s\n", 
								deltaT(&sendtime, &recvtime), reply);
							contact=strstr(crlf, CONT_STR);
							if (!contact)
								contact=strstr(crlf, "\nCONT_SHORT_STR");
							if (contact){
								crlf=strchr(contact,'\n');
								*crlf='\0';
								printf("\t%s\n", contact);
							}
							else {
								printf("\twithout Contact header\n");
							}
							if (regexec(&okexp, reply, 0, 0, 0)==0)
								on_success(reply);
							else
								exit_code(1);
						}
					} /* if trace ... */
					else if (usrloc == 1||invite == 1||message == 1) {
						if (regexec(&proexp, reply, 0, 0, 0)==0) {
							if (verbose > 2)
								printf("\nignoring provisinal "
									"response\n");
							retryAfter = SIP_T2;
							dontsend = 1;
						}
						else {
						switch (usrlocstep) {
							case REG_REP:
								/* we have sent a register and look 
								   at the response now */
								if (regexec(&okexp, reply, 0, 0, 0)==0) {
									if (verbose > 1)
										printf ("\tOK\n");
									if (verbose > 2)
										printf("\n%s\n", reply);
								}
								else {
									printf("\nreceived:\n%s\nerror: didn't "
										"received '200 OK' on register (see "
										"above). aborting\n", reply);
									exit_code(1);
								}
								if (invite == 0 && message == 0) {
									if (namebeg==nameend) {
										if (verbose>0) 
											printf("\nAll usrloc tests"
											" completed successful.\nreceived"
											" last message %.3f ms after first"
											" request (test duration).\n", 
											deltaT(&firstsendt, &recvtime));
										if (big_delay>0 && verbose>0)
											printf("biggest delay between "
												"request and response was %.3f"
												" ms\n", big_delay);
										if (retrans_r_c>0 && verbose>0)
											printf("%i retransmission(s) "
												"received from server.\n", 
												retrans_r_c);
										if (retrans_s_c>0 && verbose>0) {
											printf("%i time(s) the timeout of "
												"%i ms exceeded and request was"
												" retransmitted.\n", 
												retrans_s_c, retryAfter);
											if (retrans_s_c > nagios_warn)
												exit_code(4);
										}
										if (timing) printf("%.3f ms\n",
															deltaT(&firstsendt, &recvtime));
										on_success(reply);
									}
									/* lets see if we deceid to remove a 
									   binding (case 6)*/
									rem_rand=rand();
									if (rand_rem == 0||
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
										usrlocstep=UNREG_REP;
									}
								}
								else if (invite == 1) {
									create_msg(buff, REQ_INV);
									cseqcmp++;
									usrlocstep=INV_RECV;
								}
								else if (message == 1) {
									create_msg(buff, REQ_MES);
									cseqcmp++;
									usrlocstep=MES_RECV;
								}
								if (sleep_ms != 0) {
									nanosleep(&sleep_ms_s, &sleep_rem);
								}
								break;
							case INV_RECV:
								/* see if we received our invite */
								if (!strncmp(reply, messusern, 
									strlen(messusern))) {
									if (verbose > 1)
										printf("\t\treceived invite\n");
									if (verbose > 2)
										printf("\n%s\n", reply);
									cpy_vias(reply, confirm);
									cpy_to(reply, confirm);
									strcpy(buff, confirm);
									usrlocstep=INV_OK_RECV;
								}
								else {
									printf("\nreceived:\n%s\nerror: did not "
										"received the INVITE that was sent "
										"(see above). aborting\n", reply);
									exit_code(1);
								}
								break;
							case INV_OK_RECV:
								/* did we received our ok ? */
								if (strncmp(reply, INV_STR, INV_STR_LEN)==0) {
									if (verbose>0)
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
									usrlocstep=INV_ACK_RECV;
								}
								else {
									printf("\nreceived:\n%s\nerror: did not "
										"received the '200 OK' that was sent "
										"as the reply on the INVITE (see "
										"above). aborting\n", reply);
									exit_code(1);
								}
								break;
							case INV_ACK_RECV:
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
									if (verbose>0 && nameend>0)
										printf("usrloc for %s%i completed "
											"successful\n", username, namebeg);
									else if (verbose>0)
										printf("usrloc for %s completed "
											"successful\n", username);
									if (namebeg==nameend) {
										if (verbose>0)
											printf("\nAll usrloc tests completed "
												"successful.\nreceived last message"
												" %.3f ms after first request (test"
												" duration).\n", deltaT(&firstsendt,
												 &recvtime));
										if (big_delay>0)
											printf("biggest delay between "
												"request and response was %.3f"
												" ms\n", big_delay);
										if (retrans_r_c>0)
											printf("%i retransmission(s) "
												"received from server.\n", 
												retrans_r_c);
										if (retrans_s_c>0) {
											printf("%i time(s) the timeout of "
												"%i ms exceeded and request was"
												" retransmitted.\n", 
												retrans_s_c, retryAfter);
											if (retrans_s_c > nagios_warn)
												exit_code(4);
										}
										on_success(reply);
									}
									if (usrloc == 1) {
										/* lets see if we deceid to remove a 
										   binding (case 6)*/
										rem_rand=rand();
										if (rand_rem == 0||
											((float)rem_rand/RAND_MAX) 
												> USRLOC_REMOVE_PERCENT) {
											namebeg++;
											create_msg(buff, REQ_REG);
											cseqcmp=cseqcmp+2;
											usrlocstep=REG_REP;
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
											usrlocstep=UNREG_REP;
										}
									}
									else {
										namebeg++;
										create_msg(buff, REQ_INV);
										cseqcmp=cseqcmp+3;
										usrlocstep=INV_RECV;
									}
								}
								else {
									printf("\nreceived:\n%s\nerror: did not "
										"received the 'ACK' that was sent "
										"as the reply on the '200 OK' (see "
										"above). aborting\n", reply);
									exit_code(1);
								}
								if (sleep_ms != 0)
									nanosleep(&sleep_ms_s, &sleep_rem);
								break;
							case MES_RECV:
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
									usrlocstep=MES_OK_RECV;
								}
								else {
									printf("\nreceived:\n%s\nerror: did not "
										"received the 'MESSAGE' that was sent "
										"(see above). aborting\n", reply);
									exit_code(1);
								}
								break;
							case MES_OK_RECV:
								/* we sent our reply on the message and
								   look if this is also forwarded to us */
								if (strncmp(reply, MES_STR, MES_STR_LEN)==0) {
									if (verbose>0)
										printf("ignoring MESSAGE "
											"retransmission\n");
									retrans_r_c++;
									dontsend=1;
									continue;
								}
								if (regexec(&okexp, reply, 0, 0, 0)==0) {
									if (verbose > 1)
										printf("  reply received\n\n");
									else if (verbose>0 && nameend>0)
										printf("usrloc for %s%i completed "
											"successful\n", username, namebeg);
									else if (verbose>0)
										printf("usrloc for %s completed "
											"successful\n", username);
									if (namebeg==nameend) {
										if (verbose>0)
											printf("\nAll usrloc tests completed "
												"successful.\nreceived last message"
												" %.3f ms after first request (test"
												" duration).\n", deltaT(&firstsendt,
												 &recvtime));
										if (big_delay>0)
											printf("biggest delay between "
												"request and response was %.3f"
												" ms\n", big_delay);
										if (retrans_r_c>0)
											printf("%i retransmission(s) "
												"received from server.\n", 
												retrans_r_c);
										if (retrans_s_c>0) {
											printf("%i time(s) the timeout of "
												"%i ms exceeded and request was"
												" retransmitted.\n", 
												retrans_s_c, retryAfter);
											if (retrans_s_c > nagios_warn)
												exit_code(4);
										}
										on_success(reply);
									}
									if (usrloc == 1) {
										/* lets see if we deceid to remove a 
										   binding (case 6)*/
										rem_rand=rand();
										if (rand_rem>0 ||
											((float)rem_rand/RAND_MAX) 
												> USRLOC_REMOVE_PERCENT) {
											namebeg++;
											create_msg(buff, REQ_REG);
											cseqcmp=cseqcmp+2;
											usrlocstep=REG_REP;
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
											usrlocstep=UNREG_REP;
										}
									}
									else {
										namebeg++;
										create_msg(buff, REQ_MES);
										cseqcmp=cseqcmp+3;
										usrlocstep=MES_RECV;
									}
								}
								else {
									if (verbose>0) {
										if (mes_body)
											printf("\nreceived:\n%s\nerror: did"
												" not received 200 for the "
												"MESSAGE (see above)\n",
												reply);
										else
											printf("\nreceived:\n%s\nerror: did"
												" not received the '200 OK' "
												"that was sent as the reply on"
												" the MESSAGE (see above). "
												"aborting\n", reply);
									}
									exit_code(1);
								}
								if (sleep_ms != 0)
									nanosleep(&sleep_ms_s, &sleep_rem);
								break;
							case UNREG_REP:
								if (strncmp(reply, MES_STR, MES_STR_LEN)==0) {
									if (verbose>0)
										printf("ignoring MESSAGE "
											"retransmission\n");
									retrans_r_c++;
									dontsend=1;
									continue;
								}
								if (regexec(&okexp, reply, 0, 0, 0)==0) {
									if (verbose > 1) printf("   OK\n\n");
									else if (verbose>0 && nameend>0)
										printf("Binding removal for %s%i "
											"successful\n", username, namebeg);
									else if (verbose>0)
										printf("Binding removal for %s "
											"successful\n", username);
									namebeg = rem_namebeg;
									namebeg++;
									create_msg(buff, REQ_REG);
									cseqcmp++;
									usrlocstep=REG_REP;
									i--;
								}
								else {
									printf("\nreceived:\n%s\nerror: did not "
										"received the expected 200 on the "
										"remove bindings request for %s%i (see"
										" above). aborting\n", reply, username, 
										namebeg);
									exit_code(1);
								}
								if (sleep_ms != 0)
									nanosleep(&sleep_ms_s, &sleep_rem);
								break;
							default:
								printf("error: unknown step in usrloc\n");
								exit_code(2);
								break;
						}
						}
					}
					else if (randtrash == 1) {
						/* in randomzing trash we are expexting 4?? error codes
						   everything else should not be normal */
						if (regexec(&errexp, reply, 0, 0, 0)==0) {
							if (verbose > 2)
								printf("received:\n%s\n", reply);
							if (verbose > 1) {
								printf("received expected 4xx ");
								if (warning_ext == 1) {
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
								exit_code(0);
							}
							else {
								printf("maximum sendings reached but did not "
									"get a response on this request:\n%s\n", 
									buff);
								exit_code(3);
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
								if (!crlf) {
									printf("failed to find newline\n");
									exit_code(254);
								}
								*crlf='\0';
								printf("   %s\n   provisional received; still"
									" waiting for a final response\n", reply);
							}
							retryAfter = SIP_T2;
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
								if (!crlf) {
									printf("failed to find newline\n");
									exit_code(254);
								}
								*crlf='\0';
								printf("   %s\n   final received\n", reply);
							}
							else if (verbose>0) printf("%s\n", reply);
							else if (timing) printf("%.3f ms\n", 
										deltaT(&firstsendt, &recvtime));
							if (regexec(&okexp, reply, 0, 0, 0)==0)
								on_success(reply);
							else
								exit_code(1);
						}
					} /* redirect, auth, and modes */
		
				} /* ret > 0 */
				else {
					if (usrloc == 1)
						printf("failed\n");
					perror("socket error");
					exit_code(3);
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
					exit_code(0);
				}
				namebeg++;
				create_msg(buff, REQ_FLOOD);
			}
		} /* for nretries */

	} /* while redirected */
	if (randtrash == 1) exit_code(0);
	printf("** give up retransmissioning....\n");
	if (retrans_r_c>0 && (verbose > 1))
		printf("%i retransmissions received during test\n", retrans_r_c);
	if (retrans_s_c>0 && (verbose > 1))
		printf("sent %i retransmissions during test\n", retrans_s_c);
	exit_code(3);
}

