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

#ifdef HAVE_LIMITS_H
# include <limits.h>
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
#endif /* TIME_WITH_SYS_TIME */
#ifdef HAVE_UNISTD_H
# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif
# include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_SYS_POLL_H
# include <sys/poll.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#include "shoot.h"

#ifdef RAW_SUPPORT
# ifdef HAVE_NETINET_IN_SYSTM_H 
#  include <netinet/in_systm.h>
# endif
# ifdef HAVE_NETINET_IP_H
#  include <netinet/ip.h>
# endif
# ifdef HAVE_NETINET_IP_ICMP_H
#  include <netinet/ip_icmp.h>
# endif
# ifdef HAVE_NETINET_UDP_H
#  define __FAVOR_BSD
#  include <netinet/udp.h>
# endif
#endif /* RAW_SUPPORT */

#include "request.h"   
#include "auth.h"
#include "header_f.h"
#include "helper.h"
#include "exit_code.h"

#ifndef DEFAULT_RETRYS
#define DEFAULT_RETRYS 5
#endif

#ifndef DEFAULT_TIMEOUT
#define DEFAULT_TIMEOUT 5000
#endif

struct timezone tz;
struct timeval sendtime, recvtime, tv, firstsendt, starttime, delaytime;
int dontsend, dontrecv, usock, csock, retryAfter, randretrys, retrans_s_c;
int i, send_counter;
double senddiff, big_delay;
regex_t redexp, proexp, okexp, tmhexp, errexp, authexp, replyexp;
enum usteps { REG_REP, INV_RECV, INV_OK_RECV, INV_ACK_RECV, MES_RECV, 
					MES_OK_RECV, UNREG_REP};
enum usteps usrlocstep;
#ifdef RAW_SUPPORT
int rawsock;
#endif

void send_message(char* mes, struct sockaddr *dest) {
	int ret;

	if (dontsend == 0) {
		/* lets fire the request to the server and store when we did */
		if (csock == -1) {
			ret = sendto(usock, mes, strlen(mes), 0, dest, sizeof(struct sockaddr));
		}
		else {
			ret = send(csock, mes, strlen(mes), 0);
		}
		(void)gettimeofday(&sendtime, &tz);
		if (ret==-1) {
			printf("\n");
			perror("send failure");
			exit_code(2);
		}
#ifdef HAVE_INET_NTOP
		if (verbose > 2)
			printf("send to: %s:%i\n", target_dot, rport);
#endif
		send_counter++;
	}
	else {
		dontsend = 0;
	}
}

int check_for_message(char *recv, int size) {
	fd_set	fd;
	int ret = 0;
	struct pollfd sockerr;

	if (dontrecv == 0) {
		/* set the timeout and wait for a response */
		tv.tv_sec = retryAfter/1000;
		tv.tv_usec = (retryAfter % 1000) * 1000;

		FD_ZERO(&fd);
		if (usock != -1)
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
		dontrecv = 0;
	}

	if (ret == 0)
	{
		/* store the time of our first send */
		if (send_counter==1)
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
					recvfrom(usock, recv, size, 0, NULL, 0);
				else
					recvfrom(csock, recv, size, 0, NULL, 0);
				printf("\n");
				perror("send failure");
				if (randtrash == 1) 
					printf ("last message before send failure:\n%s\n", request);
				exit_code(3);
			}
		}
		/* printout that we did not received anything */
		if (trace == 1) {
			printf("%i: timeout after %i ms\n", i, retryAfter);
			i--;
		}
		else if (usrloc == 1||invite == 1||message == 1) {
			printf("timeout after %i ms\n", retryAfter);
			i--;
		}
		else if (verbose>0) 
			printf("** timeout after %i ms**\n", retryAfter);
		if (randtrash == 1) {
			printf("did not get a response on this request:\n%s\n", request);
			if (i+1 < nameend) {
				if (randretrys == 2) {
					printf("sended the following message three "
							"times without getting a response:\n%s\n"
							"give up further retransmissions...\n", request);
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
				printf("*** giving up, no response after %.3f ms\n", senddiff);
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
		return -1;
	}
	else if ( ret == -1 ) {
		perror("select error");
		exit_code(2);
	}
	else if (((usock != -1) && FD_ISSET(usock, &fd)) || ((csock != -1) && FD_ISSET(csock, &fd))) {
		if ((usock != -1) && FD_ISSET(usock, &fd))
			ret = usock;
		else
			ret = csock;
		/* no timeout, no error ... something has happened :-) */
	 	if (trace == 0 && usrloc ==0 && invite == 0 && message == 0 && randtrash == 0 && (verbose > 1))
			printf ("\nmessage received");
	}
#ifdef RAW_SUPPORT
	else if ((rawsock != -1) && FD_ISSET(rawsock, &fd)) {
		if (verbose > 1)
			printf("\nreceived ICMP packet");
		ret = rawsock;
	}
#endif
	else {
		printf("\nselect returned succesfuly, nothing received\n");
		return -1;
	}
	return ret;
}

int recv_message(char *buf, int size) {
	int ret = 0;
	int sock = 0;
	double tmp_delay;
#ifdef HAVE_INET_NTOP
	struct sockaddr_in peer_adr;
	socklen_t psize = sizeof(peer_adr);
#endif
#ifdef RAW_SUPPORT
	struct sockaddr_in faddr;
	struct ip 		*r_ip_hdr, *s_ip_hdr;
	struct icmp 	*icmp_hdr;
	struct udphdr 	*udp_hdr;
	size_t r_ip_len, s_ip_len, icmp_len;
	int srcport, dstport;
	unsigned int flen;
#endif

	sock = check_for_message(buf, size);
	if (sock <= 1) {
		return -1;
	}
	if (sock != rawsock) {
		ret = recvfrom(sock, buf, size, 0, NULL, 0);
	}
#ifdef RAW_SUPPORT
	else {
		/* lets check if the ICMP message matches with our 
		   sent packet */
		flen = sizeof(faddr);
		memset(&faddr, 0, sizeof(struct sockaddr));
		ret = recvfrom(rawsock, buf, size, 0, (struct sockaddr *)&faddr, &flen);
		if (ret == -1) {
			perror("error while trying to read from icmp raw socket");
			exit_code(2);
		}
		r_ip_hdr = (struct ip *) buf;
		r_ip_len = r_ip_hdr->ip_hl << 2;

		icmp_hdr = (struct icmp *) (buf + r_ip_len);
		icmp_len = ret - r_ip_len;

		if (icmp_len < 8) {
			if (verbose > 1)
				printf(": ignoring (ICMP header length below 8 bytes)\n");
			return 0;
		}
		else if (icmp_len < 36) {
			if (verbose > 1)
				printf(": ignoring (ICMP message too short to contain IP and UDP header)\n");
			return 0;
		}
		s_ip_hdr = (struct ip *) ((char *)icmp_hdr + 8);
		s_ip_len = s_ip_hdr->ip_hl << 2;
		if (s_ip_hdr->ip_p == IPPROTO_UDP) {
			udp_hdr = (struct udphdr *) ((char *)s_ip_hdr + s_ip_len);
			srcport = ntohs(udp_hdr->uh_sport);
			dstport = ntohs(udp_hdr->uh_dport);
			if ((srcport == lport) && (dstport == rport)) {
				printf(" (type: %u, code: %u)", icmp_hdr->icmp_type, icmp_hdr->icmp_code);
#ifdef HAVE_INET_NTOP
				if (inet_ntop(AF_INET, &faddr.sin_addr, &source_dot[0], INET_ADDRSTRLEN) != NULL)
					printf(": from %s\n", source_dot);
				else
					printf("\n");
#else
				printf("\n");
#endif
				exit_code(3);
			}
			else {
				if (verbose > 2)
					printf(": ignoring (ICMP error does not match send data)\n");
				return 0;
			}
		}
		else {
			if (verbose > 1)
				printf(": ignoring (ICMP data is not a UDP packet)\n");
			return 0;
		}
	}
#endif
	*(buf+ ret) = '\0';
	if (ret > 0) {
		/* store the time of our first send */
		if (send_counter == 1)
			memcpy(&firstsendt, &sendtime, sizeof(struct timeval));
		retryAfter = SIP_T1;
		/* store the biggest delay if one occured */
		if (delaytime.tv_sec != 0) {
			tmp_delay = deltaT(&delaytime, &recvtime);
			if (tmp_delay > big_delay)
				big_delay = tmp_delay;
			delaytime.tv_sec = 0;
			delaytime.tv_usec = 0;
		}
#ifdef HAVE_INET_NTOP
		if ((verbose > 2) && (getpeername(sock, (struct sockaddr *)&peer_adr, &psize) == 0) && (inet_ntop(peer_adr.sin_family, &peer_adr.sin_addr, &source_dot[0], INET_ADDRSTRLEN) != NULL)) {
			printf(" from: %s:%i\n", source_dot, ntohs(peer_adr.sin_port));
		}
		else if (verbose > 1)
			printf(":\n");
#else
		printf(":\n");
#endif
	}
	return ret;
}

/* if a reply was received successfuly, return success, unless 
 * reply matching is enabled and no match occured
 */

inline static void on_success(char *rep)
{
	if ((rep != NULL) && re && regexec(re, rep, 0, 0, 0) == REG_NOMATCH) {
		fprintf(stderr, "error: RegExp failed\n");
		exit_code(32);
	} else {
		exit_code(0);
	}
}

void handle_3xx(struct sockaddr_in *tadr)
{
	char *uscheme, *uuser, *uhost, *contact;

	printf("** received redirect ");
	if (warning_ext == 1) {
		printf("from ");
		warning_extract(reply);
		printf("\n");
	}
	else
		printf("\n");
	/* we'll try to handle 301 and 302 here, other 3xx are to complex */
	regcomp(&redexp, "^SIP/[0-9]\\.[0-9] 30[125] ", 
			REG_EXTENDED|REG_NOSUB|REG_ICASE);
	if (regexec(&redexp, reply, 0, 0, 0) == REG_NOERROR) {
		/* try to find the contact in the redirect */
		contact = uri_from_contact(reply);
		if (contact==NULL) {
			printf("error: cannot find Contact in this "
				"redirect:\n%s\n", reply);
			exit_code(3);
		}
		/* correct our request */
		uri_replace(request, contact);
		new_transaction(request);
		/* extract the needed information*/
		rport = 0;
		address = 0;
		parse_uri(contact, &uscheme, &uuser, &uhost, &rport);
		if (!rport)
			address = getsrvaddress(uhost, &rport);
		if (!address)
			address = getaddress(uhost);
		if (!address){
			printf("error: cannot determine host "
					"address from Contact of redirect:"
					"\n%s\n", reply);
			exit_code(2);
		}
		if (!rport) {
			rport = 5060;
		}
		free(contact);
		if (!outbound_proxy)
			set_target(tadr, address, rport, csock);
		//i=nretries; ???
	}
	else {
		printf("error: cannot handle this redirect:"
				"\n%s\n", reply);
		exit_code(2);
	}
}

void trace_reply()
{
	char *contact;

	if (regexec(&tmhexp, reply, 0, 0, 0) == REG_NOERROR) {
		/* we received 483 to many hops */
		printf("%i: ", i);
		if (verbose > 2) {
			printf("(%.3f ms)\n%s\n", 
				deltaT(&sendtime, &recvtime), reply);
		}
		else {
			warning_extract(reply);
			printf("(%.3f ms) ", deltaT(&sendtime, &recvtime));
			print_message_line(reply);
		}
		namebeg++;
		cseq_counter++;
		create_msg(request, REQ_OPT);
		add_via(request);
		set_maxforw(request, -1);
		return;
	}
	else if (regexec(&proexp, reply, 0, 0, 0) == REG_NOERROR) {
		/* we received a provisional response */
		printf("%i: ", i);
		if (verbose > 2) {
			printf("(%.3f ms)\n%s\n", 
				deltaT(&sendtime, &recvtime), reply);
		}
		else {
			warning_extract(reply);
			printf("(%.3f ms) ", deltaT(&sendtime, &recvtime));
			print_message_line(reply);
		}
		retryAfter = SIP_T2;
		dontsend=1;
		return;
	}
	else {
		/* anything else then 483 or provisional will
		   be treated as final */
		if (maxforw==i)
			printf("%i: ", i);
		else
			printf("\t");
		warning_extract(reply);
		printf("(%.3f ms) ", deltaT(&sendtime, &recvtime));
		print_message_line(reply);
		if ((contact = STRCASESTR(reply, CONT_STR)) != NULL ||
				(contact = STRCASESTR(reply, CONT_SHORT_STR)) != NULL) {
			printf("\t");
			print_message_line(contact);
		}
		else {
			printf("\twithout Contact header\n");
		}
		if (regexec(&okexp, reply, 0, 0, 0) == REG_NOERROR)
			on_success(reply);
		else
			exit_code(1);
	}
}

void handle_default()
{
	/* in the normal send and reply case anything other 
	   then 1xx will be treated as final response*/
	if (regexec(&proexp, reply, 0, 0, 0) == REG_NOERROR) {
		if (verbose > 1) {
			printf("%s\n\n", reply);
			printf("** reply received ");
			if (send_counter == 1) {
				printf("after %.3f ms **\n", deltaT(&sendtime, &recvtime));
			}
			else {
				printf("%.3f ms after first send\n   and "
						"%.3f ms after last send **\n", deltaT(&firstsendt, &recvtime), 
						deltaT(&sendtime, &recvtime));
			}
			printf("   ");
			print_message_line(reply);
			printf("   provisional received; still"
					" waiting for a final response\n");
		}
		retryAfter = SIP_T2;
		dontsend = 1;
		return;
	}
	else {
		if (verbose > 1) {
			printf("%s\n\n", reply);
			printf("** reply received ");
			if (send_counter == 1) {
				printf("after %.3f ms **\n", deltaT(&sendtime, &recvtime));
			}
			else {
				printf("%.3f ms after first send\n   and "
						"%.3f ms after last send **\n", deltaT(&firstsendt, &recvtime), 
						deltaT(&sendtime, &recvtime));
			}
			printf("   ");
			print_message_line(reply);
			printf("   final received\n");
		}
		else if (verbose>0) {
			printf("%s\n", reply);
		}
		else if (timing) {
			printf("%.3f ms\n", deltaT(&firstsendt, &recvtime));
		}
		if (regexec(&okexp, reply, 0, 0, 0) == REG_NOERROR) {
			on_success(reply);
		}
		else {
			exit_code(1);
		}
	}
}

void handle_randtrash()
{
	/* in randomzing trash we are expexting 4?? error codes
	   everything else should not be normal */
	if (regexec(&errexp, reply, 0, 0, 0) == REG_NOERROR) {
		if (verbose > 2)
			printf("received:\n%s\n", reply);
		if (verbose > 1) {
			printf("received expected 4xx ");
			if (warning_ext == 1) {
				printf ("from ");
				warning_extract(reply);
				printf("\n");
			}
			else {
				printf("\n");
			}
		}
	}
	else {
		printf("warning: did not received 4xx\n");
		if (verbose > 1) 
			printf("sended:\n%s\nreceived:\n%s\n", request, reply);
	}
	if (nameend == (i+1)) {
		if (randretrys == 0) {
			printf("random end reached. server survived :) respect!\n");
			exit_code(0);
		}
		else {
			printf("maximum sendings reached but did not "
				"get a response on this request:\n%s\n", request);
			exit_code(3);
		}
	}
	else {
		trash_random(request);
	}
}

void before_sending()
{
	/* some initial output */
	if ((usrloc == 1||invite == 1||message == 1) && (verbose > 1) && (dontsend == 0)) {
		switch (usrlocstep) {
			case REG_REP:
				if (nameend>0)
					printf("registering user %s%i... ", username, namebeg);
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
					printf("sending message to %s%i... ", username, namebeg);
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
					printf("remove binding for %s%i...", username, namebeg);
				else
					printf("remove binding for %s...", username);
				break;
		}
	} /* if usrloc...*/
	else if (flood == 1 && verbose > 0) {
		printf("flooding message number %i\n", i+1);
	}
	else if (randtrash == 1 && verbose > 0) {
		printf("message with %i randomized chars\n", i+1);
		if (verbose > 2)
			printf("request:\n%s\n", request);
	}
	else if (trace == 0 && usrloc == 0 && flood == 0 && randtrash == 0 && (verbose > 1)	&& dontsend == 0){
		printf("** request **\n%s\n", request);
	}
}

/* this is the main function with the loops and modes */
void shoot(char *buff, int buff_size)
{
	struct sockaddr_in	addr;
	//struct timeval	tv, sendtime, recvtime, firstsendt, delaytime, starttime;
	//struct timezone tz;
	struct timespec sleep_ms_s, sleep_rem;
	int nretries;
	int ret;
	int cseqtmp, rand_tmp;
	int rem_rand, retrans_r_c;
	//int randretrys = 0;
	//int cseqcmp = 0;
	int rem_namebeg = 0;
	//double big_delay, tmp_delay;
	char *lport_str;
	//char *uscheme, *uuser, *uhost;
	char *crlf = NULL;
	char buff2[BUFSIZE];
	//fd_set	fd;
	socklen_t slen;
	//regex_t redexp, proexp, okexp, tmhexp, errexp, authexp, replyexp;

	/* the vars are filled by configure */
	nretries = DEFAULT_RETRYS;
	/* retryAfter = DEFAULT_TIMEOUT; */
	retryAfter = SIP_T1;
	cseq_counter = 1;
	usrlocstep = REG_REP;

	/* initalize some local vars */
	dontsend=dontrecv=retrans_r_c=retrans_s_c = 0;
	big_delay= 0;
	delaytime.tv_sec = 0;
	delaytime.tv_usec = 0;

	csock = usock = -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family=AF_INET;
	addr.sin_addr.s_addr = htonl( INADDR_ANY );
	addr.sin_port = htons((short)lport);

	/* create the un-connected socket */
	if (!symmetric) {
		usock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (usock==-1) {
			perror("unconnected UDP socket creation failed");
			exit_code(2);
		}
		if (bind( usock, (struct sockaddr *) &addr, sizeof(addr) )==-1) {
			perror("unconnected UDP socket binding failed");
			exit_code(2);
		}
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

		if (!symmetric)
			addr.sin_port = htons((short)0);
		if (bind( csock, (struct sockaddr *) &addr, sizeof(addr) )==-1) {
			perror("connected UDP socket binding failed");
			exit_code(2);
		}
#ifdef RAW_SUPPORT
	}
#endif

	/* for the via line we need our listening port number */
	if (lport==0){
		memset(&addr, 0, sizeof(addr));
		slen=sizeof(addr);
		if (symmetric)
			getsockname(csock, (struct sockaddr *)&addr, &slen);
		else
			getsockname(usock, (struct sockaddr *)&addr, &slen);
		lport=ntohs(addr.sin_port);
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
	regcomp(&replyexp, "^SIP/[0-9]\\.[0-9] [1-6][0-9][0-9]", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE); 
	regcomp(&proexp, "^SIP/[0-9]\\.[0-9] 1[0-9][0-9] ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE); 
	regcomp(&okexp, "^SIP/[0-9]\\.[0-9] 2[0-9][0-9] ", 
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
		//cseqcmp=1;
	}
	else if (trace == 1){
		/* for trace we need some spezial initis */
		if (maxforw!=-1)
			nretries=maxforw;
		else
			nretries=255;
		namebeg=1;
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
					"request length\n");
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
			set_maxforw(buff, maxforw);
		if(via_ins == 1)
			add_via(buff);
	}

	request = buff;

	set_target(&addr, address, rport, csock);

		/* here we go for the number of nretries which strongly depends on the 
		   mode */
		for (i = 0; i <= nretries; i++)
		{
			before_sending();

			if (sleep_ms == -2) {
				rand_tmp = rand();
				sleep_ms_s.tv_sec = rand_tmp / 1000;
				sleep_ms_s.tv_nsec = (rand_tmp % 1000) * 1000;
			}

			send_message(request, (struct sockaddr *)&addr);

			/* in flood we are only interested in sending so skip the rest */
			if (flood == 0) {
				ret = recv_message(&buff2[0], sizeof(buff2));
				if(ret > 0)
				{
					reply = &buff2[0];
					/* send ACK for non-provisional reply on INVITE */
					if ((strncmp(request, "INVITE", 6)==0) && 
							(regexec(&replyexp, reply, 0, 0, 0) == REG_NOERROR) && 
							(regexec(&proexp, reply, 0, 0, 0) == REG_NOMATCH)) { 
						build_ack(request, reply, ack);
						/* lets fire the ACK to the server */
						send_message(ack, (struct sockaddr *)&addr);
					}
					/* check for old CSeq => ignore retransmission */
					//if (usrloc == 0 && invite == 0 && message == 0)
					//	cseqcmp = namebeg;
					cseqtmp = cseq(reply);
					if ((0 < cseqtmp) && (cseqtmp < cseq_counter)) {
						if (verbose>0)
							printf("ignoring retransmission\n");
						retrans_r_c++;
						dontsend = 1;
						continue;
					}
					else if (regexec(&authexp, reply, 0, 0, 0) == REG_NOERROR) {
						if (!username) {
							printf("%s\nerror: received 401 but cannot "
								"authentication without a username\n", reply);
							exit_code(2);
						}
						/* prevents a strange error */
						regcomp(&authexp, "^SIP/[0-9]\\.[0-9] 40[17] ", 
							REG_EXTENDED|REG_NOSUB|REG_ICASE);
						insert_auth(request, reply);
						if (verbose > 2)
							printf("\nreceived:\n%s\n", reply);
						new_transaction(buff);
						continue;
					} /* if auth...*/
					/* lets see if received a redirect */
					if (redirects == 1 && regexec(&redexp, reply, 0, 0, 0) == REG_NOERROR) {
						handle_3xx(&addr);
					} /* if redircts... */
					else if (trace == 1) {
						trace_reply();
					} /* if trace ... */
					else if (usrloc == 1||invite == 1||message == 1) {
						if (regexec(&proexp, reply, 0, 0, 0) == REG_NOERROR) {
							if (verbose > 2)
								printf("\nignoring provisional "
									"response\n");
							retryAfter = SIP_T2;
							dontsend = 1;
						}
						else {
						switch (usrlocstep) {
							case REG_REP:
								/* we have sent a register and look 
								   at the response now */
								if (regexec(&okexp, reply, 0, 0, 0) == REG_NOERROR) {
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
									if ( ((float)rem_rand/RAND_MAX)*100 > rand_rem) {
										namebeg++;
										create_msg(buff, REQ_REG);
										cseq_counter++;
									}
									else {
										/* to prevent only removing of low
										   user numbers new random number*/
										rem_rand = rand();
										rem_namebeg = namebeg;
										namebeg = ((float)rem_rand/RAND_MAX)
													* namebeg;
										cseq_counter++;
										trashchar=cseq_counter;
										create_msg(buff, REQ_REM);
										usrlocstep=UNREG_REP;
									}
								}
								else if (invite == 1) {
									create_msg(buff, REQ_INV);
									cseq_counter++;
									usrlocstep=INV_RECV;
								}
								else if (message == 1) {
									create_msg(buff, REQ_MES);
									cseq_counter++;
									usrlocstep=MES_RECV;
								}
								if (sleep_ms != 0) {
									nanosleep(&sleep_ms_s, &sleep_rem);
								}
								break;
							case INV_RECV:
								/* see if we received our invite */
								if (!STRNCASECMP(reply, messusern, 
									strlen(messusern))) {
									if (verbose > 1)
										printf("\t\treceived invite\n");
									if (verbose > 2)
										printf("\n%s\n", reply);
									cpy_vias(reply, confirm);
									cpy_to(reply, confirm);
									strcpy(buff, confirm);
									build_ack(request, confirm, ack);
									strcpy(request, confirm);
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
								if (STRNCASECMP(reply, INV_STR, INV_STR_LEN)==0) {
									if (verbose>0)
										printf("ignoring INVITE "
											"retransmission\n");
									retrans_r_c++;
									dontsend=1;
									continue;
								}
								if (regexec(&okexp, reply, 0, 0, 0) == REG_NOERROR) {
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
									sprintf(messusern, "%s sip:sipsak_conf", ACK_STR);
								if (STRNCASECMP(reply, messusern, 
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
										if (((float)rem_rand/RAND_MAX) * 100 > rand_rem) {
											namebeg++;
											create_msg(buff, REQ_REG);
											cseq_counter+=2;
											usrlocstep=REG_REP;
										}
										else {
											/* to prevent only removing of low
											   user numbers new random number*/
											rem_rand = rand();
											rem_namebeg = namebeg;
											namebeg = ((float)rem_rand/RAND_MAX)
														* namebeg;
											cseq_counter++;
											trashchar=cseq_counter;
											create_msg(buff, REQ_REM);
											usrlocstep=UNREG_REP;
										}
									}
									else {
										namebeg++;
										create_msg(buff, REQ_INV);
										cseq_counter+=3;
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
								if (!STRNCASECMP(reply, messusern, 
									strlen(messusern))) {
									if (verbose > 1) {
										crlf=STRCASESTR(reply, "\r\n\r\n");
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
								if (STRNCASECMP(reply, MES_STR, MES_STR_LEN)==0) {
									if (verbose>0)
										printf("ignoring MESSAGE "
											"retransmission\n");
									retrans_r_c++;
									dontsend=1;
									continue;
								}
								if (regexec(&okexp, reply, 0, 0, 0) == REG_NOERROR) {
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
										if (((float)rem_rand/RAND_MAX) * 100 > rand_rem) {
											namebeg++;
											create_msg(buff, REQ_REG);
											cseq_counter+=2;
											usrlocstep=REG_REP;
										}
										else {
											/* to prevent only removing of low
											   user numbers new random number*/
											rem_rand = rand();
											rem_namebeg = namebeg;
											namebeg = ((float)rem_rand/RAND_MAX)
														* namebeg;
											cseq_counter++;
											trashchar=cseq_counter;
											create_msg(buff, REQ_REM);
											usrlocstep=UNREG_REP;
										}
									}
									else {
										namebeg++;
										create_msg(buff, REQ_MES);
										cseq_counter+=3;
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
								if (STRNCASECMP(reply, MES_STR, MES_STR_LEN)==0) {
									if (verbose>0)
										printf("ignoring MESSAGE "
											"retransmission\n");
									retrans_r_c++;
									dontsend=1;
									continue;
								}
								if (regexec(&okexp, reply, 0, 0, 0) == REG_NOERROR) {
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
									cseq_counter++;
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
						handle_randtrash();
					}
					else {
						handle_default();
					} /* redirect, auth, and modes */
				} /* ret > 0 */
				else if (ret == -1) { // we did not got anything back, send again
					continue;
				}
				else {
					if (usrloc == 1)
						printf("failed\n");
					perror("socket error");
					exit_code(3);
				}
			} /* !flood */
			else {
				if (send_counter == 1)
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

	if (randtrash == 1)
		exit_code(0);
	printf("** give up retransmissioning....\n");
	if (retrans_r_c>0 && (verbose > 1))
		printf("%i retransmissions received during test\n", retrans_r_c);
	if (retrans_s_c>0 && (verbose > 1))
		printf("sent %i retransmissions during test\n", retrans_s_c);
	exit_code(3);
}
