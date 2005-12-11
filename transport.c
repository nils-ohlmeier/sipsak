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
#include "sipsak.h"

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
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#include "transport.h"
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

#include "exit_code.h"
#include "helper.h"
#include "header_f.h"

#ifdef RAW_SUPPORT
int rawsock;
#endif

void create_sockets(struct sipsak_con_data *cd) {
	socklen_t slen;

	memset(&(cd->adr), 0, sizeof(struct sockaddr_in));
	cd->adr.sin_family = AF_INET;
	cd->adr.sin_addr.s_addr = htonl( INADDR_ANY);
	cd->adr.sin_port = htons((short)lport);

	if (transport == SIP_UDP_TRANSPORT) {
		/* create the un-connected socket */
		if (!symmetric) {
			cd->usock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (cd->usock==-1) {
				perror("unconnected UDP socket creation failed");
				exit_code(2);
			}
			if (bind(cd->usock, (struct sockaddr *) &(cd->adr), sizeof(struct sockaddr_in) )==-1) {
				perror("unconnected UDP socket binding failed");
				exit_code(2);
			}
		}


#ifdef RAW_SUPPORT
		/* try to create the raw socket */
		rawsock = (int)socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (rawsock==-1) {
			if (verbose>1)
				fprintf(stderr, "warning: need raw socket (root privileges) to receive all ICMP errors\n");
#endif
			/* create the connected socket as a primitve alternative to the 
			   raw socket*/
			cd->csock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (cd->csock==-1) {
				perror("connected UDP socket creation failed");
				exit_code(2);
			}

			if (!symmetric)
				cd->adr.sin_port = htons((short)0);
			if (bind(cd->csock, (struct sockaddr *) &(cd->adr), sizeof(struct sockaddr_in) )==-1) {
				perror("connected UDP socket binding failed");
				exit_code(2);
			}
#ifdef RAW_SUPPORT
		}
		else if (symmetric) {
			cd->csock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (cd->csock==-1) {
				perror("connected UDP socket creation failed");
				exit_code(2);
			}
			if (bind(cd->csock, (struct sockaddr *) &(cd->adr), sizeof(struct sockaddr_in) )==-1) {
				perror("connected UDP socket binding failed");
				exit_code(2);
			}
		}
#endif
	}
	else {
		cd->csock = (int)socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (cd->csock==-1) {
			perror("TCP socket creation failed");
			exit_code(2);
		}
		if (bind(cd->csock, (struct sockaddr *) &(cd->adr), sizeof(struct sockaddr_in) )==-1) {
			perror("TCP socket binding failed");
			exit_code(2);
		}
	}

	/* for the via line we need our listening port number */
	if (lport==0){
		memset(&(cd->adr), 0, sizeof(struct sockaddr_in));
		slen=sizeof(struct sockaddr_in);
		if (symmetric || transport != SIP_UDP_TRANSPORT)
			getsockname(cd->csock, (struct sockaddr *) &(cd->adr), &slen);
		else
			getsockname(cd->usock, (struct sockaddr *) &(cd->adr), &slen);
		lport=ntohs(cd->adr.sin_port);
	}
}

void send_message(char* mes, struct sipsak_con_data *cd,
			struct sipsak_counter *sc, struct sipsak_sr_time *srt) {
	struct timezone tz;
	int ret;

	if (cd->dontsend == 0) {
		if (verbose > 2) {
			printf("\nrequest:\n%s", mes);
		}
		/* lets fire the request to the server and store when we did */
		if (cd->csock == -1) {
#ifdef DEBUG
			printf("\nusing un-connected socket for sending\n");
#endif
			ret = sendto(cd->usock, mes, strlen(mes), 0, (struct sockaddr *) &(cd->adr), sizeof(struct sockaddr));
		}
		else {
#ifdef DEBUG
			printf("\nusing connected socket for sending\n");
#endif
			ret = send(cd->csock, mes, strlen(mes), 0);
		}
		(void)gettimeofday(&(srt->sendtime), &tz);
		if (ret==-1) {
			if (verbose)
				printf("\n");
			perror("send failure");
			exit_code(2);
		}
#ifdef HAVE_INET_NTOP
		if (verbose > 2) {
			printf("\nsend to: %s:%s:%i\n", transport_str, target_dot, rport);
    }
#endif
		sc->send_counter++;
	}
	else {
		cd->dontsend = 0;
	}
}

void check_socket_error(int socket, int size) {
	struct pollfd sockerr;
	int ret = 0;

	/* lets see if we at least received an icmp error */
	sockerr.fd=socket;
	sockerr.events=POLLERR;
	ret = poll(&sockerr, 1, 10);
	if (ret==1) {
		if (sockerr.revents && POLLERR) {
			recvfrom(socket, recv, size, 0, NULL, 0);
			if (verbose)
				printf("\n");
			perror("send failure");
			if (randtrash == 1) 
				printf ("last message before send failure:\n%s\n", req);
			exit_code(3);
		}
	}
}

int check_for_message(char *recv, int size, struct sipsak_con_data *cd,
			struct sipsak_sr_time *srt, struct sipsak_counter *count,
			struct sipsak_delay *sd) {
	fd_set	fd;
	struct timezone tz;
	struct timeval tv;
	double senddiff;
	int ret = 0;

	if (cd->dontrecv == 0) {
		/* set the timeout and wait for a response */
		tv.tv_sec = sd->retryAfter/1000;
		tv.tv_usec = (sd->retryAfter % 1000) * 1000;

		FD_ZERO(&fd);
		if (cd->usock != -1)
			FD_SET(cd->usock, &fd); 
		if (cd->csock != -1)
			FD_SET(cd->csock, &fd); 
#ifdef RAW_SUPPORT
		if (rawsock != -1)
			FD_SET(rawsock, &fd); 
#endif

		ret = select(FD_SETSIZE, &fd, NULL, NULL, &tv);
		(void)gettimeofday(&(srt->recvtime), &tz);
	}
	else {
		cd->dontrecv = 0;
	}

	/* store the time of our first send */
	if (count->send_counter==1) {
		memcpy(&(srt->firstsendt), &(srt->sendtime), sizeof(struct timeval));
	}
	if (sd->retryAfter == SIP_T1) {
		memcpy(&(srt->starttime), &(srt->sendtime), sizeof(struct timeval));
	}
	if (ret == 0)
	{
		/* lets see if we at least received an icmp error */
		if (cd->csock == -1) 
			check_socket_error(cd->usock, size);
		else
			check_socket_error(cd->csock, size);
		/* printout that we did not received anything */
		if (trace == 1) {
			printf("%i: timeout after %i ms\n", namebeg, sd->retryAfter);
		}
		else if (usrloc == 1||invite == 1||message == 1) {
			printf("timeout after %i ms\n", sd->retryAfter);
		}
		else if (verbose>0) 
			printf("** timeout after %i ms**\n", sd->retryAfter);
		if (randtrash == 1) {
			printf("did not get a response on this request:\n%s\n", req);
			if (cseq_counter < nameend) {
				if (count->randretrys == 2) {
					printf("sended the following message three "
							"times without getting a response:\n%s\n"
							"give up further retransmissions...\n", req);
					exit_code(3);
				}
				else {
					printf("resending it without additional "
							"random changes...\n\n");
					(count->randretrys)++;
				}
			}
		}
		senddiff = deltaT(&(srt->starttime), &(srt->recvtime));
		if (senddiff > (float)64 * (float)SIP_T1) {
			if (timing == 0) {
				if (verbose>0)
					printf("*** giving up, no final response after %.3f ms\n", senddiff);
				exit_code(3);
			}
			else {
				timing--;
				count->run++;
				sd->all_delay += senddiff;
				sd->big_delay = senddiff;
				new_transaction(req);
				sd->retryAfter = SIP_T1;
				if (timing == 0) {
					printf("%.3f/%.3f/%.3f ms\n", sd->small_delay, sd->all_delay / count->run, sd->big_delay);
					exit_code(3);
				}
			}
		}
		else {
			/* set retry time according to RFC3261 */
			if ((inv_trans) || (sd->retryAfter *2 < SIP_T2)) {
				sd->retryAfter = sd->retryAfter * 2;
			}
			else {
				sd->retryAfter = SIP_T2;
			}
		}
		(count->retrans_s_c)++;
		if (srt->delaytime.tv_sec == 0)
			memcpy(&(srt->delaytime), &(srt->sendtime), sizeof(struct timeval));
		/* if we did not exit until here lets try another send */
		return -1;
	}
	else if ( ret == -1 ) {
		perror("select error");
		exit_code(2);
	}
	else if (((cd->usock != -1) && FD_ISSET(cd->usock, &fd)) || ((cd->csock != -1) && FD_ISSET(cd->csock, &fd))) {
		if ((cd->usock != -1) && FD_ISSET(cd->usock, &fd))
			ret = cd->usock;
		else if ((cd->csock != -1) && FD_ISSET(cd->csock, &fd))
			ret = cd->csock;
		else {
			printf("unable to determine the socket which received something\n");
			exit_code(2);
		}
		/* no timeout, no error ... something has happened :-) */
	 	if (trace == 0 && usrloc ==0 && invite == 0 && message == 0 && randtrash == 0 && (verbose > 1))
			printf ("\nmessage received");
	}
#ifdef RAW_SUPPORT
	else if ((rawsock != -1) && FD_ISSET(rawsock, &fd)) {
		if (verbose > 1)
			printf("\nreceived ICMP message");
		ret = rawsock;
	}
#endif
	else {
		printf("\nselect returned succesfuly, nothing received\n");
		return -1;
	}
	return ret;
}

int complete_mes(char *mes, int size) {
	int cl = 0, headers = 0, len = 0;
	char *tmp = NULL;

	cl = get_cl(mes);
#ifdef DEBUG
	printf("CL: %i\n", cl);
#endif
	if (cl < 0){
		if (verbose > 0)
			printf("missing CL header; waiting for more bytes...\n");
		return 0;
	}
	tmp = get_body(mes);
#ifdef DEBUG
	printf("body: '%s'\n", tmp);
#endif
	headers = tmp - mes;
#ifdef DEBUG
	printf("length: %i, headers: %i\n", size, headers);
#endif
	len = headers + cl;
	if (len == size) {
		if (verbose > 0)
			printf("message is complete\n");
		return 1;
	}
	else if (len > size) {
		if (verbose > 0)
			printf("waiting for more bytes...\n");
		return 0;
	}
	else {
		/* we received more then the sender claims to sent
		 * for now we treat this as a complete message
		 * FIXME: should we store the extra bytes in a buffer and
		 *        truncate the message at the calculated length !? */
		if (verbose > 0)
			printf("received too much bytes...\n");
		return 1;
	}
}

int recv_message(char *buf, int size, int inv_trans, 
			struct sipsak_delay *sd, struct sipsak_sr_time *srt,
			struct sipsak_counter *count, struct sipsak_con_data *cd,
			struct sipsak_regexp *reg) {
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

	if (cd->buf_tmp) {
		buf = cd->buf_tmp;
		size = size - cd->buf_tmp_size;
	}
	sock = check_for_message(buf, size, cd, srt, count, sd);
	if (sock <= 1) {
		return -1;
	}
#ifdef RAW_SUPPORT
	if (sock != rawsock) {
#else
	else {
#endif
		check_socket_error(sock, size);
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
			return -2;
		}
		else if (icmp_len < 36) {
			if (verbose > 1)
				printf(": ignoring (ICMP message too short to contain IP and UDP header)\n");
			return -2;
		}
		s_ip_hdr = (struct ip *) ((char *)icmp_hdr + 8);
		s_ip_len = s_ip_hdr->ip_hl << 2;
		if (s_ip_hdr->ip_p == IPPROTO_UDP) {
			udp_hdr = (struct udphdr *) ((char *)s_ip_hdr + s_ip_len);
			srcport = ntohs(udp_hdr->uh_sport);
			dstport = ntohs(udp_hdr->uh_dport);
#ifdef DEBUG
			printf("\nlport: %i, rport: %i\n", lport, rport);
#endif
			if ((srcport == lport) && (dstport == rport)) {
				printf(" (type: %u, code: %u)", icmp_hdr->icmp_type, icmp_hdr->icmp_code);
#ifdef HAVE_INET_NTOP
				if (inet_ntop(AF_INET, &faddr.sin_addr, &source_dot[0], INET_ADDRSTRLEN) != NULL)
					printf(": from %s\n", source_dot);
				else
					printf("\n");
#else
				printf("\n");
#endif // HAVE_INET_NTOP
				exit_code(3);
			}
			else {
				if (verbose > 2)
					printf(": ignoring (ICMP message does not match used ports)\n");
				return -2;
			}
		}
		else {
			if (verbose > 1)
				printf(": ignoring (ICMP data is not a UDP packet)\n");
			return -2;
		}
	}
#endif // RAW_SUPPORT
	if (ret > 0) {
		*(buf+ ret) = '\0';
		if (transport != SIP_UDP_TRANSPORT) {
			if (verbose > 0)
				printf("\nchecking message for completness...\n");
			if (complete_mes(buf, ret) == 1) {
				cd->buf_tmp = NULL;
				ret += cd->buf_tmp_size;
				cd->buf_tmp_size = 0;
			}
			else {
				if (cd->buf_tmp) {
					cd->buf_tmp += ret;
					cd->buf_tmp_size += ret;
				}
				else {
					cd->buf_tmp = buf + ret;
					cd->buf_tmp_size = ret;
				}
				cd->dontsend = 1;
				ret = -1;
			}
		}
		/* store the biggest delay if one occured */
		if (srt->delaytime.tv_sec != 0) {
			tmp_delay = deltaT(&(srt->delaytime), &(srt->recvtime));
			if (tmp_delay > sd->big_delay)
				sd->big_delay = tmp_delay;
			if ((sd->small_delay == 0) || (tmp_delay < sd->small_delay))
				sd->small_delay = tmp_delay;
			srt->delaytime.tv_sec = 0;
			srt->delaytime.tv_usec = 0;
		}
		if (timing > 0) {
			tmp_delay = deltaT(&(srt->sendtime), &(srt->recvtime));
			if (tmp_delay > sd->big_delay)
				sd->big_delay = tmp_delay;
			if ((sd->small_delay == 0) || (tmp_delay < sd->small_delay))
				sd->small_delay = tmp_delay;
			sd->all_delay += tmp_delay;
		}
#ifdef HAVE_INET_NTOP
		if ((verbose > 2) && (getpeername(sock, (struct sockaddr *)&peer_adr, &psize) == 0) && (inet_ntop(peer_adr.sin_family, &peer_adr.sin_addr, &source_dot[0], INET_ADDRSTRLEN) != NULL)) {
			printf("\nreceived from: %s:%s:%i\n", transport_str, 
						source_dot, ntohs(peer_adr.sin_port));
		}
		else if (verbose > 1 && trace == 0 && usrloc == 0)
			printf(":\n");
#else
		if (trace == 0 && usrloc == 0)
			printf(":\n");
#endif // HAVE_INET_NTOP
		if (!inv_trans && ret > 0 && (regexec(&(reg->proexp), buf, 0, 0, 0) != REG_NOERROR)) {
			sd->retryAfter = SIP_T1;
		}
	}
	else {
		check_socket_error(sock, size);
		printf("nothing received, select returned error\n");
		exit_code(2);
	}
	return ret;
}

/* clears the given sockaddr, fills it with the given data and if a
 * socket is given connects the socket to the new target */
int set_target(struct sockaddr_in *adr, unsigned long target, int port, int socket, int connected) {
	if (socket != -1 && transport != SIP_UDP_TRANSPORT && connected) {
		if (shutdown(socket, SHUT_RDWR) != 0) {
			perror("error while shutting down socket");
		}
	}

	memset(adr, 0, sizeof(struct sockaddr_in));
	adr->sin_addr.s_addr = target;
	adr->sin_port = htons((short)port);
	adr->sin_family = AF_INET;

#ifdef HAVE_INET_NTOP
	inet_ntop(adr->sin_family, &adr->sin_addr, &target_dot[0], INET_ADDRSTRLEN);
#endif

	if (socket != -1) {
		if (connect(socket, (struct sockaddr *)adr, sizeof(struct sockaddr_in)) == -1) {
			perror("connecting socket failed");
			exit_code(2);
		}
	}
	return 1;
}

