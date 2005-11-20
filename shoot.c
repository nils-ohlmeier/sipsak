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
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "shoot.h"

#include "request.h"   
#include "auth.h"
#include "header_f.h"
#include "helper.h"
#include "exit_code.h"
#include "transport.h"

#ifndef DEFAULT_RETRYS
#define DEFAULT_RETRYS 5
#endif

#ifndef DEFAULT_TIMEOUT
#define DEFAULT_TIMEOUT 5000
#endif

char *usern;

enum usteps usrlocstep;

struct sipsak_regexp regexps;

struct sipsak_sr_time times;
struct sipsak_con_data cdata;
struct sipsak_counter counters;
struct sipsak_delay delays;

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

/* just print the given username and number into the first buffer and
 * append an @ char */
static inline void create_usern(char *target, char *username, int number)
{
	if (number >= 0) {
		sprintf(target, "%s%i@", username, number);
	}
	else {
		sprintf(target, "%s@", username);
	}
}

/* tries to take care of a redirection */
void handle_3xx(struct sockaddr_in *tadr)
{
	char *uscheme, *uuser, *uhost, *contact;

	printf("** received redirect ");
	if (warning_ext == 1) {
		printf("from ");
		warning_extract(rec);
		printf("\n");
	}
	else
		printf("\n");
	/* we'll try to handle 301 and 302 here, other 3xx are to complex */
	regcomp(&(regexps.redexp), "^SIP/[0-9]\\.[0-9] 30[125] ", 
			REG_EXTENDED|REG_NOSUB|REG_ICASE);
	if (regexec(&(regexps.redexp), rec, 0, 0, 0) == REG_NOERROR) {
		/* try to find the contact in the redirect */
		contact = uri_from_contact(rec);
		if (contact==NULL) {
			fprintf(stderr, "error: cannot find Contact in this "
				"redirect:\n%s\n", rec);
			exit_code(3);
		}
		/* correct our request */
		uri_replace(req, contact);
		new_transaction(req);
		/* extract the needed information*/
		rport = 0;
		address = 0;
		parse_uri(contact, &uscheme, &uuser, &uhost, &rport);
		if (!rport)
			address = getsrvadr(uhost, &rport, &transport);
		if (!address)
			address = getaddress(uhost);
		if (!address){
			fprintf(stderr, "error: cannot determine host "
					"address from Contact of redirect:"
					"\n%s\n", rec);
			exit_code(2);
		}
		if (!rport) {
			rport = 5060;
		}
		free(contact);
		if (!outbound_proxy)
			cdata.connected = set_target(tadr, address, rport, cdata.csock, cdata.connected);
	}
	else {
		fprintf(stderr, "error: cannot handle this redirect:"
				"\n%s\n", rec);
		exit_code(2);
	}
}

/* takes care of replies in the trace route mode */
void trace_reply()
{
	char *contact;

	if (regexec(&(regexps.tmhexp), rec, 0, 0, 0) == REG_NOERROR) {
		/* we received 483 to many hops */
		printf("%i: ", namebeg);
		if (verbose > 2) {
			printf("(%.3f ms)\n%s\n", 
				deltaT(&(times.sendtime), &(times.recvtime)), rec);
		}
		else {
			warning_extract(rec);
			printf("(%.3f ms) ", deltaT(&(times.sendtime), &(times.recvtime)));
			print_message_line(rec);
		}
		namebeg++;
		cseq_counter++;
		create_msg(REQ_OPT, req, NULL, usern, cseq_counter);
		set_maxforw(req, namebeg);
		return;
	}
	else if (regexec(&(regexps.proexp), rec, 0, 0, 0) == REG_NOERROR) {
		/* we received a provisional response */
		printf("%i: ", namebeg);
		if (verbose > 2) {
			printf("(%.3f ms)\n%s\n", 
				deltaT(&(times.sendtime), &(times.recvtime)), rec);
		}
		else {
			warning_extract(rec);
			printf("(%.3f ms) ", deltaT(&(times.sendtime), &(times.recvtime)));
			print_message_line(rec);
		}
		delays.retryAfter = SIP_T2;
		cdata.dontsend=1;
		return;
	}
	else {
		/* anything else then 483 or provisional will
		   be treated as final */
		printf("%i: ", namebeg);
		warning_extract(rec);
		printf("(%.3f ms) ", deltaT(&(times.sendtime), &(times.recvtime)));
		print_message_line(rec);
		if ((contact = STRCASESTR(rec, CONT_STR)) != NULL ||
				(contact = STRCASESTR(rec, CONT_SHORT_STR)) != NULL) {
			if (*contact == '\n') {
				contact++;
			}
			printf("\t");
			print_message_line(contact);
		}
		else {
			printf("\twithout Contact header\n");
		}
		if (regexec(&(regexps.okexp), rec, 0, 0, 0) == REG_NOERROR)
			on_success(rec);
		else
			exit_code(1);
	}
}

/* takes care of replies in the default mode */
void handle_default()
{
	/* in the normal send and reply case anything other 
	   then 1xx will be treated as final response*/
	if (regexec(&(regexps.proexp), rec, 0, 0, 0) == REG_NOERROR) {
		if (verbose > 1) {
			printf("%s\n\n", rec);
			printf("** reply received ");
			if ((counters.send_counter == 1) || (STRNCASECMP(req, ACK_STR, ACK_STR_LEN) == 0)) {
				printf("after %.3f ms **\n", deltaT(&(times.firstsendt), &(times.recvtime)));
			}
			else {
				printf("%.3f ms after first send\n   and "
						"%.3f ms after last send **\n", deltaT(&(times.firstsendt), &(times.recvtime)), 
						deltaT(&(times.sendtime), &(times.recvtime)));
			}
			printf("   ");
			print_message_line(rec);
			printf("   provisional received; still"
					" waiting for a final response\n");
		}
		if (inv_trans) {
			delays.retryAfter = inv_final;
		}
		else {
			delays.retryAfter = SIP_T2;
		}
		cdata.dontsend = 1;
		return;
	}
	else {
		if (verbose > 1) {
			printf("%s\n\n", rec);
			printf("** reply received ");
			if ((counters.send_counter == 1) || (STRNCASECMP(req, ACK_STR, ACK_STR_LEN) == 0)){
				printf("after %.3f ms **\n", deltaT(&(times.firstsendt), &(times.recvtime)));
			}
			else {
				printf("%.3f ms after first send\n   and "
						"%.3f ms after last send **\n", deltaT(&(times.firstsendt), &(times.recvtime)), 
						deltaT(&(times.sendtime), &(times.recvtime)));
			}
			printf("   ");
			print_message_line(rec);
			printf("   final received\n");
		}
		else if (verbose>0) {
			printf("%s\n", rec);
		}
		else if (timing) {
			printf("%.3f ms\n", deltaT(&(times.firstsendt), &(times.recvtime)));
		}
		if (regexec(&(regexps.okexp), rec, 0, 0, 0) == REG_NOERROR) {
			on_success(rec);
		}
		else {
			exit_code(1);
		}
	}
}

/* takes care of replies in the readntrash mode */
void handle_randtrash()
{
	/* in randomzing trash we are expexting 4?? error codes
	   everything else should not be normal */
	if (regexec(&(regexps.errexp), rec, 0, 0, 0) == REG_NOERROR) {
		if (verbose > 2)
			printf("received:\n%s\n", rec);
		if (verbose > 1) {
			printf("received expected 4xx ");
			if (warning_ext == 1) {
				printf ("from ");
				warning_extract(rec);
				printf("\n");
			}
			else {
				printf("\n");
			}
		}
	}
	else {
		fprintf(stderr, "warning: did not received 4xx\n");
		if (verbose > 1) 
			printf("sended:\n%s\nreceived:\n%s\n", req, rec);
	}
	if (cseq_counter == nameend) {
		if (counters.randretrys == 0) {
			printf("random end reached. server survived :) respect!\n");
			exit_code(0);
		}
		else {
			printf("maximum sendings reached but did not "
				"get a response on this request:\n%s\n", req);
			exit_code(3);
		}
	}
	else {
		trash_random(req);
	}
}

/* takes care of replies in the usrloc mode */
void handle_usrloc()
{
	char *crlf;
	char ruri[11+12+20]; //FIXME: username length 20 should be dynamic

	if (regexec(&(regexps.proexp), rec, 0, 0, 0) == REG_NOERROR) {
		if (verbose > 2) {
			print_message_line(rec);
			printf("ignoring provisional response\n\n");
		}
		if (inv_trans) {
			delays.retryAfter = inv_final;
		}
		else {
			delays.retryAfter = SIP_T2;
		}
		cdata.dontsend = 1;
	}
	else {
		switch (usrlocstep) {
			case REG_REP:
				/* we have sent a register and look 
				   at the response now */
				if (regexec(&(regexps.okexp), rec, 0, 0, 0) == REG_NOERROR) {
					if (verbose > 1) {
						printf ("\tOK\n");
					}
					if (verbose > 2) {
						printf("\n%s\n", rec);
					}
				}
				else {
					fprintf(stderr, "received:\n%s\nerror: didn't "
									"received '200 OK' on register (see "
									"above). aborting\n", rec);
					exit_code(1);
				}
				if (invite == 0 && message == 0) {
					if (namebeg==nameend) {
						if (verbose>0)  {
							printf("\nAll usrloc tests"
										" completed successful.\nreceived"
										" last message %.3f ms after first"
										" request (test duration).\n", 
										deltaT(&(times.firstsendt), &(times.recvtime)));
						}
						if (delays.big_delay>0 && verbose>0) {
							printf("biggest delay between "
										"request and response was %.3f"
										" ms\n", delays.big_delay);
						}
						if (counters.retrans_r_c>0 && verbose>0) {
							printf("%i retransmission(s) received from server.\n", 
										counters.retrans_r_c);
						}
						if (counters.retrans_s_c>0 && verbose>0) {
							printf("%i time(s) the timeout of "
										"%i ms exceeded and request was"
										" retransmitted.\n", 
										counters.retrans_s_c, delays.retryAfter);
							if (counters.retrans_s_c > nagios_warn) {
												exit_code(4);
							}
						}
						if (timing) {
							printf("%.3f ms\n",
										deltaT(&(times.firstsendt), &(times.recvtime)));
						}
						on_success(rec);
					} /* namebeg == nameend */
					/* lets see if we deceid to remove a 
					   binding (case 6)*/
					if ( ((float)rand()/RAND_MAX)*100 > rand_rem) {
						namebeg++;
						cseq_counter++;
						create_usern(usern, username, namebeg);
						create_msg(REQ_REG, req, NULL, usern, cseq_counter);
					}
					else {
						/* to prevent only removing of low
						   user numbers new random number*/
						cseq_counter++;
						create_usern(usern, username, ((float)rand()/RAND_MAX) * namebeg);
						create_msg(REQ_REM, req, NULL, usern, cseq_counter);
						usrlocstep=UNREG_REP;
					}
				} /* invite == 0 && message == 0 */
				else if (invite == 1) {
					cseq_counter++;
					create_msg(REQ_INV, req, rep, usern, cseq_counter);
					inv_trans = 1;
					usrlocstep=INV_RECV;
				}
				else if (message == 1) {
					cseq_counter++;
					create_msg(REQ_MES, req, rep, usern, cseq_counter);
					inv_trans = 0;
					usrlocstep=MES_RECV;
				}
				break;
			case INV_RECV:
				/* see if we received our invite */
				sprintf(ruri, "%s sip:%s", INV_STR, usern);
				if (!STRNCASECMP(rec, ruri, strlen(ruri))) {
					if (verbose > 1) {
						printf("\t\treceived invite\n");
					}
					if (verbose > 2) {
						printf("\n%s\n", rec);
					}
					cpy_vias(rec, rep);
					cpy_rr(rec, rep, 0);
					swap_ptr(&req, &rep);
					usrlocstep=INV_OK_RECV;
					inv_trans = 0;
				}
				else {
					fprintf(stderr, "received:\n%s\nerror: did not "
								"received the INVITE that was sent "
								"(see above). aborting\n", rec);
					exit_code(1);
				}
				break;
			case INV_OK_RECV:
				/* did we received our ok ? */
				if (STRNCASECMP(rec, INV_STR, INV_STR_LEN)==0) {
					if (verbose>0) {
						printf("ignoring INVITE retransmission\n");
					}
					counters.retrans_r_c++;
					cdata.dontsend=1;
					return;
				}
				if (regexec(&(regexps.okexp), rec, 0, 0, 0) == REG_NOERROR) {
					if (verbose > 1) {
						printf("\t200 OK received\n");
					}
					if (verbose > 2) {
						printf("\n%s\n", rec);
					}
					/* ACK was send already earlier generically */
					usrlocstep=INV_ACK_RECV;
					cdata.dontsend=1;
				}
				else {
					fprintf(stderr, "received:\n%s\nerror: did not "
								"received the '200 OK' that was sent "
								"as the reply on the INVITE (see "
								"above). aborting\n", rec);
					exit_code(1);
				}
				break;
			case INV_ACK_RECV:
				/* did we received our ack */
				if (STRNCASECMP(rec, SIP200_STR, SIP200_STR_LEN)==0) {
					if (verbose>0) {
						printf("ignoring 200 OK retransmission\n");
					}
					counters.retrans_r_c++;
					cdata.dontsend=1;
					return;
				}
				sprintf(ruri, "%s sip:sipsak_conf@", ACK_STR);
				if (STRNCASECMP(rec, ruri, strlen(ruri))==0) {
					if (verbose > 1) {
						printf("\tACK received\n");
					}
					if (verbose > 2) {
						printf("\n%s\n", rec);
					}
					if (verbose>0 && nameend>0) {
						printf("usrloc for %s%i completed "
									"successful\n", username, namebeg);
					}
					else if (verbose>0) {
						printf("usrloc for %s completed successful\n", username);
					}
					if (namebeg==nameend) {
						if (verbose>0) {
							printf("\nAll usrloc tests completed "
										"successful.\nreceived last message"
										" %.3f ms after first request (test"
										" duration).\n", deltaT(&(times.firstsendt), &(times.recvtime)));
						}
						if (delays.big_delay>0) {
							printf("biggest delay between "
										"request and response was %.3f"
										" ms\n", delays.big_delay);
						}
						if (counters.retrans_r_c>0) {
							printf("%i retransmission(s) received from server.\n", 
										counters.retrans_r_c);
						}
						if (counters.retrans_s_c>0) {
							printf("%i time(s) the timeout of "
										"%i ms exceeded and request was"
										" retransmitted.\n", 
										counters.retrans_s_c, delays.retryAfter);
							if (counters.retrans_s_c > nagios_warn) {
								exit_code(4);
							}
						}
						on_success(rec);
					} /* namebeg == nameend */
					if (usrloc == 1) {
						/* lets see if we deceid to remove a 
						   binding (case 6)*/
						if (((float)rand()/RAND_MAX) * 100 > rand_rem) {
							namebeg++;
							cseq_counter++;
							create_usern(usern, username, namebeg);
							create_msg(REQ_REG, req, NULL, usern, cseq_counter);
							usrlocstep=REG_REP;
						}
						else {
							/* to prevent only removing of low
							   user numbers new random number*/
							cseq_counter++;
							create_usern(usern, username, ((float)rand()/RAND_MAX) * namebeg);
							create_msg(REQ_REM, req, NULL, usern, cseq_counter);
							usrlocstep=UNREG_REP;
						}
					} /* usrloc == 1 */
					else {
						namebeg++;
						cseq_counter++;
						create_usern(usern, username, namebeg);
						create_msg(REQ_INV, req, rep, usern, cseq_counter);
						inv_trans = 1;
						usrlocstep=INV_RECV;
					}
				} /* STRNCASECMP */
				else {
					fprintf(stderr, "received:\n%s\nerror: did not "
								"received the 'ACK' that was sent "
								"as the reply on the '200 OK' (see "
								"above). aborting\n", rec);
					exit_code(1);
				}
				break;
			case MES_RECV:
				/* we sent the message and look if its 
				   forwarded to us */
				sprintf(ruri, "%s sip:%s", MES_STR, usern);
				if (!STRNCASECMP(rec, ruri, strlen(ruri))) {
					if (verbose > 1) {
						crlf=STRCASESTR(rec, "\r\n\r\n");
						crlf=crlf+4;
						printf("  received message\n  '%s'\n", crlf);
					}
					if (verbose > 2) {
						printf("\n%s\n", rec);
					}
					cpy_vias(rec, rep);
					swap_ptr(&req, &rep);
					usrlocstep=MES_OK_RECV;
				}
				else {
					fprintf(stderr, "received:\n%s\nerror: did not "
								"received the 'MESSAGE' that was sent "
								"(see above). aborting\n", rec);
					exit_code(1);
				}
				break;
			case MES_OK_RECV:
				/* we sent our reply on the message and
				   look if this is also forwarded to us */
				if (STRNCASECMP(rec, MES_STR, MES_STR_LEN)==0) {
					if (verbose>0) {
						printf("ignoring MESSAGE retransmission\n");
					}
					counters.retrans_r_c++;
					cdata.dontsend=1;
					return;
				}
				if (regexec(&(regexps.okexp), rec, 0, 0, 0) == REG_NOERROR) {
					if (verbose > 1) {
						printf("  reply received\n\n");
					}
					else if (verbose>0 && nameend>0) {
						printf("usrloc for %s%i completed "
									"successful\n", username, namebeg);
					}
					else if (verbose>0) {
						printf("usrloc for %s completed successful\n", username);
					}
					if (namebeg==nameend) {
						if (verbose>0) {
							printf("\nAll usrloc tests completed "
										"successful.\nreceived last message"
										" %.3f ms after first request (test"
										" duration).\n", deltaT(&(times.firstsendt), &(times.recvtime)));
						}
						if (delays.big_delay>0) {
							printf("biggest delay between "
										"request and response was %.3f"
										" ms\n", delays.big_delay);
						}
						if (counters.retrans_r_c>0) {
							printf("%i retransmission(s) "
										"received from server.\n", 
											counters.retrans_r_c);
						}
						if (counters.retrans_s_c>0) {
							printf("%i time(s) the timeout of "
										"%i ms exceeded and request was"
										" retransmitted.\n", 
										counters.retrans_s_c, delays.retryAfter);
							if (counters.retrans_s_c > nagios_warn) {
								exit_code(4);
							}
						}
						on_success(rec);
					} /* namebeg == nameend */
					if (usrloc == 1) {
						/* lets see if we deceid to remove a 
						   binding (case 6)*/
						if (((float)rand()/RAND_MAX) * 100 > rand_rem) {
							namebeg++;
							cseq_counter++;
							create_usern(usern, username, namebeg);
							create_msg(REQ_REG, req, NULL, usern, cseq_counter);
							usrlocstep=REG_REP;
						}
						else {
							/* to prevent only removing of low
							   user numbers new random number*/
							cseq_counter++;
							create_usern(usern, username, ((float)rand()/RAND_MAX) * namebeg);
							create_msg(REQ_REM, req, NULL, usern, cseq_counter);
							usrlocstep=UNREG_REP;
						}
					} /* usrloc == 1 */
					else {
						namebeg++;
						cseq_counter++;
						create_usern(usern, username, namebeg);
						create_msg(REQ_MES, req, NULL, usern, cseq_counter);
						usrlocstep=MES_RECV;
					}
				} /* regexec */
				else {
					if (verbose>0) {
						if (mes_body) {
							fprintf(stderr, "received:\n%s\nerror: did"
										" not received 200 for the "
										"MESSAGE (see above)\n",
										rec);
						}
						else {
							fprintf(stderr, "received:\n%s\nerror: did"
										" not received the '200 OK' "
										"that was sent as the reply on"
										" the MESSAGE (see above). "
										"aborting\n", rec);
						}
					}
					exit_code(1);
				}
				break;
			case UNREG_REP:
				if (STRNCASECMP(rec, MES_STR, MES_STR_LEN)==0) {
					if (verbose>0) {
						printf("ignoring MESSAGE retransmission\n");
					}
					counters.retrans_r_c++;
					cdata.dontsend=1;
					return;
				}
				if (regexec(&(regexps.okexp), rec, 0, 0, 0) == REG_NOERROR) {
					if (verbose > 1) {
						printf("   OK\n\n");
					}
					else if (verbose>0 && nameend>0) {
						printf("Binding removal for %s%i "
									"successful\n", username, namebeg);
					}
					else if (verbose>0) {
						printf("Binding removal for %s successful\n", username);
					}
					namebeg++;
					cseq_counter++;
					create_usern(usern, username, namebeg);
					create_msg(REQ_REG, req, NULL, usern, cseq_counter);
					usrlocstep=REG_REP;
				}
				else {
					fprintf(stderr, "received:\n%s\nerror: did not "
								"received the expected 200 on the "
								"remove bindings request for %s%i (see"
								" above). aborting\n", rec, username, 
								namebeg);
					exit_code(1);
				}
				break;
			default:
				fprintf(stderr, "error: unknown step in usrloc\n");
				exit_code(2);
				break;
		} /* switch */
	} /* regexec proexp */
}

void before_sending()
{
	/* some initial output */
	if ((usrloc == 1||invite == 1||message == 1) && (verbose > 1) && (cdata.dontsend == 0)) {
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
		printf("flooding message number %i\n", namebeg);
	}
	else if (randtrash == 1 && verbose > 0) {
		printf("message with %i randomized chars\n", cseq_counter);
		if (verbose > 2)
			printf("request:\n%s\n", req);
	}
}

/* this is the main function with the loops and modes */
void shoot(char *buf, int buff_size)
{
	struct sockaddr_in	daddr;
	struct timespec sleep_ms_s, sleep_rem;
	int ret, cseqtmp, rand_tmp;
	char buf2[BUFSIZE], buf3[BUFSIZE], lport_str[LPORT_STR_LEN];

	/* delays.retryAfter = DEFAULT_TIMEOUT; */
	if (transport == SIP_UDP_TRANSPORT) {
		delays.retryAfter = SIP_T1;
	}
	else {
		delays.retryAfter = inv_final;
	}
	inv_trans = 0;
	cseq_counter = 1;
	usrlocstep = REG_REP;

	/* initalize local vars */
	cdata.dontsend=cdata.dontrecv=counters.retrans_r_c=counters.retrans_s_c= 0;
	delays.big_delay=counters.send_counter= 0;
	times.delaytime.tv_sec = 0;
	times.delaytime.tv_usec = 0;
	usern = NULL;
	/* initialize local arrays */
	memset(buf2, 0, BUFSIZE);
	memset(buf3, 0, BUFSIZE);
	memset(lport_str, 0, LPORT_STR_LEN);

	cdata.csock = cdata.usock = -1;
	cdata.connected = 0;
	cdata.buf_tmp = NULL;
	cdata.buf_tmp_size = 0;

	memset(&(times.sendtime), 0, sizeof(times.sendtime));
	memset(&(times.recvtime), 0, sizeof(times.recvtime));
	memset(&(times.firstsendt), 0, sizeof(times.firstsendt));
	memset(&(times.starttime), 0, sizeof(times.starttime));
	memset(&(times.delaytime), 0, sizeof(times.delaytime));

	req = buf;
	rep = buf2;
	rec = buf3;

	create_sockets(&cdata);

	if (sleep_ms != 0) {
		if (sleep_ms == -2) {
			rand_tmp = rand();
			sleep_ms_s.tv_sec = rand_tmp / 1000;
			sleep_ms_s.tv_nsec = (rand_tmp % 1000) * 1000000;
		}
		else {
			sleep_ms_s.tv_sec = sleep_ms / 1000;
			sleep_ms_s.tv_nsec = (sleep_ms % 1000) * 1000000;
		}
	}

	if (replace_b == 1){
		replace_string(req, "$dsthost$", domainname);
		replace_string(req, "$srchost$", fqdn);
		sprintf(lport_str, "%i", lport);
		replace_string(req, "$port$", lport_str);
		if (username)
			replace_string(req, "$user$", username);
	}
	if (replace_str)
		replace_string(req, "$replace$", replace_str);

	/* set all regular expression to simplfy the result code indetification */
	regcomp(&(regexps.replyexp), "^SIP/[0-9]\\.[0-9] [1-6][0-9][0-9]", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE); 
	regcomp(&(regexps.proexp), "^SIP/[0-9]\\.[0-9] 1[0-9][0-9] ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE); 
	regcomp(&(regexps.okexp), "^SIP/[0-9]\\.[0-9] 2[0-9][0-9] ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE); 
	regcomp(&(regexps.redexp), "^SIP/[0-9]\\.[0-9] 3[0-9][0-9] ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE);
	regcomp(&(regexps.authexp), "^SIP/[0-9]\\.[0-9] 40[17] ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE);
	regcomp(&(regexps.errexp), "^SIP/[0-9]\\.[0-9] 4[0-9][0-9] ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE); 
	regcomp(&(regexps.tmhexp), "^SIP/[0-9]\\.[0-9] 483 ", 
		REG_EXTENDED|REG_NOSUB|REG_ICASE); 

	if (username) {
		if (nameend > 0) {
			usern = str_alloc(strlen(username) + 12);
			create_usern(usern, username, namebeg);
		}
		else {
			if (*(username + strlen(username) - 1) != '@') {
				usern = str_alloc(strlen(username) + 2);
				create_usern(usern, username, -1);
			}
			else {
				usern = username;
			}
		}
	}

	if (usrloc == 1||invite == 1||message == 1){
		/* calculate the number of required steps and create initial mes */
		if (usrloc == 1) {
			create_msg(REQ_REG, req, NULL, usern, cseq_counter);
			usrlocstep=REG_REP;
		}
		else if (invite == 1) {
			create_msg(REQ_INV, req, rep, usern, cseq_counter);
			inv_trans = 1;
			usrlocstep=INV_RECV;
		}
		else {
			create_msg(REQ_MES, req, rep, usern, cseq_counter);
			if (mes_body)
				usrlocstep=MES_OK_RECV;
			else
				usrlocstep=MES_RECV;
		}
	}
	else if (trace == 1){
		/* for trace we need some spezial initis */
		namebeg=0;
		create_msg(REQ_OPT, req, NULL, usern, cseq_counter);
		set_maxforw(req, namebeg);
	}
	else if (flood == 1){
		if (nameend<=0) nameend=INT_MAX;
		namebeg=1;
		create_msg(REQ_FLOOD, req, NULL, usern, cseq_counter);
	}
	else if (randtrash == 1){
		counters.randretrys=0;
		namebeg=1;
		create_msg(REQ_RAND, req, NULL, usern, cseq_counter);
		nameend=(int)strlen(req);
		if (trashchar == 1){
			if (trashchar < nameend)
				nameend=trashchar;
			else
				fprintf(stderr, "warning: number of trashed chars to big. setting to "
					"request length\n");
		}
		trash_random(req);
	}
	else {
		/* for none of the modes we also need some inits */
		if (file_b == 0) {
			namebeg=1;
			create_msg(REQ_OPT, req, NULL, usern, cseq_counter);
		}
		else {
			if (STRNCASECMP(req, INV_STR, INV_STR_LEN) == 0) {
				inv_trans = 1;
			}
			if(via_ins == 1)
				add_via(req);
		}
		/* delays.retryAfter = delays.retryAfter / 10; */
		if(maxforw!=-1)
			set_maxforw(req, maxforw);
	}

	cdata.connected = set_target(&daddr, address, rport, cdata.csock, cdata.connected);

	/* here we go until someone decides to exit */
	while(1) {
		before_sending();

		if (sleep_ms == -2) {
			rand_tmp = rand();
			sleep_ms_s.tv_sec = rand_tmp / 1000;
			sleep_ms_s.tv_nsec = (rand_tmp % 1000) * 1000;
		}
		if (sleep_ms != 0) {
			nanosleep(&sleep_ms_s, &sleep_rem);
		}

		send_message(req, &cdata, &counters, &times);

		/* in flood we are only interested in sending so skip the rest */
		if (flood == 0) {
			ret = recv_message(rec, BUFSIZE, inv_trans, &delays, &times,
						&counters, &cdata, &regexps);
			if(ret > 0)
			{
				if (usrlocstep == INV_OK_RECV) {
					swap_ptr(&rep, &req);
				}
				/* send ACK for non-provisional reply on INVITE */
				if ((STRNCASECMP(req, "INVITE", 6)==0) && 
						(regexec(&(regexps.replyexp), rec, 0, 0, 0) == REG_NOERROR) && 
						(regexec(&(regexps.proexp), rec, 0, 0, 0) == REG_NOMATCH)) { 
					build_ack(req, rec, rep, &regexps);
					cdata.dontsend = 0;
					inv_trans = 0;
					/* lets fire the ACK to the server */
					send_message(rep, &cdata, &counters, &times);
					inv_trans = 1;
				}
				/* check for old CSeq => ignore retransmission */
				cseqtmp = cseq(rec);
				if ((0 < cseqtmp) && (cseqtmp < cseq_counter)) {
					if (verbose>0) {
						printf("ignoring retransmission\n");
					}
					counters.retrans_r_c++;
					cdata.dontsend = 1;
					continue;
					}
				else if (regexec(&(regexps.authexp), rec, 0, 0, 0) == REG_NOERROR) {
					if (!username) {
						fprintf(stderr, "%s\nerror: received 401 but cannot "
							"authentication without a username\n", rec);
						exit_code(2);
					}
					/* prevents a strange error */
					regcomp(&(regexps.authexp), "^SIP/[0-9]\\.[0-9] 40[17] ", REG_EXTENDED|REG_NOSUB|REG_ICASE);
					insert_auth(req, rec);
					if (verbose > 2)
						printf("\nreceived:\n%s\n", rec);
					new_transaction(req);
					continue;
				} /* if auth...*/
				/* lets see if received a redirect */
				if (redirects == 1 && regexec(&(regexps.redexp), rec, 0, 0, 0) == REG_NOERROR) {
					handle_3xx(&daddr);
				} /* if redircts... */
				else if (trace == 1) {
					trace_reply();
				} /* if trace ... */
				else if (usrloc == 1||invite == 1||message == 1) {
					handle_usrloc();
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
			else if (ret == -2) { // we received non-matching ICMP
				cdata.dontsend = 1;
				continue;
			}
			else {
				if (usrloc == 1) {
					printf("failed\n");
				}
				perror("socket error");
				exit_code(3);
			}
		} /* !flood */
		else {
			if (counters.send_counter == 1) {
					memcpy(&(times.firstsendt), &(times.sendtime), sizeof(struct timeval));
			}
			if (namebeg==nameend) {
				printf("flood end reached\n");
				printf("it took %.3f ms seconds to send %i request.\n", 
						deltaT(&(times.firstsendt), &(times.sendtime)), namebeg);
				printf("we sent %f requests per second.\n", 
						(namebeg/(deltaT(&(times.firstsendt), &(times.sendtime)))*1000));
				exit_code(0);
			}
			namebeg++;
			cseq_counter++;
			create_msg(REQ_FLOOD, req, NULL, usern, cseq_counter);
		}
	} /* while 1 */

	/* this should never happen any more... */
	if (randtrash == 1) {
		exit_code(0);
	}
	printf("** give up retransmissioning....\n");
	if (counters.retrans_r_c>0 && (verbose > 1)) {
		printf("%i retransmissions received during test\n", counters.retrans_r_c);
	}
	if (counters.retrans_s_c>0 && (verbose > 1)) {
		printf("sent %i retransmissions during test\n", counters.retrans_s_c);
	}
	exit_code(3);
}
