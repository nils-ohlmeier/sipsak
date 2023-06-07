/*
 * Copyright (C) 2005-2022 Nils Ohlmeier
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
#include "../config.h"

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <stdlib.h>

int verbose = 99;

/* This entire test suite can only run if c-ares is installed */
#ifndef HAVE_CARES_H

void exit_code(int code, const char *function, const char *reason) {}

int main(void) {
	/* So tests can still run on a host without c-ares */
	return EXIT_SUCCESS;
}

#else
#ifndef HAVE_CHECK_H

void exit_code(int code, const char *function, const char *reason) {}

#include <stdio.h>
int main(void) {
	printf("check_dns: !!! missing check unit test framework !!!\n");
	return EXIT_FAILURE;
}

#else

#include <ares.h>
#include <check.h>

#define RUNNING_CHECK 1

void exit_code(int code, const char *function, const char *reason) {
	ck_abort_msg("Unexpected call to exit_code() with code %i at %s: %s", code, function, reason);
}

typedef struct srv_details srv_details;

struct srv_details {
	char *name;
	unsigned long ipaddr;
	int port;
	int priority;
	int weight;
	srv_details *next;
};

extern void got_dns_reply(void *arg, int status, int timeouts, unsigned char *abuf, int alen);
extern unsigned long process_srv_details(srv_details *list, int *port);

static unsigned long process_dns_reply(char *abuf, int alen, int status, int *port) {
	srv_details *details = NULL;
	got_dns_reply(&details, status, 0, (unsigned char*)abuf, alen);
	return process_srv_details(details, port);
}

START_TEST (test_no_srv_record) {
	/* Failed DNS lookup; DNS server returns SOA record only */
	char *reply = "?\xf6\x81\x83\x00\x01\x00\x00\x00\x01\x00\x00\x04_sip\x04_tcp\x04" "blah\x04" "blah\x04" "blah\x00\x00!\x00\x01\xc0\x16\x00\x06\x00\x01\x00\x00\x01h\x00!\x02ns\xc0\x16\x05" "admin\xc0\x16x+\x91\xd5\x00\x00p\x80\x00\x00\x1c\x20\x00\x09:\x80\x00\x00\x01h";
	int reply_len = 88;
	int port = 0;
	unsigned long ipaddr = process_dns_reply(reply, reply_len, ARES_ENOTFOUND, &port);
	ck_assert_int_eq(port, 5060);
	ck_assert_uint_eq(ipaddr, 0);
}
END_TEST

START_TEST (test_one_srv_record) {
	/* One SRV record, with a non-standard port number:
	 * _sip._udp.blah.blah.blah. 360 IN SRV 10 50 1111 sip.blah.blah.
	 *
	 * And then one A record:
	 * sip.blah.blah. 360 IN A 1.2.3.4
	 */
	char *reply = "'\xf8\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x04_sip\x04_udp\x04" "blah\x04" "blah\x04" "blah\x00\x00!\x00\x01\xc0\x0c\x00!\x00\x01\x00\x00\x01h\x00\x15\x00\x0a\x00\x32\x04\x57\x03sip\x04" "blah\x04" "blah\x00\xc0\x3c\x00\x01\x00\x01\x00\x00\x01h\x00\x04\x01\x02\x03\x04";
	int reply_len = 92;
	int port = 0;
	unsigned long ipaddr = process_dns_reply(reply, reply_len, ARES_SUCCESS, &port);
	ck_assert_int_eq(port, 1111);
	ck_assert_uint_eq(ipaddr, inet_addr("1.2.3.4"));
}
END_TEST

START_TEST (test_two_srv_records_differing_priority) {
	/* Two SRV records:
	 * _sip._udp.blah.blah.blah. 360 IN SRV 10 50 5060 sip.blah.blah.
	 * _sip._udp.blah.blah.blah. 360 IN SRV 20 50 5060 sip2.blah.blah.
	 * (The one with priority 10 should be used)
	 *
	 * And then one A record:
	 * sip.blah.blah. 360 IN A 1.2.3.4
	 */
	char *reply = "'\xf8\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\x04_sip\x04_udp\x04" "blah\x04" "blah\x04" "blah\x00\x00!\x00\x01\xc0\x0c\x00!\x00\x01\x00\x00\x01h\x00\x15\x00\x0a\x00\x32\x13\xc4\x03sip\x04" "blah\x04" "blah\x00\xc0\x0c\x00!\x00\x01\x00\x00\x01h\x00\x16\x00\x14\x00\x32\x13\xc4\x04sip2\x04" "blah\x04" "blah\x00\xc0\x3c\x00\x01\x00\x01\x00\x00\x01h\x00\x04\x01\x02\x03\x04";
	int reply_len = 126;
	int port = 0;
	unsigned long ipaddr = process_dns_reply(reply, reply_len, ARES_SUCCESS, &port);
	ck_assert_int_eq(port, 5060);
	ck_assert_uint_eq(ipaddr, inet_addr("1.2.3.4"));
}
END_TEST

START_TEST (test_two_srv_records_differing_priority_2) {
	/* Two SRV records:
	 * _sip._udp.blah.blah.blah. 360 IN SRV 10 50 5060 localhost.
	 * _sip._udp.blah.blah.blah. 360 IN SRV 20 50 5060 sip2.blah.blah.
	 * (The one with priority 10 should be used)
	 *
	 * sipsak should use libc's DNS resolver to look up 'localhost'
	 */
	char *reply = "'\xf8\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x04_sip\x04_udp\x04" "blah\x04" "blah\x04" "blah\x00\x00!\x00\x01\xc0\x0c\x00!\x00\x01\x00\x00\x01h\x00\x11\x00\x0a\x00\x32\x13\xc4\x09localhost\x00\xc0\x0c\x00!\x00\x01\x00\x00\x01h\x00\x16\x00\x14\x00" "2\x13\xc4\x04sip2\x04" "blah\x04" "blah\x00";
	int reply_len = 106;
	int port = 0;
	unsigned long ipaddr = process_dns_reply(reply, reply_len, ARES_SUCCESS, &port);
	ck_assert_int_eq(port, 5060);
	ck_assert_uint_eq(ipaddr, inet_addr("127.0.0.1"));
}
END_TEST

START_TEST (test_two_srv_records_same_priority) {
	/* Now both SRV records have priority 10, but one has weight 50 and the other has weight 0
	 * The one with weight 50 should always be used */
	char *reply = "'\xf8\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\x04_sip\x04_udp\x04" "blah\x04" "blah\x04" "blah\x00\x00!\x00\x01\xc0\x0c\x00!\x00\x01\x00\x00\x01h\x00\x15\x00\x0a\x00\x32\x13\xc4\x03sip\x04" "blah\x04" "blah\x00\xc0\x0c\x00!\x00\x01\x00\x00\x01h\x00\x16\x00\x0a\x00\x00\x13\xc4\x04sip2\x04" "blah\x04" "blah\x00\xc0\x3c\x00\x01\x00\x01\x00\x00\x01h\x00\x04\x01\x02\x03\x04";
	int reply_len = 126;
	int port = 0;
	unsigned long ipaddr = process_dns_reply(reply, reply_len, ARES_SUCCESS, &port);
	ck_assert_int_eq(port, 5060);
	ck_assert_uint_eq(ipaddr, inet_addr("1.2.3.4"));
}
END_TEST

START_TEST (test_srv_and_cname_1) {
	/* Again, one SRV record:
	 * _sip._udp.blah.blah.blah. 360 IN SRV 10 50 2222 sip.blah.blah.
	 *
	 * And then one CNAME record:
	 * sip.blah.blah. 360 IN CNAME localhost
	 */
	char *reply = "'\xf8\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x04_sip\x04_udp\x04" "blah\x04" "blah\x04" "blah\x00\x00!\x00\x01\xc0\x0c\x00!\x00\x01\x00\x00\x01h\x00\x15\x00\x0a\x00\x32\x08\xae\x03sip\x04" "blah\x04" "blah\x00\xc0\x3c\x00\x05\x00\x01\x00\x00\x01h\x00\x0b\x09localhost\x00";
	int reply_len = 99;
	int port = 0;
	unsigned long ipaddr = process_dns_reply(reply, reply_len, ARES_SUCCESS, &port);
	ck_assert_int_eq(port, 2222);
	ck_assert_uint_eq(ipaddr, inet_addr("127.0.0.1"));
}
END_TEST

Suite *dns_suite(void) {
	Suite *s = suite_create("DNS");

	TCase *tc_no_srv_record = tcase_create("test_no_srv_record");
	tcase_add_test(tc_no_srv_record, test_no_srv_record);
	TCase *tc_one_srv_record = tcase_create("test_one_srv_record");
	tcase_add_test(tc_one_srv_record, test_one_srv_record);
	TCase *tc_two_srv_records_differing_priority = tcase_create("test_two_srv_records_differing_priority");
	tcase_add_test(tc_two_srv_records_differing_priority, test_two_srv_records_differing_priority);
	TCase *tc_two_srv_records_differing_priority_2 = tcase_create("test_two_srv_records_differing_priority_2");
	tcase_add_test(tc_two_srv_records_differing_priority_2, test_two_srv_records_differing_priority_2);
	TCase *tc_two_srv_records_same_priority = tcase_create("test_two_srv_records_same_priority");
	tcase_add_test(tc_two_srv_records_same_priority, test_two_srv_records_same_priority);
	TCase *tc_srv_and_cname_1 = tcase_create("test_srv_and_cname_1");
	tcase_add_test(tc_srv_and_cname_1, test_srv_and_cname_1);

	suite_add_tcase(s, tc_no_srv_record);
	suite_add_tcase(s, tc_one_srv_record);
	suite_add_tcase(s, tc_two_srv_records_differing_priority);
	suite_add_tcase(s, tc_two_srv_records_differing_priority_2);
	suite_add_tcase(s, tc_two_srv_records_same_priority);
	suite_add_tcase(s, tc_srv_and_cname_1);
	return s;
}

int main(void) {
	int number_failed;
	Suite *s = dns_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

#endif /* HAVE_CHECK_H */
#endif /* HAVE_CARES_H */
