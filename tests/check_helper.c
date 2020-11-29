#include "../config.h"

#include <stdlib.h>

#ifdef HAVE_CHECK_H

#include <check.h>
#include "../src/helper.h"

#define RUNNING_CHECK 1

void shutdown_network() {};

int verbose = 99;

void exit_code(int code, const char *function, const char *reason) {
  ck_abort_msg("Unexpected call to exit_code() with code %i at %s: %s",
      code, function, reason);
};

START_TEST (test_is_number) {
	/* failure cases */
	ck_assert_msg(is_number("") == 0, "is_number(\"\") returned %d, instead of 0", is_number(""));
	ck_assert_msg(is_number("a") == 0, "is_number(\"a\") returned %d, instead of 0", is_number("a"));
	ck_assert_msg(is_number("XYZ") == 0, "is_number(\"XYZ\") returned %d, instead of 0", is_number("XYZ"));
	ck_assert_msg(is_number("10i") == 0, "is_number(\"10i\") returned %d, instead of 0", is_number("10i"));
	ck_assert_msg(is_number("p01") == 0, "is_number(\"p01\") returned %d, instead of 0", is_number("p01"));
	ck_assert_msg(is_number("p2q") == 0, "is_number(\"p2q\") returned %d, instead of 0", is_number("p2q"));
	ck_assert_msg(is_number("1b3") == 0, "is_number(\"1b3\") returned %d, instead of 0", is_number("1b3"));

	/* success cases */
	ck_assert_msg(is_number("1") == 1, "is_number(\"1\") returned %d, instead of 1", is_number("1"));
	ck_assert_msg(is_number("10") == 1, "is_number(\"10\") returned %d, instead of 1", is_number("10"));
}
END_TEST

START_TEST (test_str_to_int) {
	/* failure because empty */
	ck_assert_msg(str_to_int(0, "") == -2, "str_to_int(0, \"\") returned %d, instead of -2", str_to_int(0, ""));
	ck_assert_msg(str_to_int(1, "") == -2, "str_to_int(1, \"\") returned %d, instead of -2", str_to_int(1, ""));
	ck_assert_msg(str_to_int(0, " ") == -2, "str_to_int(0, \" \") returned %d, instead of -2", str_to_int(0, " "));
	ck_assert_msg(str_to_int(1, " ") == -2, "str_to_int(1, \" \") returned %d, instead of -2", str_to_int(1, " "));
	ck_assert_msg(str_to_int(0, "	") == -2, "str_to_int(0, \"\\t\") returned %d, instead of -2", str_to_int(0, "	"));
	ck_assert_msg(str_to_int(1, "	") == -2, "str_to_int(1, \"\\t\") returned %d, instead of -2", str_to_int(1, "	"));
	ck_assert_msg(str_to_int(0, " 	 ") == -2, "str_to_int(0, \" \\t\") returned %d, instead of -2", str_to_int(0, " 	 "));
	ck_assert_msg(str_to_int(1, " 	 ") == -2, "str_to_int(1, \" \\t\") returned %d, instead of -2", str_to_int(1, " 	 "));

	/* failure because non-int */
	ck_assert_msg(str_to_int(0, "a") == -2, "str_to_int(0, \"a\") returned %d, instead of -2", str_to_int(0, "a"));
	ck_assert_msg(str_to_int(1, "a") == -2, "str_to_int(1, \"a\") returned %d, instead of -2", str_to_int(1, "a"));
	ck_assert_msg(str_to_int(0, " a") == -2, "str_to_int(0, \" a\") returned %d, instead of -2", str_to_int(0, " a"));
	ck_assert_msg(str_to_int(1, " a") == -2, "str_to_int(1, \" a\") returned %d, instead of -2", str_to_int(1, " a"));
	ck_assert_msg(str_to_int(0, " a ") == -2, "str_to_int(0, \" a \") returned %d, instead of -2", str_to_int(0, " a "));
	ck_assert_msg(str_to_int(1, " a ") == -2, "str_to_int(1, \" a \") returned %d, instead of -2", str_to_int(1, " a "));
	ck_assert_msg(str_to_int(0, "ABC") == -2, "str_to_int(0, \"ABC\") returned %d, instead of -2", str_to_int(0, "ABC"));
	ck_assert_msg(str_to_int(1, "ABC") == -2, "str_to_int(1, \"ABC\") returned %d, instead of -2", str_to_int(1, "ABC"));
	ck_assert_msg(str_to_int(0, " ABC") == -2, "str_to_int(0, \" ABC\") returned %d, instead of -2", str_to_int(0, " ABC"));
	ck_assert_msg(str_to_int(1, " ABC") == -2, "str_to_int(1, \" ABC\") returned %d, instead of -2", str_to_int(1, " ABC"));
	ck_assert_msg(str_to_int(0, " ABC	") == -2, "str_to_int(0, \" ABC\\t\") returned %d, instead of -2", str_to_int(0, " ABC	"));
	ck_assert_msg(str_to_int(1, " ABC	") == -2, "str_to_int(1, \" ABC\\t\") returned %d, instead of -2", str_to_int(1, " ABC	"));

	/* success cases */
	ck_assert_msg(str_to_int(0, "1") == 1, "str_to_int(0, \"1\") returned %d, instead of 1", str_to_int(0, "1"));
	ck_assert_msg(str_to_int(1, "1") == 1, "str_to_int(1, \"1\") returned %d, instead of 1", str_to_int(1, "1"));
	ck_assert_msg(str_to_int(0, "10") == 10, "str_to_int(0, \"10\") returned %d, instead of 10", str_to_int(0, "10"));
	ck_assert_msg(str_to_int(1, "10") == 10, "str_to_int(1, \"10\") returned %d, instead of 10", str_to_int(1, "10"));
	ck_assert_msg(str_to_int(0, " 10") == 10, "str_to_int(0, \" 10\") returned %d, instead of 10", str_to_int(0, " 10"));
	ck_assert_msg(str_to_int(1, " 10") == 10, "str_to_int(1, \" 10\") returned %d, instead of 10", str_to_int(1, " 10"));
	ck_assert_msg(str_to_int(0, " 10 ") == 10, "str_to_int(0, \" 10 \") returned %d, instead of 10", str_to_int(0, " 10 "));
	ck_assert_msg(str_to_int(1, " 10 ") == 10, "str_to_int(1, \" 10 \") returned %d, instead of 10", str_to_int(1, " 10 "));
	ck_assert_msg(str_to_int(0, "	 10 	") == 10, "str_to_int(0, \"\\t 10 \\t\") returned %d, instead of 10", str_to_int(0, "	 10 	"));
	ck_assert_msg(str_to_int(1, "	 10 	") == 10, "str_to_int(1, \"\\t 10 \\t\") returned %d, instead of 10", str_to_int(1, "	 10 	"));

	/* success and failures depending on the mode */
	ck_assert_msg(str_to_int(0, "1 a") == -2, "str_to_int(0, \"1 a\") returned %d, instead of -2", str_to_int(0, "1 a"));
	ck_assert_msg(str_to_int(1, "1 a") == 1, "str_to_int(1, \"1 a\") returned %d, instead of 1", str_to_int(1, "1"));
	ck_assert_msg(str_to_int(0, "10	B") == -2, "str_to_int(0, \"10\\tB\") returned %d, instead of -2", str_to_int(0, "10	B"));
	ck_assert_msg(str_to_int(1, "10	B") == 10, "str_to_int(1, \"10\\tB\") returned %d, instead of 10", str_to_int(1, "10	B"));
	ck_assert_msg(str_to_int(0, " 100	ABC ") == -2, "str_to_int(0, \" 100\\tABC \") returned %d, instead of -2", str_to_int(0, " 100	ABC "));
	ck_assert_msg(str_to_int(1, " 100	ABC ") == 100, "str_to_int(1, \" 100\\tABC \") returned %d, instead of 100", str_to_int(1, " 100	ABC "));
}
END_TEST

START_TEST (test_is_ip) {
	/* failure cases */
	ck_assert_msg(is_ip("") == 0, "is_ip(\"\") returned %d, instead of 0", is_ip(""));
	ck_assert_msg(is_ip("0") == 0, "is_ip(\"0\") returned %d, instead of 0", is_ip("0"));
	ck_assert_msg(is_ip("100") == 0, "is_ip(\"100\") returned %d, instead of 0", is_ip("100"));
	ck_assert_msg(is_ip("1000") == 0, "is_ip(\"1000\") returned %d, instead of 0", is_ip("1000"));
	ck_assert_msg(is_ip("1.0") == 0, "is_ip(\"1.0\") returned %d, instead of 0", is_ip("1.0"));
	ck_assert_msg(is_ip("1.2.0") == 0, "is_ip(\"1.2.0\") returned %d, instead of 0", is_ip("1.2.0"));
	ck_assert_msg(is_ip("1.2.3.4.5") == 0, "is_ip(\"1.2.3.4.5\") returned %d, instead of 0", is_ip("1.2.3.4.5"));
	ck_assert_msg(is_ip("1000.0.0.0") == 0, "is_ip(\"1000.0.0.0\") returned %d, instead of 0", is_ip("1000.0.0.0"));
	ck_assert_msg(is_ip("0.1000.0.0") == 0, "is_ip(\"0.1000.0.0\") returned %d, instead of 0", is_ip("0.1000.0.0"));
	ck_assert_msg(is_ip("0.0.1000.0") == 0, "is_ip(\"0.0.1000.0\") returned %d, instead of 0", is_ip("0.0.1000.0"));
	ck_assert_msg(is_ip("0.0.0.1000") == 0, "is_ip(\"0.0.0.1000\") returned %d, instead of 0", is_ip("0.0.0.1000"));

	/* success cases */
	ck_assert_msg(is_ip("0.0.0.0") == 1, "is_ip(\"0.0.0.0\") returned %d, instead of 1", is_ip("0.0.0.0"));
	ck_assert_msg(is_ip("1.2.3.4") == 1, "is_ip(\"1.2.3.4\") returned %d, instead of 1", is_ip("1.2.3.4"));
	ck_assert_msg(is_ip("192.168.1.1") == 1, "is_ip(\"192.168.1.1\") returned %d, instead of 1", is_ip("192.168.1.1"));
	/* this is a known limitation ;) */
	ck_assert_msg(is_ip("999.999.999.999") == 1, "is_ip(\"999.999.999.999\") returned %d, instead of 1", is_ip("999.999.999.999"));
}
END_TEST

START_TEST (test_getaddress) {
	unsigned long localaddr;

	/* failure case */
	ck_assert_msg(getaddress("") == 0, "getaddress(\"\") returned %lu, instead of 0", getaddress(""));

	localaddr = htonl(0x7f000001L);

	/* success cases */
	ck_assert_msg(getaddress("127.0.0.1") == localaddr, "getaddress(\"127.0.0.1\") returned %lu, instead of %lu", getaddress("127.0.0.1"), localaddr);
	/* this should work also without DNS */
	ck_assert_msg(getaddress("localhost") == localaddr, "getaddress(\"localhost\") returned %lu, instead of %lu", getaddress("localhost"), localaddr);
}
END_TEST

START_TEST (test_insert_cr) {
	char ta[15];

	memset(ta, '\0', 15);
	insert_cr(ta);
	ck_assert_msg(memcmp(ta, "\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0", 15) == 0, "insert_cr(\"\") returned '%s', instead of \"\r\n\"", ta);

	memset(ta, '\0', 15);
	memcpy(ta, "test", 4);
	insert_cr(ta);
	ck_assert_msg(memcmp(ta, "test\r\n\0\0\0\0\0\0\0\0\0", 15) == 0, "insert_cr(\"test\") returned '%s', instead of \"test\r\n\"", ta);

	memset(ta, '\0', 15);
	memcpy(ta, "test\n", 5);
	insert_cr(ta);
	ck_assert_msg(memcmp(ta, "test\r\n\r\n\0\0\0\0\0\0\0", 15) == 0, "insert_cr(\"test\\n\") returned '%s', instead of \"test\\r\\n\"", ta);

	memset(ta, '\0', 15);
	memcpy(ta, "foo\nbar\n", 8);
	insert_cr(ta);
	ck_assert_msg(memcmp(ta, "foo\r\nbar\r\n\r\n\0\0\0", 15) == 0, "insert_cr(\"foo\\nbar\\n\") returned '%s', instead of \"foo\\r\\nbar\\r\\n\"", ta);
}
END_TEST

START_TEST (test_get_fqdn) {
  char fqdn[FQDN_SIZE];

  memset(fqdn, '\0', FQDN_SIZE);
  get_fqdn(fqdn, 0, "127.0.0.15");
  ck_assert_msg(memcmp(fqdn, "127.0.0.15\0", 11) == 0, "get_fqdn returned '%s', instead of '127.0.0.15'", fqdn);

  memset(fqdn, '\0', FQDN_SIZE);
  get_fqdn(fqdn, 0, "localhost");
  ck_assert_msg(memcmp(fqdn, "localhost\0", 10) == 0, "get_fqdn returned '%s', instead of 'localhost'", fqdn);

  memset(fqdn, '\0', FQDN_SIZE);
  get_fqdn(fqdn, 1, "127.0.0.21");
  ck_assert_msg(memcmp(fqdn, "127.0.0.21\0", 11) == 0, "get_fqdn returned '%s', instead of '127.0.0.21'", fqdn);

  memset(fqdn, '\0', FQDN_SIZE);
  get_fqdn(fqdn, 1, "localhost");
  ck_assert_msg(memcmp(fqdn, "127.0.0.1\0", 10) == 0, "get_fqdn returned '%s', instead of '127.0.0.1'", fqdn);

  /* this fails on Travis Linux hosts, because their host names have no dots
  memset(fqdn, '\0', FQDN_SIZE);
  get_fqdn(fqdn, 0, 0);
  ck_assert_msg(memcmp(fqdn, "\0\0\0\0\0", 5) != 0, "get_fqdn empty buffer '%s'", fqdn);
  fprintf(stderr, "after fqdn test 1\n");

  memset(fqdn, '\0', FQDN_SIZE);
  get_fqdn(fqdn, 1, 0);
  ck_assert_msg(memcmp(fqdn, "127.0.0.1\0", 10) == 0, "get_fqdn returned '%s', instead of '127.0.0.1'", fqdn);
  fprintf(stderr, "after fqdn test 2\n");
  */
}
END_TEST

Suite *helper_suite(void) {
	Suite *s = suite_create("Helper");

	/* is_number test case */
	TCase *tc_is_number = tcase_create("is_number");
	tcase_add_test(tc_is_number, test_is_number);

	/* str_to_int test case */
	TCase *tc_str_to_int = tcase_create("str_to_int");
	tcase_add_test(tc_str_to_int, test_str_to_int);

	/* is_ip test case */
	TCase *tc_is_ip = tcase_create("is_ip");
	tcase_add_test(tc_is_ip, test_is_ip);

	/* getaddress test case */
	TCase *tc_getaddress = tcase_create("getaddress");
	tcase_add_test(tc_getaddress, test_getaddress);

	/* insert_cr test case */
	TCase *tc_insert_cr = tcase_create("insert_cr");
	tcase_add_test(tc_insert_cr, test_insert_cr);

	/* get_fqdn test case */
	TCase *tc_get_fqdn = tcase_create("get_fqdn");
	tcase_add_test(tc_get_fqdn, test_get_fqdn);

	/* add test cases to suite */
	suite_add_tcase(s, tc_is_number);
	suite_add_tcase(s, tc_str_to_int);
	suite_add_tcase(s, tc_is_ip);
	suite_add_tcase(s, tc_getaddress);
	suite_add_tcase(s, tc_insert_cr);
	suite_add_tcase(s, tc_get_fqdn);

	return s;
}

int main(void) {
	int number_failed;
	Suite *s = helper_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else /* HAVE_CHECK_H */

#include <stdio.h>
int main(void) {
	printf("check_helper: !!! missing check unit test framework !!!\n");
	return EXIT_FAILURE;
}

#endif /* HAVE_CHECK_H */
