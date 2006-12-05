#include "../config.h"

#ifdef HAVE_CHECK_H

#include <stdlib.h>
#include <check.h>
#include "../helper.h"

#define RUNNING_CHECK 1

START_TEST (test_is_number) {
	fail_unless(is_number("") == 0,
		"is_number(\"\") returned %d, instead of 0", is_number(""));
	fail_unless(is_number("a") == 0,
		"is_number(\"a\") returned %d, instead of 0", is_number("a"));
	fail_unless(is_number("XYZ") == 0,
		"is_number(\"XYZ\") returned %d, instead of 0", is_number("XYZ"));
	fail_unless(is_number("10i") == 0,
		"is_number(\"10i\") returned %d, instead of 0", is_number("10i"));
	fail_unless(is_number("p01") == 0,
		"is_number(\"p01\") returned %d, instead of 0", is_number("p01"));
	fail_unless(is_number("p2q") == 0,
		"is_number(\"p2q\") returned %d, instead of 0", is_number("p2q"));
	fail_unless(is_number("1b3") == 0,
		"is_number(\"1b3\") returned %d, instead of 0", is_number("1b3"));
	fail_unless(is_number("1") == 1,
		"is_number(\"1\") returned %d, instead of 1", is_number("1"));
	fail_unless(is_number("10") == 1,
		"is_number(\"10\") returned %d, instead of 1", is_number("10"));
}
END_TEST

START_TEST (test_str_to_int) {
	fail_unless(str_to_int("") == -2,
		"str_to_int(\"\") returned %d, instead of -2", str_to_int(""));
	fail_unless(str_to_int(" ") == -2,
		"str_to_int(\" \") returned %d, instead of -2", str_to_int(" "));
	fail_unless(str_to_int("	") == -2,
		"str_to_int(\"\\t\") returned %d, instead of -2", str_to_int("	"));
	fail_unless(str_to_int(" 	 ") == -2,
		"str_to_int(\" \\t\") returned %d, instead of -2", str_to_int(" 	 "));
	fail_unless(str_to_int("a") == -2,
		"str_to_int(\"a\") returned %d, instead of -2", str_to_int("a"));
	fail_unless(str_to_int(" a") == -2,
		"str_to_int(\" a\") returned %d, instead of -2", str_to_int(" a"));
	fail_unless(str_to_int(" a ") == -2,
		"str_to_int(\" a \") returned %d, instead of -2", str_to_int(" a "));
	fail_unless(str_to_int("ABC") == -2,
		"str_to_int(\"ABC\") returned %d, instead of -2", str_to_int("ABC"));
	fail_unless(str_to_int(" ABC") == -2,
		"str_to_int(\" ABC\") returned %d, instead of -2", str_to_int(" ABC"));
	fail_unless(str_to_int(" ABC	") == -2,
		"str_to_int(\" ABC\\t\") returned %d, instead of -2", str_to_int(" ABC	"));
	fail_unless(str_to_int("1") == 1,
		"str_to_int(\"1\") returned %d, instead of 1", str_to_int("1"));
	fail_unless(str_to_int("10") == 10,
		"str_to_int(\"10\") returned %d, instead of 10", str_to_int("10"));
	fail_unless(str_to_int(" 10") == 10,
		"str_to_int(\" 10\") returned %d, instead of 10", str_to_int(" 10"));
	fail_unless(str_to_int(" 10 ") == 10,
		"str_to_int(\" 10 \") returned %d, instead of 10", str_to_int(" 10 "));
	fail_unless(str_to_int("	 10 	") == 10,
		"str_to_int(\"\\t 10 \\t\") returned %d, instead of 10", str_to_int("	 10 	"));
}
END_TEST

START_TEST (test_is_ip) {
	fail_unless(is_ip("") == 0,
		"is_ip(\"\") returned %d, instead of 0", is_ip(""));
	fail_unless(is_ip("0") == 0,
		"is_ip(\"0\") returned %d, instead of 0", is_ip("0"));
	fail_unless(is_ip("100") == 0,
		"is_ip(\"100\") returned %d, instead of 0", is_ip("100"));
	fail_unless(is_ip("1000") == 0,
		"is_ip(\"1000\") returned %d, instead of 0", is_ip("1000"));
	fail_unless(is_ip("1.0") == 0,
		"is_ip(\"1.0\") returned %d, instead of 0", is_ip("1.0"));
	fail_unless(is_ip("1.2.0") == 0,
		"is_ip(\"1.2.0\") returned %d, instead of 0", is_ip("1.2.0"));
	fail_unless(is_ip("1.2.3.4.5") == 0,
		"is_ip(\"1.2.3.4.5\") returned %d, instead of 0", is_ip("1.2.3.4.5"));
	fail_unless(is_ip("1000.0.0.0") == 0,
		"is_ip(\"1000.0.0.0\") returned %d, instead of 0", is_ip("1000.0.0.0"));
	fail_unless(is_ip("0.1000.0.0") == 0,
		"is_ip(\"0.1000.0.0\") returned %d, instead of 0", is_ip("0.1000.0.0"));
	fail_unless(is_ip("0.0.1000.0") == 0,
		"is_ip(\"0.0.1000.0\") returned %d, instead of 0", is_ip("0.0.1000.0"));
	fail_unless(is_ip("0.0.0.1000") == 0,
		"is_ip(\"0.0.0.1000\") returned %d, instead of 0", is_ip("0.0.0.1000"));
	fail_unless(is_ip("0.0.0.0") == 1,
		"is_ip(\"0.0.0.0\") returned %d, instead of 1", is_ip("0.0.0.0"));
	fail_unless(is_ip("1.2.3.4") == 1,
		"is_ip(\"1.2.3.4\") returned %d, instead of 1", is_ip("1.2.3.4"));
	fail_unless(is_ip("192.168.1.1") == 1,
		"is_ip(\"192.168.1.1\") returned %d, instead of 1", is_ip("192.168.1.1"));
	// this is a "known bug" ;)
	fail_unless(is_ip("999.999.999.999") == 1,
		"is_ip(\"999.999.999.999\") returned %d, instead of 1", is_ip("999.999.999.999"));
}
END_TEST

START_TEST (test_getaddress) {
	fail_unless(getaddress("") == 0,
		"getaddress(\"\") returned %lu, instead of 0", getaddress(""));
	fail_unless(getaddress("127.0.0.1") == 16777343,
		"getaddress(\"127.0.0.1\") returned %lu, instead of 16777343", getaddress("127.0.0.1"));
	// this should work also without DNS
	fail_unless(getaddress("localhost") == 16777343,
		"getaddress(\"localhost\") returned %lu, instead of 16777343", getaddress("localhost"));
}
END_TEST

START_TEST (test_insert_cr) {
	char ta[15];

	memset(ta, '\0', 15);
	insert_cr(ta);
	fail_unless(memcmp(ta, "\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0", 15) == 0,
		"insert_cr(\"\") returned '%s', instead of \"\r\n\"", ta);
	memset(ta, '\0', 15);
	memcpy(ta, "test", 4);
	insert_cr(ta);
	fail_unless(memcmp(ta, "test\r\n\0\0\0\0\0\0\0\0\0", 15) == 0,
		"insert_cr(\"test\") returned '%s', instead of \"test\r\n\"", ta);
	memset(ta, '\0', 15);
	memcpy(ta, "test\n", 5);
	insert_cr(ta);
	fail_unless(memcmp(ta, "test\r\n\r\n\0\0\0\0\0\0\0", 15) == 0,
		"insert_cr(\"test\\n\") returned '%s', instead of \"test\\r\\n\"", ta);
	memset(ta, '\0', 15);
	memcpy(ta, "foo\nbar\n", 8);
	insert_cr(ta);
	fail_unless(memcmp(ta, "foo\r\nbar\r\n\r\n\0\0\0", 15) == 0,
		"insert_cr(\"foo\\nbar\\n\") returned '%s', instead of \"foo\\r\\nbar\\r\\n\"", ta);
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

	/* add test cases to suite */
	suite_add_tcase(s, tc_is_number);
	suite_add_tcase(s, tc_str_to_int);
	suite_add_tcase(s, tc_is_ip);
	suite_add_tcase(s, tc_getaddress);
	suite_add_tcase(s, tc_insert_cr);

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
	return 0;
}

#endif /* HAVE_CHECK_H */
