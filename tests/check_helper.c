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

Suite *helper_suite(void) {
	Suite *s = suite_create("Helper");

	/* is_number test case */
	TCase *tc_is_number = tcase_create("is_number");
	tcase_add_test(tc_is_number, test_is_number);

	/* str_to_int test case */
	TCase *tc_str_to_int = tcase_create("str_to_int");
	tcase_add_test(tc_str_to_int, test_str_to_int);

	/* add test cases to suite */
	suite_add_tcase(s, tc_is_number);
	suite_add_tcase(s, tc_str_to_int);

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
