#include "../config.h"

#include <stdlib.h>

#ifdef HAVE_CHECK_H

#include <check.h>
#include "../src/header_f.h"

#define RUNNING_CHECK 1

int verbose = 99;

char *transport_str = "UDP";

void exit_code(int code, const char *function, const char *reason) {
  ck_abort_msg("Unexpected call to exit_code() with code %i at %s: %s",
      code, function, reason);
};

START_TEST (test_get_cl) {
	/* failure cases */
	ck_assert_msg(get_cl("") == -1, "get_cl(\"\") returned %d, instead of -1", get_cl(""));
	ck_assert_msg(get_cl("a") == -1, "get_cl(\"a\") returned %d, instead of -1", get_cl("a"));

	/* success cases */
	ck_assert_msg(get_cl("Content-Length: 123") == 123, "get_cl(\"123\") returned %d, instead of 123", get_cl("Content_Length: 123"));
	ck_assert_msg(get_cl("Content-Length: 321\r\n") == 321, "get_cl(\"321\") returned %d, instead of 321", get_cl("Content_Length: 321\r\n"));
	ck_assert_msg(get_cl("\nl: 456") == 456, "get_cl(\"456\") returned %d, instead of 456", get_cl("\nl: 456"));
	ck_assert_msg(get_cl("\nl: 789\r\n") == 789, "get_cl(\"789\") returned %d, instead of 789", get_cl("\nl: 789\r\n"));
}
END_TEST

Suite *header_f_suite(void) {
	Suite *s = suite_create("Header_f");

	/* get_cl test case */
	TCase *tc_get_cl = tcase_create("get_cl");
	tcase_add_test(tc_get_cl, test_get_cl);

	/* add test cases to suite */
	suite_add_tcase(s, tc_get_cl);

	return s;
}

int main(void) {
	int number_failed;
	Suite *s = header_f_suite();
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
