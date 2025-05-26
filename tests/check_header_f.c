#include "../config.h"

#include <stdlib.h>

#ifdef HAVE_CHECK_H

#include <check.h>
#include <stdio.h>
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

START_TEST (test_find_lr_parameter) {
	/* failure cases */
	ck_assert_msg(find_lr_parameter("") == 0, "find_lr_parameter(\"\") returned %d, instead of 0", find_lr_parameter(""));
	ck_assert_msg(find_lr_parameter("a") == 0, "find_lr_parameter(\"a\") returned %d, instead of 0", find_lr_parameter("a"));
	ck_assert_msg(find_lr_parameter(";lr") == 0, "find_lr_parameter(\";lr\") returned %d, instead of 0", find_lr_parameter(";lr"));
	ck_assert_msg(find_lr_parameter("\n") == 0, "find_lr_parameter(\"\\n\") returned %d, instead of 0", find_lr_parameter("\n"));
	ck_assert_msg(find_lr_parameter("aaa\nbbb") == 0, "find_lr_parameter(\"aaa\\nbbb\") returned %d, instead of 0", find_lr_parameter("aaa\nbbb"));
	ck_assert_msg(find_lr_parameter("a\n;lr") == 0, "find_lr_parameter(\"a\n;lr\") returned %d, instead of 0", find_lr_parameter("a\n;lr"));

	/* success cases */
	ck_assert_msg(find_lr_parameter(";lr\n") == 1, "find_lr_parameter(\";lr\n\") returned %d, instead of 1", find_lr_parameter(";lr\n"));
	ck_assert_msg(find_lr_parameter("Record-Route: foo;lr\n") == 1, "find_lr_parameter(\"Record-Route: foo;lr\n\") returned %d, instead of 1", find_lr_parameter(";lr\n"));
}
END_TEST

START_TEST (test_get_cseq) {
	/* failure cases */
	ck_assert_msg(get_cseq("") == 0, "get_cseq(\"\") returned %d, instead of 0", find_lr_parameter(""));
	ck_assert_msg(get_cseq("foo") == 0, "get_cseq(\"foo\") returned %d, instead of 0", find_lr_parameter("foo"));
	ck_assert_msg(get_cseq("Cseq: ") == 0, "get_cseq(\"Cseq: \") returned %d, instead of 0", find_lr_parameter("Cseq: "));
	ck_assert_msg(get_cseq("Cseq: -5") == 0, "get_cseq(\"Cseq: -5\") returned %d, instead of 0", find_lr_parameter("Cseq: -5"));
	ck_assert_msg(get_cseq("Cseq: a") == 0, "get_cseq(\"Cseq: a\") returned %d, instead of 0", find_lr_parameter("Cseq: a"));

	/* success cases */
	ck_assert_msg(get_cseq("Cseq: 1") == 1, "get_cseq(\"Cseq: 1\") returned %d, instead of 1", find_lr_parameter("Cseq: 1"));
	ck_assert_msg(get_cseq("Cseq: 123456") == 123456, "get_cseq(\"Cseq: 123456\") returned %d, instead of 123456", find_lr_parameter("Cseq: 123456"));
}
END_TEST

START_TEST (test_set_cl) {
    char message[1024];
    int result;

    /* Test setting Content-Length with full header name */
	memset(message, 0, sizeof(message));
    strcpy(message, "\r\nContent-Length: 123\r\n\r\n");
    set_cl(message, 456);
    result = get_cl(message);
    ck_assert_msg(result == 456, "set_cl failed to set Content-Length to 456, got %d", result);

    /* Test setting Content-Length with short header name */
	memset(message, 0, sizeof(message));
    strcpy(message, "\r\nl: 123\r\n\r\n");
    set_cl(message, 789);
    result = get_cl(message);
    ck_assert_msg(result == 789, "set_cl failed to set Content-Length to 789, got %d", result);

    /* Test setting Content-Length to zero */
	memset(message, 0, sizeof(message));
    strcpy(message, "\r\nContent-Length: 123\r\n\r\n");
    set_cl(message, 0);
    result = get_cl(message);
	ck_assert_msg(result == 0, "set_cl failed to set Content-Length to 0, got %d", result);

    /* Test setting Content-Length to a large number */
	memset(message, 0, sizeof(message));
    strcpy(message, "\r\nContent-Length: 123\r\n\r\n\r\n\r\n");
    set_cl(message, 999999);
    result = get_cl(message);
    ck_assert_msg(result == 999999, "set_cl failed to set Content-Length to 999999, got %d", result);

    /* Test with missing Content-Length header */
	memset(message, 0, sizeof(message));
    strcpy(message, "SIP/2.0 200 OK\r\n\r\n");
    set_cl(message, 123);
    result = get_cl(message);
    ck_assert_msg(result == -1, "set_cl should not modify message without Content-Length header");
}
END_TEST

Suite *header_f_suite(void) {
	Suite *s = suite_create("Header_f");

	/* get_cl test case */
	TCase *tc_get_cl = tcase_create("get_cl");
	tcase_add_test(tc_get_cl, test_get_cl);
	/* find_lr_parameter test case */
	TCase *tc_find_lr_parameter = tcase_create("find_lr_parameter");
	tcase_add_test(tc_find_lr_parameter, test_find_lr_parameter);
	/* get_cseq test case */
	TCase *tc_get_cseq = tcase_create("get_cseq");
	tcase_add_test(tc_get_cseq, test_get_cseq);
	/* set_cl test case */
	TCase *tc_set_cl = tcase_create("set_cl");
	tcase_add_test(tc_set_cl, test_set_cl);

	/* add test cases to suite */
	suite_add_tcase(s, tc_get_cl);
	suite_add_tcase(s, tc_find_lr_parameter);
	suite_add_tcase(s, tc_get_cseq);
	suite_add_tcase(s, tc_set_cl);

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
