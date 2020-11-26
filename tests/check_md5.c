#include "../config.h"

#include <stdlib.h>

#ifdef HAVE_CHECK_H

#include <check.h>
#include "../src/md5.h"

#define RUNNING_CHECK 1

char md5hex_buf[33]; /* NULed by initialization */
const char *md5hex(unsigned char res[16]) {
	int i;
	for (i = 0; i < 16; ++i) {
		sprintf(md5hex_buf + 2 * i, "%02hhx", res[i]);
	}
	return md5hex_buf;
}

START_TEST (test_md5_empty) {
	const char expected[] = "d41d8cd98f00b204e9800998ecf8427e";
	unsigned char res[16];
	MD5_CTX ctx;

	MD5Init(&ctx);
	MD5Final(&res[0], &ctx);

	ck_assert_msg(
		strcmp(md5hex(res), expected) == 0,
		"md5('') returned %s instead of %s", &md5hex_buf[0], expected);
}
END_TEST

START_TEST (test_md5_quick_brown_fox) {
	const char expected[] = "14aa0efdbdac9187f334b9d25ddeaefe";
	unsigned char res[16];
	MD5_CTX ctx;

	MD5Init(&ctx);
	MD5Update(&ctx, "The quick brown fox ", 20);
	MD5Update(&ctx, "jumped over ", 12);
	MD5Update(&ctx, "the \0NUL\n", 9);
	//MD5Update(&ctx, "The quick brown fox jumped over the \0NUL\n", 41);
	MD5Final(&res[0], &ctx);

	ck_assert_msg(
		strcmp(md5hex(res), expected) == 0,
		"md5('The quick brown fox jumped over the \\0NUL\\n') "
		"returned %s instead of %s", &md5hex_buf[0], expected);
}
END_TEST

Suite *md5_suite(void) {
	Suite *s = suite_create("MD5");

	TCase *tc_md5_empty = tcase_create("test_md5_empty");
	tcase_add_test(tc_md5_empty, test_md5_empty);

	TCase *tc_md5_quick_brown_fox = tcase_create("test_md5_quick_brown_fox");
	tcase_add_test(tc_md5_quick_brown_fox, test_md5_quick_brown_fox);

	/* add test cases to suite */
	suite_add_tcase(s, tc_md5_empty);
	suite_add_tcase(s, tc_md5_quick_brown_fox);

	return s;
}

int main(void) {
	int number_failed;
	Suite *s = md5_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else /* HAVE_CHECK_H */

#include <stdio.h>
int main(void) {
	printf("check_md5: !!! missing check unit test framework !!!\n");
	return EXIT_FAILURE;
}

#endif /* HAVE_CHECK_H */
