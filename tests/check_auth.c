#include "../config.h"

#include <stdlib.h>

#ifdef HAVE_CHECK_H

#include <check.h>
#include "../src/auth.h"
#include "../src/sipsak.h"

#define RUNNING_CHECK 1

void shutdown_network() {};

int verbose = 99;

START_TEST (test_auth_digest_md5) {
  char message[BUFSIZE] = "REGISTER test@example.org SIP/2.0\r\nbarfoo\r\n";
  char auth_response[BUFSIZE] = "401\r\nWWW-Authenticate: Digest algorithm=MD5 realm=example.org nonce=1234567890\r\n";
  char username[] = "testuser";
  char password[] = "helloworld";

  const char expected[] = "REGISTER test@example.org SIP/2.0\r\nAuthorization: Digest username=\"testuser\", uri=\"test@example.org\", algorithm=MD5, realm=example.org nonce=1234567890, nonce=1234567890, response=\"f89e480f3bcaacdd1021f8d29ee8959a\"\r\nbarfoo\r\n";

  printf("before: '%s'\n", message);
  insert_auth(&message[0], &auth_response[0], &username[0], &password[0],
      &username[0], NULL, 0, 1);
  printf("after: '%s'\n", message);

  fail_unless(strcmp(&message[0], &expected[0]) == 0,
      "insert_auth() resulted in '%s' instead of '%s'", &message[0], &expected[0]);
}
END_TEST

Suite *auth_suite(void) {
	Suite *s = suite_create("auth");

	TCase *tc_auth_digest_md5 = tcase_create("test_auth_digest_md5");
	tcase_add_test(tc_auth_digest_md5, test_auth_digest_md5);

	/* add test cases to suite */
	suite_add_tcase(s, tc_auth_digest_md5);

	return s;
}

int main(void) {
	int number_failed;
	Suite *s = auth_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else /* HAVE_CHECK_H */

#include <stdio.h>
int main(void) {
	printf("check_auth: !!! missing check unit test framework !!!\n");
	return EXIT_FAILURE;
}

#endif /* HAVE_CHECK_H */
