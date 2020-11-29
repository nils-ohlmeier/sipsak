#include "../config.h"

#include <stdlib.h>

#ifdef HAVE_CHECK_H

#include <check.h>
#include "../src/auth.h"
#include "../src/sipsak.h"

#define RUNNING_CHECK 1

void shutdown_network() {};

int verbose = 99;

int expected_exit_code = -1;
char *expected_exit_reason = NULL;
int expected_exit_code_called = 0;

void set_expected_exit_code(int code, const char *reason) {
  expected_exit_code = code;
  expected_exit_reason = reason;
  expected_exit_code_called = 0;
}

void exit_code(int code, const char *function, const char *reason) {
  if (expected_exit_code == -1) {
    ck_abort_msg("Unexpected call to exit_code() with code %i at %s: %s",
        code, function, reason);
  }
  expected_exit_code_called = 1;
  ck_assert_msg(expected_exit_code == code, "Expected call to exit_code() with wrong code number");
  ck_assert_str_eq(expected_exit_reason, reason);
};

START_TEST (test_insert_auth_md5) {
  char message1[BUFSIZE] = "REGISTER test@example.org SIP/2.0\r\nbarfoo\r\n";
  char auth_response[BUFSIZE] = "401\r\nWWW-Authenticate: Digest algorithm=MD5,nonce=1234567890,realm=example.org\r\n";
  char username[] = "testuser";
  char password[] = "helloworld";

  const char expected1[] = "REGISTER test@example.org SIP/2.0\r\nAuthorization: Digest username=\"testuser\", uri=\"test@example.org\", algorithm=MD5, realm=example.org, nonce=1234567890, response=\"6a1ad69841f79661cda113d0dff8ab3d\"\r\nbarfoo\r\n";

  insert_auth(&message1[0], &auth_response[0], &username[0], &password[0],
      NULL, NULL, 0, 0);

  ck_assert_msg(strcmp(&message1[0], &expected1[0]) == 0,
      "insert_auth() 'basic' resulted in '%s' instead of '%s'", &message1[0], &expected1[0]);

  char message2[BUFSIZE] = "INVITE test@example.org SIP/2.0\r\nbarfoo\r\n";
  char auth_username[] = "authuser";

  const char expected2[] = "INVITE test@example.org SIP/2.0\r\nAuthorization: Digest username=\"authuser\", uri=\"test@example.org\", algorithm=MD5, realm=example.org, nonce=1234567890, response=\"97b2d3f13a5484a471c681faf7ca14b1\"\r\nbarfoo\r\n";

  insert_auth(&message2[0], &auth_response[0], NULL, &password[0],
      &auth_username[0], NULL, 0, 0);

  ck_assert_msg(strcmp(&message2[0], &expected2[0]) == 0,
      "insert_auth() 'authusername' resulted in '%s' instead of '%s'", &message2[0], &expected2[0]);

  char message3[BUFSIZE] = "MESSAGE test@example.org SIP/2.0\r\nbarfoo\r\n";

  const char expected3[] = "MESSAGE test@example.org SIP/2.0\r\nAuthorization: Digest username=\"testuser1\", uri=\"test@example.org\", algorithm=MD5, realm=example.org, nonce=1234567890, response=\"dcb615fe24c81241d6fa0c533d153e51\"\r\nbarfoo\r\n";

  insert_auth(&message3[0], &auth_response[0], &username[0], &password[0],
      NULL, NULL, 1, 1);

  ck_assert_msg(strcmp(&message3[0], &expected3[0]) == 0,
      "insert_auth() 'namebegin' resulted in '%s' instead of '%s'", &message3[0], &expected3[0]);

  char message4[BUFSIZE] = "foobar test@example.org SIP/2.0\r\nbarfoo\r\n";
  char authhash[] = "dcb615fe24c81241d6fa0c533d153e51";

  const char expected4[] = "foobar test@example.org SIP/2.0\r\nAuthorization: Digest username=\"testuser\", uri=\"test@example.org\", algorithm=MD5, realm=example.org, nonce=1234567890, response=\"48d6b710677a1aca3a5424debf9e012a\"\r\nbarfoo\r\n";

  insert_auth(&message4[0], &auth_response[0], &username[0], &password[0],
      NULL, &authhash[0], 0, 0);

  ck_assert_msg(strcmp(&message4[0], &expected4[0]) == 0,
      "insert_auth() 'authhash' resulted in '%s' instead of '%s'",
      &message4[0], &expected4[0]);

  char message5[BUFSIZE] = "ACK test@example.org SIP/2.0\r\nbarfoo\r\n";
  char auth_response2[BUFSIZE] = "401\r\nWWW-Authenticate: Digest algorithm=MD5, realm=example.org, nonce=1234567890, opaque=sjw8fn3wbj5sfs,\r\n";

  const char expected5[] = "ACK test@example.org SIP/2.0\r\nAuthorization: Digest username=\"testuser\", uri=\"test@example.org\", algorithm=MD5, realm=example.org, opaque=sjw8fn3wbj5sfs, nonce=1234567890, response=\"781a7065cb6c4ecba6fdccd0ef8190c5\"\r\nbarfoo\r\n";

  insert_auth(&message5[0], &auth_response2[0], &username[0], &password[0],
      NULL, NULL, 0, 0);

  ck_assert_msg(strcmp(&message5[0], &expected5[0]) == 0,
      "insert_auth() 'opaque' resulted in '%s' instead of '%s'",
      &message5[0], &expected5[0]);

  /*
  char message6[BUFSIZE] = "INVITE test@example.org SIP/2.0\r\nbarfoo\r\n";
  char auth_response3[BUFSIZE] = "401\r\nWWW-Authenticate: Digest algorithm=MD5, realm=example.org, qop=\"auth\", nonce=1234567890\r\n";

  const char expected6[] = "INVITE test@example.org SIP/2.0\r\nAuthorization: Digest username=\"testuser\", uri=\"test@example.org\", algorithm=MD5, realm=example.org, nonce=1234567890, qop=auth, nc=00000001, cnonce=\"41a7\", response=\"78e1c78a0638d5e25fe430fb3e7946f8\"\r\nbarfoo\r\n";

  insert_auth(&message6[0], &auth_response3[0], &username[0], &password[0],
      NULL, NULL, 0, 0);

  ck_assert_msg(strcmp(&message6[0], &expected6[0]) == 0,
      "insert_auth() 'qop=auth' resulted in '%s' instead of '%s'",
      &message6[0], &expected6[0]);

  char message7[BUFSIZE] = "INVITE test@example.org SIP/2.0\r\nbarfoo\r\n";
  char auth_response4[BUFSIZE] = "401\r\nWWW-Authenticate: Digest algorithm=MD5, realm=example.org, opaque=vdjn5t8gvsjs,qop=\"auth\", nonce=1234567890\r\n";

  const char expected7[] = "INVITE test@example.org SIP/2.0\r\nAuthorization: Digest username=\"testuser\", uri=\"test@example.org\", algorithm=MD5, realm=example.org, opaque=vdjn5t8gvsjs, nonce=1234567890, qop=auth, nc=00000002, cnonce=\"10d63af1\", response=\"78e43bf1d1aa928f701dcc8b3ab9aa97\"\r\nbarfoo\r\n";

  insert_auth(&message7[0], &auth_response4[0], &username[0], &password[0],
      NULL, NULL, 0, 0);

  ck_assert_msg(strcmp(&message7[0], &expected7[0]) == 0,
      "insert_auth() 'opaque + qop' resulted in '%s' instead of '%s'",
      &message7[0], &expected7[0]);
  */
}
END_TEST

START_TEST (test_insert_auth_exits) {
  char message1[BUFSIZE] = "REGISTER test@example.org SIP/2.0\r\nbarfoo\r\n";
  //char auth_response[BUFSIZE] = "401\r\nWWW-Authenticate: Digest algorithm=MD5,nonce=1234567890,realm=example.org\r\n";
  char auth_response[BUFSIZE] = "401";
  char username[] = "testuser";
  char password[] = "helloworld";

  set_expected_exit_code(3, "missing authentication header in reply");
  insert_auth(&message1[0], &auth_response[0], &username[0], &password[0],
      NULL, NULL, 0, 0);
  ck_assert_int_eq(expected_exit_code_called, 1);

  /*
  char message2[BUFSIZE] = "REGISTER";

  set_expected_exit_code(3, "missing new line in request");
  insert_auth(&message2[0], &auth_response[0], &username[0], &password[0],
      NULL, NULL, 0, 0);
  ck_assert_int_eq(expected_exit_code_called, 1);
  */
}
END_TEST

Suite *auth_suite(void) {
	Suite *s = suite_create("auth");

	TCase *tc_insert_auth_md5 = tcase_create("test_insert_auth_md5");
	tcase_add_test(tc_insert_auth_md5, test_insert_auth_md5);

	TCase *tc_insert_auth_exits = tcase_create("test_insert_auth_exits");
	tcase_add_test(tc_insert_auth_exits, test_insert_auth_exits);

	/* add test cases to suite */
	suite_add_tcase(s, tc_insert_auth_md5);
	suite_add_tcase(s, tc_insert_auth_exits);

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
