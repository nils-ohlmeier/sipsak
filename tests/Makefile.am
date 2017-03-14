TESTS = check_helper check_md5

check_PROGRAMS = check_helper check_md5

check_helper_SOURCES = check_helper.c ../helper.h ../helper.c ../exit_code.h ../exit_code.c
check_helper_CFLAGS = @CHECK_CFLAGS@ -DRUNNING_CHECK
check_helper_LDADD = @CHECK_LIBS@

check_md5_SOURCES = check_md5.c ../md5.h ../md5.c
check_md5_CFLAGS = @CHECK_CFLAGS@ -DRUNNING_CHECK
check_md5_LDADD = @CHECK_LIBS@
