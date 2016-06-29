TESTS = check_helper

check_PROGRAMS = check_helper

check_helper_SOURCES = check_helper.c $(top_srcdir)/helper.h $(top_srcdir)/helper.c $(top_srcdir)/exit_code.h $(top_srcdir)/exit_code.c
check_helper_CFLAGS = @CHECK_CFLAGS@ -DRUNNING_CHECK
check_helper_LDADD = @CHECK_LIBS@
