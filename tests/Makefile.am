TESTS = check_helper

check_PROGRAMS = check_helper

check_helper_SOURCES = check_helper.c $(top_builddir)/helper.h $(top_builddir)/helper.c $(top_builddir)/exit_code.h $(top_builddir)/exit_code.c
check_helper_CFLAGS = @CHECK_CFLAGS@ -DRUNNING_CHECK
check_helper_LDADD = @CHECK_LIBS@
