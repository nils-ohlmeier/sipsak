#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([sipsak],[0.8.9_pre],[calrissian@users.berlios.de])
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR([sipsak.c])
AC_CONFIG_HEADER([config.h])



# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CANONICAL_HOST

case "$host" in
  *-*-solaris*)
    LIBS="$LIBS -lposix4 -lsocket -lnsl"
    ;;
  *)
    LIBS="$LIBS"
    ;;
esac
AC_SUBST([LIBS])


# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([gethostbyname gethostname gettimeofday memset regcomp select socket strchr strstr uname])

GCC_STACK_PROTECT_CC

# Check for default number of retrys
def_retrys=5
AC_ARG_ENABLE([retrys],AS_HELP_STRING(--enable-retrys=NUM,number NUM of retrys in default mode (default 5)),[def_retrys=$enableval])
if test "$def_retrys" = no; then
  def_retrys=1
fi
AC_DEFINE_UNQUOTED(DEFAULT_RETRYS, $def_retrys, [Default number of retrys in default mode.])

# Check for default timeout
def_timeout=5000
AC_ARG_ENABLE([timeout],AS_HELP_STRING(--enable-timeout=SEC,maximum timeout in SEC milliseconds (default 5000)),[def_timeout=$enableval])
if test "$def_timeout" = no; then
  # no timeout makes no sense
  def_timeout=1000
fi
AC_DEFINE_UNQUOTED(DEFAULT_TIMEOUT, $def_timeout, [Default maximum timeout on waiting for response.])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
