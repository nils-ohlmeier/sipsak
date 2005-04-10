#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([sipsak],[0.8.pre12],[develop@ohlmeier.org])
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

AC_PROG_CC
# Add -Wall if we are using GCC
if test "x$GCC" = "xyes"; then
	CFLAGS="$CFLAGS -Wall"
fi

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([ctype.h arpa/inet.h getopt.h netdb.h netinet/in.h netinet/in_systm.h limits.h sys/poll.h regex.h stdlib.h stdio.h string.h sys/param.h sys/socket.h sys/time.h unistd.h sys/utsname.h],,[AC_MSG_ERROR([missing required header (see above)])],)
AC_CHECK_HEADERS([openssl/md5.h])
AC_HEADER_SYS_WAIT
AC_HEADER_TIME
AC_CHECK_HEADERS([netinet/ip.h netinet/udp.h],,,
[[#ifdef HAVE_NETINET_IN_SYSTM_H
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#endif
]])
AC_CHECK_HEADERS([netinet/ip_icmp.h],,,
[[#ifdef HAVE_NETINET_IN_SYSTM_H
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
]])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([getchar gethostbyname gethostname gettimeofday inet_ntop memset ntohs regcomp select socket strchr strstr uname],,[AC_MSG_ERROR([missing required function (see above)])])
AC_CHECK_FUNCS([getdomainname getopt_long strcasestr])

AC_CHECK_LIB(crypto, MD5_Init,
 LIBS="$LIBS -lcrypto"
)

GCC_STACK_PROTECT_CC

# Check for default number of retrys
def_retrys=5
AC_ARG_ENABLE([retrys],AS_HELP_STRING(--enable-retrys=NUM,number NUM of retrys in default mode (default 5)),[def_retrys=$enableval])
if test "$def_retrys" = no; then
  def_retrys=1
fi
AC_DEFINE_UNQUOTED(DEFAULT_RETRYS, $def_retrys, [Default number of retrys in default mode.])

# Check for T1 timer value
def_timeout=500
AC_ARG_ENABLE([timeout],AS_HELP_STRING(--enable-timeout=SEC,SIP timer T1 in SEC milliseconds (default 500)),[def_timeout=$enableval])
if test "$def_timeout" = no; then
  # no timeout makes no sense
  def_timeout=500
fi
AC_DEFINE_UNQUOTED(DEFAULT_TIMEOUT, $def_timeout, [Default maximum timeout on waiting for response.])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
