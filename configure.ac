#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([sipsak],[0.9.9-pre],[github@ohlmeier.org])
AM_INIT_AUTOMAKE([subdir-objects])
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR([src/sipsak.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
# Add -Wall if we are using GCC
if test "x$GCC" = "xyes"; then
  CFLAGS="$CFLAGS -Wall"
fi
SIPSAK_GCC_STACK_PROTECT_CC
CHECK_PROG_DISTCC

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
AC_CHECK_HEADERS([ctype.h errno.h arpa/inet.h netdb.h netinet/in.h netinet/in_systm.h limits.h sys/poll.h regex.h signal.h stdarg.h stdlib.h stdio.h string.h sys/param.h sys/socket.h sys/time.h unistd.h sys/utsname.h],,[AC_MSG_ERROR([missing required header (see above)])],)
AC_CHECK_HEADERS([getopt.h syslog.h])
AC_HEADER_SYS_WAIT
AC_HEADER_TIME

SIPSAK_IP_UDP
SIPSAK_ICMP
SIPSAK_RAW_SUPPORT

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([getchar gethostbyname gethostname getopt getpid gettimeofday memset ntohs regcomp select socket strchr strcmp strstr strtol uname],,[AC_MSG_ERROR([missing required function (see above)])])
AC_CHECK_FUNCS([calloc getdomainname getopt_long inet_ntop strncasecmp strcasestr syslog])

PKG_PROG_PKG_CONFIG

# Check if the check unit test framework is available
PKG_CHECK_MODULES([CHECK], [check >= 0.9.3], [
    AC_DEFINE([HAVE_CHECK_H], [1], [Has check.h])
  ],:)

PKG_CHECK_MODULES([GNUTLS], [gnutls >= 1.0.0], [
    AC_DEFINE([HAVE_GNUTLS], [1], [Has gnutls >= 1.0.0])
    HAVE_GNUTLS=1
    LIBS="${LIBS} ${GNUTLS_LIBS}"
    CFLAGS="${CFLAGS} ${GNUTLS_CFLAGS}"
  ], [
    AC_CHECK_HEADERS([openssl/md5.h], [
      AC_SEARCH_LIBS([MD5_Init], [crypto], [
        AC_DEFINE([HAVE_CRYPTO_WITH_MD5], [1], [The crypto lib has MD5 functions])
      ])
    ])

    AC_CHECK_HEADERS([openssl/sha.h], [
      AC_SEARCH_LIBS([SHA1_Init], [crypto], [
        AC_DEFINE([HAVE_CRYPTO_WITH_SHA1], [1], [The crpyto lib has SHA1 functions])
      ])
    ])
])
PKG_CHECK_MODULES([GNUTLS319], [gnutls >= 3.1.9], [
    AC_DEFINE([HAVE_GNUTLS_319], [1], [Has gntuls >= 3.1.9])
  ],:)

dnl ---
dnl Check if GnuTLS has SRP support.
dnl ---
if test "$HAVE_GNUTLS" = "1"; then
  AC_CHECK_LIB(gnutls, gnutls_srp_verifier,
   [
     AC_DEFINE(HAVE_GNUTLS_SRP, 1, [if you have the function gnutls_srp_verifier])
     AC_SUBST(HAVE_GNUTLS_SRP, [1])
   ])
fi


PKG_CHECK_MODULES([CARES], [libcares], [
  AC_DEFINE([HAVE_CARES_H], [1], [Has cares.h])
  LIBS="$LIBS $CARES_LIBS"
  CFLAGS="$CFLAGS $CARES_CFLAGS"
  AC_CHECK_HEADERS([arpa/nameser.h])
  ],:)

# FIXME: this has to replaced with a real check
# LIBS="$LIBS -lssl"

SIPSAK_TIMER
SIPSAK_OLD_FQDN
SIPSAK_TLS
SIPSAK_DBG_PRINT

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
