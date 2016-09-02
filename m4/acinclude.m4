AC_DEFUN([SIPSAK_IP_UDP],
[
	AC_CHECK_HEADERS([netinet/ip.h netinet/udp.h],,,
		[[#ifdef HAVE_NETINET_IN_SYSTM_H
		#include <sys/types.h>
		#include <netinet/in.h>
		#include <netinet/in_systm.h>
		#endif
	]])
])

AC_DEFUN([SIPSAK_ICMP],
[
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
])

AC_DEFUN([SIPSAK_RAW_SUPPORT],
[
	AC_REQUIRE([SIPSAK_IP_UDP])
	AC_REQUIRE([SIPSAK_ICMP])
	AC_CHECK_HEADERS([cygwin/icmp.h])
	AC_ARG_ENABLE([raw-support],
	  AS_HELP_STRING([--disable-raw-support], [compile without raw socket support]),
	  [sipsak_raw_support=$enable_raw_support],
	  [sipsak_raw_support=yes])
	AC_MSG_CHECKING([raw socket support])
	AS_IF([test "X$ac_cv_header_netinet_ip_h" = "Xno" ||
	       test "X$ac_cv_header_netinet_ip_icmp_h" = "Xno" ||
	       test "X$ac_cv_header_cygwin_icmp_h" = "Xyes"], [
	  sipsak_raw_support=no
	])
	AS_IF([test "X$sipsak_raw_support" = "Xyes"], [
	  AC_DEFINE([RAW_SUPPORT], [1], [Define to 1 to use raw socket support])
	])
	AC_MSG_RESULT([$sipsak_raw_support])
])

AC_DEFUN([SIPSAK_TIMER],
[
	# Check for T1 timer value
	def_timeout=500
	AC_ARG_ENABLE([timeout],AS_HELP_STRING(--enable-timeout=SEC,SIP timer T1 in SEC milliseconds (default 500)),[def_timeout=$enableval])
	if test "X$def_timeout" = "Xno"; then
	  # no timeout makes no sense
	  def_timeout=500
	fi
	AC_DEFINE_UNQUOTED(DEFAULT_TIMEOUT, $def_timeout, [Default maximum timeout on waiting for response.])
])

AC_DEFUN([SIPSAK_OLD_FQDN],
[
    AC_MSG_CHECKING([oldstyle numeric])
    AC_ARG_ENABLE([ips],
       AS_HELP_STRING([--disbale-ips], [compile with oldstyle --numeric behavior]),
       [
        AC_MSG_RESULT([yes])
        AC_DEFINE([OLDSTYLE_FQDN], [1], [Oldstyle FQDN behavior])
       ],
       [ AC_MSG_RESULT([not requested])
       ])
])

AC_DEFUN([SIPSAK_TLS],
[
    AC_MSG_CHECKING([disable TLS])
    AC_ARG_ENABLE([tls],
       AS_HELP_STRING([--disable-tls], [compile without TLS transport]),
       [
        AC_MSG_RESULT([yes])
        AC_DEFINE([SIPSAK_NO_TLS], [1], [Skip TLS transport])
       ],
       [ AC_MSG_RESULT([not requested])
       ])
])

AC_DEFUN([SIPSAK_DBG_PRINT],
[
    AC_MSG_CHECKING([enable debug messages])
    AC_ARG_ENABLE([debug],
       AS_HELP_STRING([--enable-debug], [compile extra debug messages]),
       [
        AC_MSG_RESULT([yes])
        AC_DEFINE([SIPSAK_PRINT_DBG], [1], [Enable debug messages])
       ],
       [ AC_MSG_RESULT([not requested])
       ])
])

AC_DEFUN([CHECK_PROG_DISTCC],
[
    AC_MSG_CHECKING([whether to use distcc])
    AC_ARG_ENABLE([distcc],
        AS_HELP_STRING([--enable-distcc], [compile in parallel with distcc]),
        [
          AC_MSG_RESULT([yes])
          AC_CHECK_PROG([DISTCC], [distcc])
        ],
        [ AC_MSG_RESULT([not requested])
        ])
])

dnl
dnl Useful macros for autoconf to check for ssp-patched gcc
dnl 1.0 - September 2003 - Tiago Sousa <mirage@kaotik.org>
dnl
dnl About ssp:
dnl GCC extension for protecting applications from stack-smashing attacks
dnl http://www.research.ibm.com/trl/projects/security/ssp/
dnl
dnl Usage:
dnl After calling the correct AC_LANG_*, use the corresponding macro:
dnl
dnl GCC_STACK_PROTECT_CC
dnl checks -fstack-protector with the C compiler, if it exists then updates
dnl CFLAGS and defines ENABLE_SSP_CC
dnl
dnl GCC_STACK_PROTECT_CXX
dnl checks -fstack-protector with the C++ compiler, if it exists then updates
dnl CXXFLAGS and defines ENABLE_SSP_CXX
dnl

AC_DEFUN([SIPSAK_GCC_STACK_PROTECT_CC],[
  ssp_cc=yes
  if test "X$CC" != "X"; then
    AC_MSG_CHECKING([whether ${CC} accepts -fstack-protector])
    ssp_old_cflags="$CFLAGS"
    CFLAGS="$CFLAGS -fstack-protector"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[]])], [], [], [ssp_cc=no])
    AC_MSG_RESULT([$ssp_cc])
    if test "X$ssp_cc" = "Xno"; then
      CFLAGS="$ssp_old_cflags"
    else
      AC_DEFINE([ENABLE_SSP_CC], 1, [Define if SSP C support is enabled.])
    fi
  fi
])

dnl *-*wedit:notab*-*  Please keep this as the last line.
