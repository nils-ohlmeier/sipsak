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

AC_DEFUN([SIPSAK_RETRYS],
[
	# Check for default number of retrys
	def_retrys=5
	AC_ARG_ENABLE([retrys],AS_HELP_STRING(--enable-retrys=NUM,number NUM of retrys in default mode (default 5)),[def_retrys=$enableval])
	if test "$def_retrys" = no; then
	  def_retrys=1
	fi
	AC_DEFINE_UNQUOTED(DEFAULT_RETRYS, $def_retrys, [Default number of retrys in default mode.])
])

AC_DEFUN([SIPSAK_TIMER],
[
	# Check for T1 timer value
	def_timeout=500
	AC_ARG_ENABLE([timeout],AS_HELP_STRING(--enable-timeout=SEC,SIP timer T1 in SEC milliseconds (default 500)),[def_timeout=$enableval])
	if test "$def_timeout" = no; then
	  # no timeout makes no sense
	  def_timeout=500
	fi
	AC_DEFINE_UNQUOTED(DEFAULT_TIMEOUT, $def_timeout, [Default maximum timeout on waiting for response.])
])

AC_DEFUN([CHECK_LIB_RULI],
[
	AC_MSG_CHECKING([for libruli])

	ruli_incidr=NONE
	ruli_libdir=NONE

	ruli_incdirs="/usr/include /usr/local/include"
	for dir in $ruli_incdirs; do
		try="$dir/ruli.h"
		if test -f $try; then
			ruli_incdir=$dir;
			break;
		fi
	done

	ruli_libdirs="/usr/lib /usr/local/lib"
	for dir in $ruli_libdirs; do
		try="$dir/libruli.so"
		if test -f $try; then
			ruli_libdir=$dir;
			break;
		fi
	done

	if test "$ruli_incdir" = "NONE" || test "$ruli_libdir" = "NONE"; then
		AC_MSG_RESULT([no])
	else
		AC_MSG_RESULT([yes])
		AC_DEFINE([HAVE_RULI_H], [1], [Has ruli.h])
		LIBS="$LIBS -L$ruli_libdir -lruli"
		CFLAGS="$CFLAGS -I$ruli_incdir"
	fi
])

AC_DEFUN([CHECK_PROG_DISTCC],
[
    AC_MSG_CHECKING([for distcc])
    AC_ARG_ENABLE([distcc],
        AC_HELP_STRING([--enable-distcc], [compile in parallel with distcc]),
        [
			distcc_dirs="/ /usr /usr/local /usr/local/gnu /usr/gnu"
            for dir in $distcc_dirs; do
                if test -x "$dir/bin/distcc"; then
                    found_distcc=yes;
                    DISTCC="$dir/bin/distcc"
                    break;
                fi
            done
            if test x_$found_distcc != x_yes; then
                AC_MSG_ERROR([not found])
            else
                AC_MSG_RESULT([yes])
                AC_SUBST([DISTCC])
            fi
        ],
        [ AC_MSG_RESULT([not requested])
        ])
])

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

AC_DEFUN([GCC_STACK_PROTECT_CC],[
  ssp_cc=yes
  if test "X$CC" != "X"; then
    AC_MSG_CHECKING([whether ${CC} accepts -fstack-protector])
    ssp_old_cflags="$CFLAGS"
    CFLAGS="$CFLAGS -fstack-protector"
    AC_TRY_COMPILE(,,, ssp_cc=no)
    echo $ssp_cc
    if test "X$ssp_cc" = "Xno"; then
      CFLAGS="$ssp_old_cflags"
    else
      AC_DEFINE([ENABLE_SSP_CC], 1, [Define if SSP C support is enabled.])
    fi
  fi
])
