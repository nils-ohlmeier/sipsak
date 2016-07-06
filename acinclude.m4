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
       AC_HELP_STRING([--disbale-ips], [compile with oldstyle --numeric behavior]),
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
       AC_HELP_STRING([--disable-tls], [compile without TLS transport]),
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
       AC_HELP_STRING([--enable-debug], [compile extra debug messages]),
       [
        AC_MSG_RESULT([yes])
        AC_DEFINE([SIPSAK_PRINT_DBG], [1], [Enable debug messages])
       ],
       [ AC_MSG_RESULT([not requested])
       ])
])

dnl AM_PATH_CHECK([MINIMUM-VERSION])
dnl Test for check, and define CHECK_CFLAGS, CHECK_LIBS and HAVE_CHECK_H
dnl

AC_DEFUN([AM_PATH_CHECK],
[
  AC_ARG_WITH([check],
  [  --with-check=PATH       prefix where check is installed [default=auto]])

  min_check_version=ifelse([$1], ,0.8.2,$1)

  AC_MSG_CHECKING(for check - version >= $min_check_version)

  if test x$with_check = xno; then
    AC_MSG_RESULT(disabled)
    ifelse([$3], , AC_MSG_ERROR([disabling check is not supported]), [$3])
  else
    if test "x$with_check" != x; then
      CHECK_CFLAGS="-I$with_check/include"
      CHECK_LIBS="-L$with_check/lib -lcheck"
    else
      CHECK_CFLAGS=""
      CHECK_LIBS="-lcheck"
    fi

    ac_save_CFLAGS="$CFLAGS"
    ac_save_LIBS="$LIBS"

    CFLAGS="$CFLAGS $CHECK_CFLAGS"
    LIBS="$CHECK_LIBS $LIBS"

    rm -f conf.check-test
    AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>

#include <check.h>

int main ()
{
  int major, minor, micro;
  char *tmp_version;

  system ("touch conf.check-test");

  /* HP/UX 9 (%@#!) writes to sscanf strings */
  tmp_version = strdup("$min_check_version");
  if (sscanf(tmp_version, "%d.%d.%d", &major, &minor, &micro) != 3) {
     printf("%s, bad version string\n", "$min_check_version");
     return 1;
   }

  if ((CHECK_MAJOR_VERSION != check_major_version) ||
      (CHECK_MINOR_VERSION != check_minor_version) ||
      (CHECK_MICRO_VERSION != check_micro_version))
    {
      printf("\n*** The check header file (version %d.%d.%d) does not match\n",
             CHECK_MAJOR_VERSION, CHECK_MINOR_VERSION, CHECK_MICRO_VERSION);
      printf("*** the check library (version %d.%d.%d).\n",
             check_major_version, check_minor_version, check_micro_version);
      return 1;
    }

  if ((check_major_version > major) ||
      ((check_major_version == major) && (check_minor_version > minor)) ||
      ((check_major_version == major) && (check_minor_version == minor) && (check_micro_version >= micro)))
    {
      return 0;
    }
  else
    {
      printf("\n*** An old version of check (%d.%d.%d) was found.\n",
             check_major_version, check_minor_version, check_micro_version);
      printf("*** You need a version of check being at least %d.%d.%d.\n", major, minor, micro);
      printf("***\n");
      printf("*** If you have already installed a sufficiently new version, this error\n");
      printf("*** probably means that the wrong copy of the check library and header\n");
      printf("*** file is being found. Rerun configure with the --with-check=PATH option\n");
      printf("*** to specify the prefix where the correct version was installed.\n");
    }

  return 1;
}
],, no_check=yes, [echo $ac_n "cross compiling; assumed OK... $ac_c"])

    CFLAGS="$ac_save_CFLAGS"
    LIBS="$ac_save_LIBS"

    if test "x$no_check" = x ; then
      AC_MSG_RESULT(yes)
	  AC_DEFINE([HAVE_CHECK_H], [1], [Has check.h])
    else
      AC_MSG_RESULT(no)

      CHECK_CFLAGS=""
      CHECK_LIBS=""

      rm -f conf.check-test
    fi

    AC_SUBST(CHECK_CFLAGS)
    AC_SUBST(CHECK_LIBS)

    rm -f conf.check-test

  fi
])

AC_DEFUN([CHECK_LIB_CARES],
[
	AC_MSG_CHECKING([for ares_version.h])

	ares_incdir=NONE
	ares_libdir=NONE
	ares_libcall=NONE
	ares_incdirs="/usr/include /usr/local/include /sw/include /opt/include /opt/local/include"
	ares_libdirs="/usr/lib64 /usr/lib /usr/local/lib64 /usr/local/lib /sw/lib /opt/lib /opt/local/lib"
	ares_libexten=".so .dylib .a"

	for dir in $ares_incdirs; do
		try="$dir/ares_version.h"
		if test -f $try; then
			ares_incdir=$dir;
			break;
		fi
	done

	if test "$ares_incdir" = "NONE"; then
		AC_MSG_RESULT([not found])
	else
		AC_MSG_RESULT([found at $ares_incdir])

		AC_MSG_CHECKING([for c-ares lib])

		for dir in $ares_libdirs; do
			for extension in $ares_libexten; do
				try="$dir/libcares$extension"
				if test -f $try; then
					ares_libdir=$dir;
					ares_libcall=cares;
					break;
				fi
			done
			if test "$ares_libdir" != "NONE"; then
				break;
			fi
		done

		if test "$ares_libdir" = "NONE"; then
			AC_MSG_RESULT([not found])
		else
			AC_MSG_RESULT([found at $ares_libdir])
		fi

		AC_CHECK_LIB(cares, ares_version,
		  AC_DEFINE([HAVE_CARES_H], [1], [Has cares.h])
		  LIBS="$LIBS -L$ares_libdir -l$ares_libcall"
		  CFLAGS="$CFLAGS -I$ares_incdir"
		  SIPSAK_HAVE_ARES="1"
		  AC_SUBST(SIPSAK_HAVE_ARES)
		)
	fi
])

AC_DEFUN([CHECK_LIB_RULI],
[
	AC_MSG_CHECKING([for ruli.h])

	ruli_incdir=NONE
	ruli_libdir=NONE
	ruli_incdirs="/usr/include /usr/local/include /sw/include /opt/include /opt/local/include"
	ruli_libdirs="/usr/lib64 /usr/lib /usr/local/lib64 /usr/local/lib /sw/lib /opt/lib /opt/local/lib"
	ruli_libexten=".so .dylib .a"

	for dir in $ruli_incdirs; do
		try="$dir/ruli.h"
		if test -f $try; then
			ruli_incdir=$dir;
			break;
		fi
	done

	if test "$ruli_incdir" = "NONE"; then
		AC_MSG_RESULT([not found])
	else
		AC_MSG_RESULT([found at $ruli_incdir])

		AC_MSG_CHECKING([for libruli])

		for dir in $ruli_libdirs; do
			for extension in $ruli_libexten; do
				try="$dir/libruli$extension"
				if test -f $try; then
					ruli_libdir=$dir;
					break;
				fi
			done
			if test "$ruli_libdir" != "NONE"; then
				break;
			fi
		done

		if test "$ruli_libdir" = "NONE"; then
			AC_MSG_RESULT([not found])
		else
			AC_MSG_RESULT([found at $ruli_libdir])
		fi

		AC_CHECK_LIB(ruli, ruli_sync_query,
		  AC_DEFINE([HAVE_RULI_H], [1], [Has ruli.h])
		  LIBS="$LIBS -L$ruli_libdir -lruli"
		  CFLAGS="$CFLAGS -I$ruli_incdir"
		)
	fi
])

AC_DEFUN([CHECK_PROG_DISTCC],
[
    AC_MSG_CHECKING([for distcc])
    AC_ARG_ENABLE([distcc],
        AC_HELP_STRING([--enable-distcc], [compile in parallel with distcc]),
        [
			distcc_dirs="/ /usr /usr/local /usr/local/gnu /usr/gnu /opt /opt/local"
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
    AC_TRY_COMPILE(,,, ssp_cc=no)
    echo $ssp_cc
    if test "X$ssp_cc" = "Xno"; then
      CFLAGS="$ssp_old_cflags"
    else
      AC_DEFINE([ENABLE_SSP_CC], 1, [Define if SSP C support is enabled.])
    fi
  fi
])

dnl *-*wedit:notab*-*  Please keep this as the last line.
