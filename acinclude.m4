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

AC_DEFUN([CHECK_LIB_CARES],
[
	AC_MSG_CHECKING([for ares_version.h])

	ares_incdir=NONE
	ares_libdir=NONE
	ares_libcall=NONE
	ares_incdirs="/usr/include /usr/local/include /sw/include"
	ares_libdirs="/usr/lib64 /usr/lib /usr/local/lib64 /usr/local/lib /sw/lib"
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
	ruli_incdirs="/usr/include /usr/local/include /sw/include"
	ruli_libdirs="/usr/lib64 /usr/lib /usr/local/lib64 /usr/local/lib /sw/lib"
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

dnl Autoconf macros for libgnutls
dnl $id$

# Modified for LIBGNUTLS -- nmav
# Configure paths for LIBGCRYPT
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-09

dnl AM_PATH_LIBGNUTLS([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libgnutls, and define LIBGNUTLS_CFLAGS and LIBGNUTLS_LIBS
dnl
AC_DEFUN([AM_PATH_SIPSAK_LIBGNUTLS], [
dnl
dnl Get the cflags and libraries from the libgnutls-config script
dnl
AC_MSG_CHECKING([disabled gnutls])
AC_ARG_ENABLE([gnutls], 
  AC_HELP_STRING([--disable-gnutls], [compile without gnutls]),
  [
   AC_MSG_RESULT([yes])
   DISABLE_GNUTLS=yes
   AC_SUBST([DISABLE_GNUTLS])
  ],
  [AC_MSG_RESULT([not requested])]
  )
AC_ARG_WITH(libgnutls-prefix,
          [  --with-libgnutls-prefix=PFX   Prefix where libgnutls is installed (optional)],
          libgnutls_config_prefix="$withval", libgnutls_config_prefix="")

  if test x$libgnutls_config_prefix != x ; then
     if test x${LIBGNUTLS_CONFIG+set} != xset ; then
        LIBGNUTLS_CONFIG=$libgnutls_config_prefix/bin/libgnutls-config
     fi
  fi

  if test "$DISABLE_GNUTLS" != "yes"; then
    AC_PATH_PROG(LIBGNUTLS_CONFIG, libgnutls-config, no)
  fi
  min_libgnutls_version=ifelse([$1], ,0.1.0,$1)
  AC_MSG_CHECKING(for libgnutls - version >= $min_libgnutls_version)
  no_libgnutls=""
  if test "$DISABLE_GNUTLS" = "yes"; then
	LIBGNUTLS_CONFIG=no
  fi
  if test "$LIBGNUTLS_CONFIG" = "no" ; then
    no_libgnutls=yes
  else
    LIBGNUTLS_CFLAGS=`$LIBGNUTLS_CONFIG $libgnutls_config_args --cflags`
    LIBGNUTLS_LIBS=`$LIBGNUTLS_CONFIG $libgnutls_config_args --libs`
    libgnutls_config_version=`$LIBGNUTLS_CONFIG $libgnutls_config_args --version`


      ac_save_CFLAGS="$CFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $LIBGNUTLS_CFLAGS"
      LIBS="$LIBS $LIBGNUTLS_LIBS"
dnl
dnl Now check if the installed libgnutls is sufficiently new. Also sanity
dnl checks the results of libgnutls-config to some extent
dnl
      rm -f conf.libgnutlstest
      AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>

int
main ()
{
    system ("touch conf.libgnutlstest");

    if( strcmp( gnutls_check_version(NULL), "$libgnutls_config_version" ) )
    {
      printf("\n*** 'libgnutls-config --version' returned %s, but LIBGNUTLS (%s)\n",
             "$libgnutls_config_version", gnutls_check_version(NULL) );
      printf("*** was found! If libgnutls-config was correct, then it is best\n");
      printf("*** to remove the old version of LIBGNUTLS. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If libgnutls-config was wrong, set the environment variable LIBGNUTLS_CONFIG\n");
      printf("*** to point to the correct copy of libgnutls-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
    else if ( strcmp(gnutls_check_version(NULL), LIBGNUTLS_VERSION ) )
    {
      printf("\n*** LIBGNUTLS header file (version %s) does not match\n", LIBGNUTLS_VERSION);
      printf("*** library (version %s)\n", gnutls_check_version(NULL) );
    }
    else
    {
      if ( gnutls_check_version( "$min_libgnutls_version" ) )
      {
        return 0;
      }
     else
      {
        printf("no\n*** An old version of LIBGNUTLS (%s) was found.\n",
                gnutls_check_version(NULL) );
        printf("*** You need a version of LIBGNUTLS newer than %s. The latest version of\n",
               "$min_libgnutls_version" );
        printf("*** LIBGNUTLS is always available from ftp://gnutls.hellug.gr/pub/gnutls.\n");
        printf("*** \n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the libgnutls-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of LIBGNUTLS, but you can also set the LIBGNUTLS_CONFIG environment to point to the\n");
        printf("*** correct copy of libgnutls-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
  return 1;
}
],, no_libgnutls=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
  fi

  if test "x$no_libgnutls" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     if test -f conf.libgnutlstest ; then
        :
     else
        AC_MSG_RESULT(no)
     fi
     if test "$LIBGNUTLS_CONFIG" != "no" ; then
       if test -f conf.libgnutlstest ; then
        :
       else
          echo "*** Could not run libgnutls test program, checking why..."
          CFLAGS="$CFLAGS $LIBGNUTLS_CFLAGS"
          LIBS="$LIBS $LIBGNUTLS_LIBS"
          AC_TRY_LINK([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
],      [ return !!gnutls_check_version(NULL); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding LIBGNUTLS or finding the wrong"
          echo "*** version of LIBGNUTLS. If it is not finding LIBGNUTLS, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LIBGNUTLS was incorrectly installed"
          echo "*** or that you have moved LIBGNUTLS since it was installed. In the latter case, you"
          echo "*** may want to edit the libgnutls-config script: $LIBGNUTLS_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     LIBGNUTLS_CFLAGS=""
     LIBGNUTLS_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  rm -f conf.libgnutlstest
  AC_SUBST(LIBGNUTLS_CFLAGS)
  AC_SUBST(LIBGNUTLS_LIBS)
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
