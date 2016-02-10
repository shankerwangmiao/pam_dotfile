# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# $Id$

# This file is part of pam_dotfile.
#
# pam_dotfile is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# pam_dotfile is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pam_dotfile; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.

AC_PREREQ([2.69])
AC_INIT([pam_dotfile],[0.7.1],[mzcnzqbgsvyr (at) 0pointer (dot) de])
AC_CONFIG_SRCDIR([src/pam_dotfile.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign -Wall])

AC_DISABLE_STATIC([])

# Checks for programs.
AC_PROG_CC
LT_INIT
AC_PROG_CXX

# If using GCC specifiy some additional parameters
if test "x$GCC" = "xyes" ; then
   CFLAGS="$CFLAGS -pipe -Wall"
fi

AC_SUBST(PACKAGE_URL, [http://0pointer.de/lennart/projects/pam_dotfile/])

CFLAGS="$CFLAGS -L/lib"

# Checks for libraries.
AC_CHECK_HEADERS([security/pam_appl.h], [],
  [AC_MSG_ERROR([[PAM header files not found, install libpam-dev.]])])
AC_CHECK_HEADERS([security/pam_modules.h security/_pam_macros.h security/pam_modutil.h], [], [],
  [#include <sys/types.h>   #include <security/pam_appl.h>])



AC_CHECK_LIB([pam], [pam_start], [AC_SUBST([LIBPAM], ["-lpam"])])

AC_SEARCH_LIBS([pam_modutil_drop_priv], ["pam"], [AC_DEFINE([HAVE_PAM_MODUTIL_DROP_PRIV], [1], [pam_modutil_drop_priv()])])
AC_SEARCH_LIBS([pam_modutil_getpwnam], ["pam"], [AC_DEFINE([HAVE_PAM_MODUTIL_GETPWNAM], [1], [pam_modutil_getpwnam()])])

AC_SUBST(PAM_MODDIR, "\$(exec_prefix)/lib/security")
AC_ARG_WITH(pam-dir,
  AS_HELP_STRING([--with-pam-dir=DIR],[Where to install PAM module [[PREFIX/lib/security]]]),
            [case "${withval}" in
            /*) PAM_MODDIR="${withval}";;
            ./*|../*) AC_MSG_ERROR(Bad value for --with-pam-dir);;
            *)  PAM_MODDIR="\$(exec_prefix)/lib/${withval}";;
            esac])
AC_MSG_NOTICE([PAM installation path $PAM_MODDIR])

pam_misc_found=no;
AC_CHECK_HEADERS([security/pam_misc.h], [pam_misc_found=yes], [],
  [#include <sys/types.h>
   #include <security/pam_appl.h>])
AC_CHECK_HEADERS([pam/pam_misc.h], [pam_misc_found=yes], [],
  [#include <sys/types.h>
   #include <security/pam_appl.h>])
if test "x$pam_misc_found" = "xyes" ; then
  AC_DEFINE(PAM_CONV_FUNC,misc_conv,Have misc_conv)
  AC_CHECK_LIB([pam_misc], [misc_conv], [AC_SUBST([LIBPAMMISC], ["-lpam_misc"])])
else
  AC_CHECK_HEADERS([security/openpam.h],
  [AC_DEFINE(PAM_CONV_FUNC,openpam_ttyconv,Have openpam_ttyconv)
  ],
  [AC_MSG_ERROR([[Cannot find neither misc_conv nor openpam_ttyconv]])
  ],
  [#include <sys/types.h>
   #include <security/pam_appl.h>])
fi

# Checks for header files.

AC_CHECK_FUNCS([dup2 memset strchr strerror strrchr])
AC_FUNC_FORK
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_VPRINTF

AC_CHECK_HEADERS([fcntl.h limits.h syslog.h termios.h])
AC_HEADER_STDC
AC_HEADER_SYS_WAIT

AC_C_CONST

AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_CACHE_CHECK([return type of signal handlers],[ac_cv_type_signal],[AC_COMPILE_IFELSE(
[AC_LANG_PROGRAM([#include <sys/types.h>
#include <signal.h>
],
		 [return *(signal (0, 0)) (0) == 1;])],
		   [ac_cv_type_signal=int],
		   [ac_cv_type_signal=void])])
AC_DEFINE_UNQUOTED([RETSIGTYPE],[$ac_cv_type_signal],[Define as the return type of signal handlers
		    (`int' or `void').])

AC_TYPE_UID_T


# LYNX documentation generation
AC_ARG_ENABLE(lynx,
          AS_HELP_STRING([--disable-lynx],[Turn off lynx usage for documentation generation]),
[case "${enableval}" in
  yes) lynx=yes ;;
  no)  lynx=no ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --disable-lynx) ;;
esac],[lynx=yes])

if test x$lynx = xyes ; then
   AC_CHECK_PROG(have_lynx, lynx, yes, no)

   if test x$have_lynx = xno ; then
     AC_MSG_ERROR([*** Sorry, you have to install lynx or use --disable-lynx ***])
   fi
fi

AM_CONDITIONAL([USE_LYNX], [test "x$lynx" = xyes])

# XMLTOMAN manpage generation
AC_ARG_ENABLE(xmltoman,
        AS_HELP_STRING([--disable-xmltoman],[Disable rebuilding of man pages with xmltoman]),
[case "${enableval}" in
  yes) xmltoman=yes ;;
  no)  xmltoman=no ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --disable-xmltoman]) ;;
esac],[xmltoman=yes])

if test x$xmltoman = xyes ; then
   AC_CHECK_PROG(have_xmltoman, xmltoman, yes, no)

   if test x$have_xmltoman = xno ; then
     AC_MSG_WARN([*** Not rebuilding man pages as xmltoman is not found ***])
     xmltoman=no
   fi
fi

AM_CONDITIONAL([USE_XMLTOMAN], [test "x$xmltoman" = xyes])

AC_ARG_ENABLE(compat05,
              AS_HELP_STRING([--enable-compat05],[Enable compatibility with pam_dotfile <= 0.5]),
[case "${enableval}" in
  yes) compat05=yes ;;
  no)  compat05=no ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-compat05) ;;
esac],[compat05=no])

if test x$compat05 = xyes ; then
  AC_MSG_NOTICE([ *** Compatibility with pam_dotfile <= 0.5 is ENABLED ***])
  CFLAGS="$CFLAGS -DCOMPAT05=1"
else
  AC_MSG_WARN([ *** Compatibility with pam_dotfile <= 0.5 is DISABLED ***])
fi

AC_CONFIG_FILES([src/Makefile Makefile man/Makefile doc/Makefile doc/README.html])
AC_OUTPUT
