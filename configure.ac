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

AC_PREREQ(2.57)
AC_INIT([pam_dotfile], [0.6], [mzcnzqbgsvyr@itaparica.org])
AC_CONFIG_SRCDIR([src/pam_dotfile.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign -Wall])
AM_MAINTAINER_MODE

AM_DISABLE_STATIC

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_CXX

# If using GCC specifiy some additional parameters
if test "x$GCC" = "xyes" ; then
   CFLAGS="$CFLAGS -pipe -Wall"
fi

CFLAGS="$CFLAGS -L/lib"

# Checks for libraries.
AC_CHECK_HEADER([security/pam_modules.h],, [AC_MSG_ERROR([*** Sorry, you have to install the PAM development files ***])])

LIBS="$LIBS -ldl -lpam -lpam_misc"

case "$host" in
  *-*-linux*)
    PAM_MODDIR="/lib/security"
    ;;
  *)
    PAM_MODDIR="/usr/lib"
    ;;
esac
AC_SUBST(PAM_MODDIR)

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
AC_TYPE_SIGNAL
AC_TYPE_UID_T


# LYNX documentation generation
AC_ARG_ENABLE(lynx,
          AC_HELP_STRING([--disable-lynx], [Turn off lynx usage for documentation generation]),
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
        AC_HELP_STRING([--disable-xmltoman], [Disable rebuilding of man pages with xmltoman]),
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
              AC_HELP_STRING([--enable-compat05], [Enable compatibility with pam_dotfile <= 0.5]),
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
