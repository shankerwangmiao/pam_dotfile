# $Id$
#
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

AM_CFLAGS = -DSBINDIR=\"@sbindir@\"

moduledir = @PAM_MODDIR@
module_LTLIBRARIES = pam_dotfile.la

pam_dotfile_la_SOURCES = pam_dotfile.c md5.c md5util.c md5.h md5util.h log.c log.h common.c common.h
pam_dotfile_la_LDFLAGS = -module -avoid-version
pam_dotfile_la_CFLAGS = $(AM_CFLAGS)

sbin_PROGRAMS = pam-dotfile-helper
bin_PROGRAMS = pam-dotfile-gen pamtest

pam_dotfile_gen_SOURCES = pam-dotfile-gen.c md5.c md5.h md5util.c md5util.h 
pam_dotfile_gen_CFLAGS = $(AM_CFLAGS)

pam_dotfile_helper_SOURCES = pam-dotfile-helper.c md5.c md5.h md5util.c md5util.h common.c common.h log.c log.h 
pam_dotfile_helper_CFLAGS = $(AM_CFLAGS)

pamtest_SOURCES = pamtest.c

install-exec-hook:
	chown root $(DESTDIR)$(sbindir)/pam-dotfile-helper
	chmod u+s $(DESTDIR)$(sbindir)/pam-dotfile-helper
