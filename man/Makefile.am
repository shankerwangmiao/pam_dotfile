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

man_MANS = pam-dotfile-gen.1 pam-dotfile-helper.8

EXTRA_DIST = $(man_MANS) pam-dotfile-helper.8.xml.in pam-dotfile-gen.1.xml.in

if USE_XMLTOMAN

CLEANFILES = $(man_MANS)

pam-dotfile-gen.1: pam-dotfile-gen.1.xml.in Makefile
	sed -e 's,@sysconfdir\@,$(sysconfdir),g' -e 's,@sbindir\@,$(sbindir),g' -e 's,@PACKAGE_BUGREPORT\@,$(PACKAGE_BUGREPORT),g' $< | xmltoman - > $@

pam-dotfile-helper.8: pam-dotfile-helper.8.xml.in Makefile
	sed -e 's,@sysconfdir\@,$(sysconfdir),g' -e 's,@sbindir\@,$(sbindir),g' -e 's,@PACKAGE_BUGREPORT\@,$(PACKAGE_BUGREPORT),g' $< | xmltoman - > $@

endif
