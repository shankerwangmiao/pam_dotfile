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

EXTRA_DIST=bootstrap.sh README LICENSE
SUBDIRS=src man doc

MAINTAINERCLEANFILES = README
noinst_DATA = README

README:
	rm -f README
	$(MAKE) -C doc README
	ln -s doc/README README

homepage:
	test -d $$HOME/homepage/lennart
	mkdir -p $$HOME/homepage/lennart/projects/pam_dotfile
	cp *.tar.gz $$HOME/homepage/lennart/projects/pam_dotfile
	cp doc/README.html doc/style.css $$HOME/homepage/lennart/projects/pam_dotfile
	cp $$HOME/homepage/lennart/projects/pam_dotfile/README.html $$HOME/homepage/lennart/projects/pam_dotfile/index.html
