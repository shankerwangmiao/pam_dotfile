#ifndef foomd5utilhfoo
#define foomd5utilhfoo

/***
  This file is part of pam_dotfile.

  pam_dotfile is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  pam_dotfile is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with pam_dotfile; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA
***/

void fhex(unsigned char *bin, int len, char *txt);
#define fhex_md5(bin,txt) fhex((bin),16,(txt))

#ifdef COMPAT05
void fhex_broken(unsigned char *bin, int len, char *txt);
#define fhex_broken_md5(bin,txt) fhex_broken((bin),16,(txt))
#endif

#endif
