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

#include "md5util.h"


#ifdef COMPAT05

void fhex_broken(unsigned char *bin, int len, char *txt) {
    const static char hex[] = "01234567890abcdef";
    int i;

    for (i = 0; i < len; i++) {
        txt[i*2] = hex[bin[i]>>4];
        txt[i*2+1] = hex[bin[i]&0xF];
    }
}

#endif

void fhex(unsigned char *bin, int len, char *txt) {
    const static char hex[] = "0123456789abcdef";
    int i;

    for (i = 0; i < len; i++) {
        txt[i*2] = hex[bin[i]>>4];
        txt[i*2+1] = hex[bin[i]&0xF];
    }
}
