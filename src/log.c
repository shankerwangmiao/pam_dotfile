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

#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>

#include "log.h"

void logmsg(context_t *c, int level, char *format, ...) {
    va_list ap;
    va_start(ap, format);

//    vfprintf(stderr, format, ap);
//    fprintf(stderr, "\n");
    
    if (c->opt_debug || (level != LOG_DEBUG && level != LOG_WARNING) || (level == LOG_WARNING && !c->opt_no_warn)) {
        static char ln[256];
        char *p;
        
        if (c->service)
            snprintf(p = ln, sizeof(ln), "%s(pam_dotfile)", c->service);
        else
            p = "pam_dotfile";
        
        openlog(p, LOG_PID, LOG_AUTHPRIV);
        vsyslog(level, format, ap);
        closelog();
    }

    va_end(ap);
}
