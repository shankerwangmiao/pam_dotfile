#ifndef foocommonhfoo
#define foocommonhfoo

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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define PAM_SM_AUTH
#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif
#ifdef HAVE_SECURITY__PAM_MACROS_H
#include <security/_pam_macros.h>
#endif

#ifndef PAM_EXTERN
#ifdef PAM_STATIC
#define PAM_EXTERN static
#else
#define PAM_EXTERN extern
#endif
#endif

typedef struct context {
    int opt_debug;
    int opt_use_first_pass;
    int opt_try_first_pass;
    int opt_rootok;
    int opt_nullok;
    int opt_fork;  // 0: auto; 1: fork; -1: nofork;
    int opt_no_warn;
    int opt_stat_only_home;
#ifdef COMPAT05
    int opt_nocompat05;
#endif
    const char *service;
} context_t;

int user_authentication(context_t *c, const char *username, const char *password);

extern char *x_strdup (const char *string);

#endif
