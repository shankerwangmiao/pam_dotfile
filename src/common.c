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

#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <pwd.h>

#include "common.h"
#include "md5.h"
#include "md5util.h"
#include "log.h"

static int _md5_compare(context_t *c, const char *password, const char *ln) {
    md5_state_t st;
    static md5_byte_t digest[16];
    static char t[33];
#ifdef COMPAT05
    int olddigest = 0;
#endif
    
    if (ln[0] == '+')
        ln++;
    else {
#ifdef COMPAT05
        if (!c->opt_nocompat05)
            olddigest = 1;
        else {
#endif
            logmsg(c, LOG_WARNING, "Authentication failure: pam_dotfile configured whithout compatibility for <= 0.5, but used with <= 0.5 authentication data");
            return PAM_AUTH_ERR;
#ifdef COMPAT05
        }
#endif
    }
    
    if (strlen(ln) != 64) {
        logmsg(c, LOG_WARNING, "Authentication failure: broken MD5 digest");
        return PAM_AUTH_ERR;
    }
    
    md5_init(&st);
    md5_append(&st, ln, 32);
    md5_append(&st, password, strlen(password));
    md5_finish(&st, digest);

#ifdef COMPAT05    
    if (olddigest)
        fhex_broken_md5(digest, t);
    else
#endif
        fhex_md5(digest, t);

    t[32] = 0;

    return strcmp(ln+32, t) ? PAM_AUTH_ERR : PAM_SUCCESS;
}

static int _check_parent_dirs(const char *base, const char *fn) {
    static char p[PATH_MAX];
    static struct stat st;
    int size_base;
    int retval;

    size_base = snprintf(p, sizeof(p) - 1, "%s", base);
    if (size_base >= (sizeof(p) - 1))
        return -1;

    retval = snprintf(&(p[size_base]), sizeof(p) - size_base, "%s", fn);
    if (retval >= (sizeof(p) - size_base))
        return -1;
    

    for (;;) {
        char *slash = strrchr(p, '/');

        if (slash == p || !slash)
            return 0;

	if (slash < &(p[size_base]))
            return 0;
        

        *slash = 0;

        if (lstat(p, &st) < 0)
            return -1;

        if (st.st_mode & 022)
            return -1;
    }
}

int user_authentication(context_t *c, const char *username, const char *password) {
    struct passwd *pw;
    FILE *f;
    static char fn[PATH_MAX];
    static char pam_fn[PATH_MAX];
    static struct stat st;
    int ret;
    
    if (!(pw = getpwnam(username))) {
        logmsg(c, LOG_WARNING, "Authentication failure: user <%s> not found", username);
        return PAM_USER_UNKNOWN;
    }

    if (!c->opt_rootok && pw->pw_uid == 0) {
        logmsg(c, LOG_WARNING, "Authentication failure: access denied for root");
        return PAM_AUTH_ERR;
    }

    logmsg(c, LOG_DEBUG, "Searching file for service %s", c->service);

    snprintf(fn, sizeof(fn), "%s/.pam-%s", pw->pw_dir, c->service);
    snprintf(pam_fn, sizeof(fn), "/.pam-%s", c->service);
    if (!(f = fopen(fn, "r")) && errno == ENOENT) {
        snprintf(fn, sizeof(fn), "%s/.pam/%s", pw->pw_dir, c->service);
	snprintf(pam_fn, sizeof(fn), "/.pam/%s", c->service);
        if (!(f = fopen(fn, "r")) && errno == ENOENT) {
            snprintf(fn, sizeof(fn), "%s/.pam-other", pw->pw_dir);
	    snprintf(pam_fn, sizeof(fn), "/.pam-other");
            if (!(f = fopen(fn, "r")) && errno == ENOENT) {
                snprintf(fn, sizeof(fn), "%s/.pam/other", pw->pw_dir);
		snprintf(pam_fn, sizeof(fn), "/.pam/other");
                if (!(f = fopen(fn, "r")) && errno == ENOENT) {
                    logmsg(c, LOG_WARNING, "Authentication failure: no .pam file in home directory of <%s> existent", username);
                    return PAM_AUTHINFO_UNAVAIL;
                }
            }
        }
    }

    if (!f) {
        logmsg(c, LOG_WARNING, "Authentication failure: could not open .pam file in home directory of <%s>", username);
        return PAM_AUTH_ERR;
    }

    if (lstat(fn, &st) < 0) {
        logmsg(c, LOG_ERR, "Could not lstat() file %s: %s", fn, strerror(errno));
        fclose(f);
        return PAM_AUTH_ERR;
    }

    if (!S_ISREG(st.st_mode)) {
        logmsg(c, LOG_ERR, "%s ist not a regular file: %s", fn, strerror(errno));
        fclose(f);
        return PAM_AUTH_ERR;
    }
    
    if (fstat(fileno(f), &st) < 0) {
        logmsg(c, LOG_ERR, "Could not fstat() file %s: %s", fn, strerror(errno));
        fclose(f);
        return PAM_AUTH_ERR;
    }

    if (st.st_mode & 0077) {
        logmsg(c, LOG_WARNING, "Authentication failure: bad access mode of file %s: %04o, correct is 0600\n", fn, st.st_mode & 07777);
        fclose(f);
        return PAM_AUTH_ERR;
    }

    if (st.st_uid != pw->pw_uid) {
        logmsg(c, LOG_WARNING, "Authentication failure: bad owner of file %s: %u, correct is %u\n", fn, st.st_uid, pw->pw_uid);
        fclose(f);
        return PAM_AUTH_ERR;
    }

    if ((c->opt_stat_only_home ? _check_parent_dirs(pw->pw_dir, pam_fn) : _check_parent_dirs("", fn)) < 0) {
        logmsg(c, LOG_ERR, "Parent directories of %s must not be group or world writable", fn);
        fclose(f);
        return PAM_AUTH_ERR;        
    }

    ret = PAM_AUTH_ERR;
    while (!feof(f)) {
        static char ln[100];
        int n;

        if (!fgets(ln, sizeof(ln), f))
            break;

        if (ln[0] == 0 || ln[0] == '\n' || ln[0] == '#')
            continue;
        
        if (ln[(n = strlen(ln))-1] == '\n')
            ln[n-1] = 0;

        if (!_md5_compare(c, password, ln)) {
            ret = PAM_SUCCESS;
            break;
        }
    }
    
    fclose(f);

    if (ret == PAM_SUCCESS)
        logmsg(c, LOG_INFO, "Authentication successful for user <%s>", username);
    else
        logmsg(c, LOG_WARNING, "Authentication failure: bad password for user <%s>", username);
    
    return ret;
}
