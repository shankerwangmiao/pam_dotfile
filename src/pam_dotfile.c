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
#include <stdarg.h>
#include <pwd.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/_pam_macros.h>

#include "md5.h"
#include "md5util.h"
#include "common.h"
#include "log.h"

#define HELPERTOOL SBINDIR"/pam-dotfile-helper"

#ifndef PAM_FAIL_DELAY
#define pam_fail_delay(x,y) 0
#endif 

#define PAM_DOTFILE_DELAY 3000000

static void sigchld(int sig)  {
}

static int _fork_authentication(context_t *c, const char *username, const char *password) {
    pid_t pid;
    int r = PAM_SYSTEM_ERR, p[2];
    struct sigaction sa_save, sa;
    
    if (pipe(p) < 0) {
        logmsg(c, LOG_ERR, "pipe(): %s", strerror(errno));
	return PAM_SYSTEM_ERR;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld;
    sa.sa_flags = SA_RESTART;
        
    if (sigaction(SIGCHLD, &sa, &sa_save) < 0) {
        logmsg(c, LOG_ERR, "sigaction(): %s", strerror(errno));
        goto finish;
    }
        
    if ((pid = fork()) < 0) {
        logmsg(c, LOG_ERR, "fork(): %s", strerror(errno));
        goto finish;
    } else if (pid == 0) {
	char * const args[] = {
            HELPERTOOL,
            x_strdup(c->service), 
	    x_strdup(username),
            c->opt_debug ? "debug" : "nodebug", 
	    c->opt_no_warn ? "no_warn" : "warn",
            c->opt_stat_only_home ? "stat_only_home" : "stat_all",
#ifdef COMPAT05
            c->opt_nocompat05 ? "nocompat05" : "compat05",
#else
            "nocompat05", 
#endif
            NULL
        };
        char * envp[] = { NULL };

        if (p[0] != 0 && dup2(p[0], 0) != 0) {
            logmsg(c, LOG_ERR, "dup2(): %s", strerror(errno));
            exit(2);
        }
        
	close(1);
        close(2);
	close(p[0]);
	close(p[1]);

        if (open("/dev/null", O_WRONLY) != 1) {
            logmsg(c, LOG_ERR, "open(\"/dev/null\", O_WRONLY): %s", strerror(errno));
            exit(2);
        }

        if (open("/dev/null", O_WRONLY) != 2) {
            logmsg(c, LOG_ERR, "open(\"/dev/null\", O_WRONLY): %s", strerror(errno));
            exit(2);
        }

	execve(HELPERTOOL, args, envp);
        
        logmsg(c, LOG_ERR, "execve(): %s", strerror(errno));
        
	exit(100);
    } else if (pid > 0) {
        FILE *f;
        int r2;
        
        close(p[0]);
        
        if (!(f = fdopen(p[1], "w"))) {
            logmsg(c, LOG_ERR, "fdopen() failed.");
            goto finish;
        } else {
            fputs(password, f);
            fflush(f);
        }

        fclose(f);
        close(p[1]);
        
        if (waitpid(pid, &r2, 0) < 0) {
            logmsg(c, LOG_ERR, "waitpid(): %s", strerror(errno));
            goto finish;
        } else {
            if (WIFEXITED(r2)) {
                logmsg(c, LOG_DEBUG, "Helper returned %u", WEXITSTATUS(r2));

                switch (WEXITSTATUS(r2)) {
                    case 0: r = PAM_SUCCESS; break;
                    case 1: r = PAM_AUTH_ERR; break;
                    case 2: r = PAM_AUTHINFO_UNAVAIL; break;
                    case 3: r = PAM_USER_UNKNOWN; break;
                }
            } else
                logmsg(c, LOG_ERR, "Helper failed abnormally");
        }
    }

finish:
    
    if (sigaction(SIGCHLD, &sa_save, NULL) < 0) {
        logmsg(c, LOG_ERR, "sigaction()#2: %s", strerror(errno));
        r = PAM_SYSTEM_ERR;
    }

    
    return r;
}

static int _authentication(context_t *c, const char *username, const char *password) {
    int b;
    
    if (!username || !*username) {
        logmsg(c, LOG_WARNING, "Authentication failure: null username supplied");
        return PAM_AUTH_ERR;
    }

    if (!password || (!c->opt_nullok && !*password)) {
        logmsg(c, LOG_WARNING, "Authentication failure: null password supplied");
        return PAM_AUTH_ERR;
    }
    
    b = geteuid() != 0;

    if (b && c->opt_fork < 0) {
        logmsg(c, LOG_ERR, "Option <nofork> set and uid != 0, failing");
        return PAM_SYSTEM_ERR;
    }
    
    if (c->opt_fork > 0)
        b = 1;

    if (!b)
        return user_authentication(c, username, password);
    else
        return _fork_authentication(c, username, password);
}

static int _parse_opt(context_t *c, int argc, const char **argv) {
    for (; argc; argc--, argv++) {
        if (!strcmp(*argv, "debug"))
            c->opt_debug = 1;
        else if (!strcmp(*argv, "use_first_pass") || !strcmp(*argv, "use_authtok"))
            c->opt_use_first_pass = 1;
        else if (!strcmp(*argv, "try_first_pass"))
            c->opt_try_first_pass = 1;
        else if (!strcmp(*argv, "rootok"))
            c->opt_rootok = 1;
        else if (!strcmp(*argv, "nullok"))
            c->opt_nullok = 1;
        else if (!strcmp(*argv, "fork"))
            c->opt_fork = 1;
        else if (!strcmp(*argv, "nofork"))
            c->opt_fork = -1;
        else if (!strcmp(*argv, "no_warn"))
            c->opt_no_warn = 1;
        else if (!strcmp(*argv, "stat_only_home"))
            c->opt_stat_only_home = 1;
#ifdef COMPAT05
        else if (!strcmp(*argv, "nocompat05"))
            c->opt_nocompat05 = 1;
#endif
        else
            logmsg(c, LOG_WARNING, "Invalid argument <%s>, ignoring", *argv);
    }

     return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *ph, int flags, int argc, const char **argv) {
    const char *username = NULL, *password = NULL, *service = NULL;
    int r;
    context_t c;
    const struct pam_conv *pc;
    static struct pam_message m[1] = { { msg_style: PAM_PROMPT_ECHO_OFF, msg : "Dotfile Password: " } };
    const static struct pam_message* pm[] = { &m[0] };
    struct pam_response *a;

    memset(&c, 0, sizeof(c));

    if ((r = _parse_opt(&c, argc, argv)) != PAM_SUCCESS)
        return r;

    if ((r = pam_get_user(ph, &username, NULL)) != PAM_SUCCESS) {
	logmsg(&c, LOG_ERR, "pam_get_user(): %s", pam_strerror(ph, r));
        return r;
    }

    if (!username || !*username) {
        logmsg(&c, LOG_DEBUG, "Authentication failure: no username supplied");
        return PAM_CRED_INSUFFICIENT;
    }

    if ((r = pam_get_item(ph, PAM_SERVICE, (const void**) &service)) != PAM_SUCCESS) {
        logmsg(&c, LOG_ERR, "pam_get_item(*, PAM_SERVICE, *): %s", pam_strerror(ph, r));
        return r;
    }

    c.service = service;

    if (c.opt_use_first_pass || c.opt_try_first_pass)
        if ((r = pam_get_item(ph, PAM_AUTHTOK, (const void**) &password)) != PAM_SUCCESS) {
            logmsg(&c, LOG_ERR, "pam_get_item(*, PAM_AUTHTOK, *): %s", pam_strerror(ph, r));
            return r;
        }
    
    if (c.opt_use_first_pass && !password) {
        logmsg(&c, LOG_DEBUG, "No password passed in PAM_AUTHTOK.");
        return PAM_CRED_INSUFFICIENT;
    }

    if (password) {
        if ((r = _authentication(&c, username, password)) == PAM_SUCCESS) {
            logmsg(&c, LOG_DEBUG, "Authentication with PAM_AUTHTOK sucessful");
            return PAM_SUCCESS;
        } else if (r != PAM_AUTH_ERR) {
            logmsg(&c, LOG_DEBUG, "Authentication with PAM_AUTHTOK failed (%i): %s", r, pam_strerror(ph, r));
            return r;
        }

        logmsg(&c, LOG_DEBUG, "Authentication with PAM_AUTHTOK failed");

        if (c.opt_use_first_pass) {
            pam_fail_delay(ph, PAM_DOTFILE_DELAY);
            return PAM_AUTH_ERR;
        }
    }
    
    if ((r = pam_get_item(ph, PAM_CONV, (const void**) &pc)) != PAM_SUCCESS) {
        logmsg(&c, LOG_ERR, "pam_get_item(*, PAM_CONV, *): %s", pam_strerror(ph, r));
        return r;
    }
    
    if (!pc || !pc->conv) {
        logmsg(&c, LOG_ERR, "conv() function invalid");
        return PAM_CONV_ERR;
    } 
    
    if ((r = pc->conv(1, pm, &a, pc->appdata_ptr)) != PAM_SUCCESS) {
        logmsg(&c, LOG_ERR, "conv(): %s", pam_strerror(ph, r));
        return r;
    }

    if (!a->resp) {
        logmsg(&c, LOG_ERR, "Got no password.");
        return PAM_CRED_INSUFFICIENT;
    }
            
    if ((r = pam_set_item(ph, PAM_AUTHTOK, x_strdup(a->resp))) != PAM_SUCCESS)
        return r;

    if ((r = _authentication(&c, username, a->resp)) == PAM_SUCCESS) {
        logmsg(&c, LOG_DEBUG, "Authentication with user password sucessful");
        return PAM_SUCCESS;
    } else if (r != PAM_AUTH_ERR) {
        logmsg(&c, LOG_DEBUG, "Authentication with PAM_AUTHTOK failed (%i): %s", r, pam_strerror(ph, r));
        return r;
    }
        
    logmsg(&c, LOG_DEBUG, "Authentication failed with user password");
    pam_fail_delay(ph, PAM_DOTFILE_DELAY);
    return PAM_AUTH_ERR;            
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
     return PAM_SUCCESS;
}
