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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "md5.h"
#include "md5util.h"

#ifdef COMPAT05
int compat = 0;
#endif

static void _random(char *r, int l) {
    FILE *f;
    int b = 0;

    if ((f = fopen("/dev/urandom", "r"))) {
        if (fread(r, l, 1, f) == 1)
            b = 1;
        fclose(f);
    }

    if (!b) {
        int i;
        fprintf(stderr, "WARNING: Could not read /dev/urandom, generating pseudo randomness.\n");

        for (i = 0; i < l; i++)
            r[i] = (unsigned char) rand() & 0xFF;
    }
}

static void _md5_gen(const char *password, FILE *f) {
    static unsigned char salt[16];
    static char saltc[33];
    static unsigned char  digest[16];
    static char digestc[33];
    md5_state_t t;
    
    _random(salt, 16);
    
    fhex(salt, 16, saltc);
    saltc[32] = 0;

    md5_init(&t);
    md5_append(&t, saltc, 32);
    md5_append(&t, password, strlen(password));
    md5_finish(&t, digest);

#ifdef COMPAT05
    if (compat)
        fhex_broken_md5(digest, digestc);
    else
#endif
        fhex_md5(digest, digestc);
    digestc[32] = 0;

#ifdef COMPAT05
    fprintf(f, "%s%s%s\n", compat ? "" : "+", saltc, digestc);
#else
    fprintf(f, "+%s%s\n", saltc, digestc);
#endif
}

void usage(char *argv0) {
    char *p;

    if ((p = strrchr(argv0, '/')))
        p++;
    else
        p = argv0;
    
#ifdef COMPAT05
    printf("%s [-C] [-a <service>] | -h\n"
#else
    printf("%s [-a <service>] | -h\n"
#endif
           "    -a <service>    Add a password for the specified service\n"
           "    -h              Show this help\n"
#ifdef COMPAT05
           "    -C              Enable compatibility with pam_dotfile <= 0.5\n"
#endif
           , p);
}

char *chomp(char *p) {
    char *e;

    while ((e = strchr(p, '\n')))
        *e = 0;

    return p;
}

int set_echo(int fd, int b) {
    static struct termios saved;
    
    if (!b) {
        static struct termios t;

        if (tcgetattr(fd, &saved) < 0) {
            fprintf(stderr, "tcgetattr(): %s\n", strerror(errno));
            return -1;
        }

        t = saved;
        t.c_lflag &= ~ECHO;
            
        if (tcsetattr(fd, TCSANOW, &t) < 0) {
            fprintf(stderr, "tcsetattr(): %s\n", strerror(errno));
            return -1;
        }
        
    } else {
        if (tcsetattr(fd, TCSANOW, &saved) < 0) {
            fprintf(stderr, "tcsetattr(): %s\n", strerror(errno));
            return -1;
        }
    }
    

    return 0;
}

int add_password(char *p) {
    FILE *f = NULL;
    static char fn[PATH_MAX];
    static char password1[128], password2[128];
    int r = -1;
    int e = 0;
    mode_t m;

    if (isatty(STDIN_FILENO)) {
        if (set_echo(STDIN_FILENO, 0) < 0)
            goto finish;

        e = 1;
    }

    snprintf(fn, sizeof(fn), "%s/.pam-%s", getenv("HOME"), p);

    m = umask(0077);
    if (!(f = fopen(fn, "a"))) {
        umask(m);
        fprintf(stderr, "Could not open file <%s> for writing: %s\n", fn, strerror(errno));
        goto finish;
    }
    umask(m);

    if (isatty(STDIN_FILENO)) {
        fputs("Password:", stdout);
        fflush(stdout);
    }

    if (!fgets(password1, sizeof(password1), stdin)) {
        fprintf(stderr, "Failure reading password\n");
        goto finish;
    }
    
    if (isatty(STDIN_FILENO)) {
        fputs("\nPlease repeat; password:", stdout);
        fflush(stdout);
    }
    
    if (!fgets(password2, sizeof(password2), stdin)) {
        fprintf(stderr, "Failure reading password\n");
        goto finish;
    }

    if (isatty(STDIN_FILENO)) {
        fputs("\n", stdout);
        fflush(stdout);
    }

    chomp(password1);
    chomp(password2);

    if (strcmp(password1, password2)) {
        fprintf(stderr, "ERROR: Passwords do not match!\n");
        goto finish;
    }

    _md5_gen(password1, f);

    fprintf(stderr, "Password added.\n");
    
    r = 0;
    
finish:
    if (e)
        set_echo(STDIN_FILENO, 1);
    
    if (f) {
        fclose(f);
        chmod(fn, 0600);
    }
    
    return 0;
}

int main(int argc, char*argv[]) {
    int c;
#ifdef COMPAT05
    const char* argspec = "a:hC";
#else
    const char* argspec = "a:h";
#endif
    char *addp = 0;
        
    srand(time(NULL)*getpid());
    

    while ((c = getopt(argc, argv, argspec)) > 0) {
        
        switch (c) {
            case 'a' :
                addp = optarg;
                break;
                
#ifdef COMPAT05
            case 'C':
                compat = 1;
                break;
#endif                    
                
            default:
                usage(argv[0]);
                return 1;
        }
    }


    if (addp)
        return add_password(addp) < 0 ? 1 : 0;
    
    for(;;) {
        int n;
        static char ln[256];
        
        if (!fgets(ln, sizeof(ln), stdin))
            break;

        if (ln[0] == 0 || ln[0] == '\n' || ln[0] == '#') {
            fputs(ln, stdout);
            continue;
        }

        if (ln[(n = strlen(ln))-1] == '\n')
            ln[n-1] = 0;

        _md5_gen(ln, stdout);
    }

    return 0;
}
