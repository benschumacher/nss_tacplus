#include <sys/types.h>

#include <dlfcn.h>
#include <libgen.h>
#include <nss.h>
#include <pwd.h>
#include <stdio.h>

typedef enum nss_status (*_nss_getpwnam_r_cb)(char *, struct passwd *, char *, size_t, int *);
int main(int argc, char *argv[])
{
    void *dlh = NULL;
    void *fh = NULL;

    if (argc < 3)
    {
        const char *name = basename(argv[0]);
        fprintf(stderr, "Usage: %s <soname> <funcname> [<username>]\n", name);
        return 1;
    }

    dlh = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (NULL == dlh)
    {
        fprintf(stderr, "Error: Can't load `%s': %s\n", argv[1], dlerror());
        return 2;
    }

    dlerror(); // Clear any existing error

    fh = dlsym(dlh, argv[2]);
    if (NULL == fh)
    {
        fprintf(stderr, "Error: Can't find symbol `%s': %s\n", argv[2],
                dlerror());
        return 3;
    }

    {
        char *name = (3 == argc ? "bschumac" : argv[3]);
        enum nss_status rv = NSS_STATUS_NOTFOUND;
        struct passwd pw;
        char buf[1024];
        int errnum = 0;
        
        rv = (*(_nss_getpwnam_r_cb)fh)(name, &pw, buf, sizeof(buf), &errnum);
        if (NSS_STATUS_SUCCESS != rv)
        {
            fprintf(stderr, "Error: Can't find user `%s': %d\n", name, rv);
            return 4;
        }
        else
        {
            printf("User `%s' found:\n", name);
            printf("%s:%s:%u:%u:%s:%s:%s\n", pw.pw_name, pw.pw_passwd, pw.pw_uid,
                   pw.pw_gid, pw.pw_gecos, pw.pw_dir, pw.pw_shell);
        }
    }

    dlclose(dlh);

    return 0;
}

