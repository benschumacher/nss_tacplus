#include "libtac/libtac.h"

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <nss.h>
#include <pthread.h>
#include <pwd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <grp.h>

#define TACPLUS_CONF_FILE "/etc/tacplus.conf"
#define CONFIG_BUFSZ 4096

static pthread_once_t G_tacplus_initialized = PTHREAD_ONCE_INIT;
static time_t G_tacplus_started = -1;
static uint32_t G_tacplus_cycles = 0;
static char G_tacplus_confbuf[CONFIG_BUFSZ];
struct tacplus_server_st
{
    struct addrinfo *server;
    char *secret;
    struct tacplus_server_st *next;
};
struct tacplus_group_map_st
{
    char *remote_group;
    char *local_group;
    struct tacplus_group_map_st *next;
};
struct tacplus_shell_map_st
{
    char *remote_group;
    char *shell;
    struct tacplus_shell_map_st *next;
};
static struct tacplus_conf_st
{
    enum nss_status status;
    int errnum;

    time_t mtime;

    struct tacplus_server_st *servers;
    struct tacplus_server_st *lastsrv;

    uint32_t timeout;
    uint8_t debug_level;
    char *service;
    char *protocol;
    char *default_hashed_uid;
    char *default_home;
    char *default_shell;

    struct tacplus_group_map_st *group_map;
    struct tacplus_group_map_st *last_group_map;
    struct tacplus_shell_map_st *shell_map;
    struct tacplus_shell_map_st *last_shell_map;
} G_tacplus_conf;

static const char CONFKEY_SERVER[]       = "server";
static const char CONFKEY_SECRET[]       = "secret";
static const char CONFKEY_TIMEOUT[]      = "timeout";
static const char CONFKEY_DEBUGLVL[]     = "debug-level";
static const char CONFKEY_SERVICE[]      = "service";
static const char CONFKEY_PROTOCOL[]     = "protocol";
static const char CONFKEY_DEF_UID[]      = "default-hashed-uid";
static const char CONFKEY_DEF_HOME[]     = "default-home";
static const char CONFKEY_DEF_SHELL[]    = "default-shell";
static const char CONFKEY_MAPPED_GROUP[] = "mapped-group";
static const char CONFKEY_MAPPED_SHELL[] = "mapped-shell";

static const char NO_PASSWD[] = "x";

/* https://stackoverflow.com/questions/2351087/what-is-the-best-32bit-hash-function-for-short-strings-tag-names# */
/* modified to output in the range of 10000 - 2147483647 */
/* name_hash: compute hash value of string */
unsigned int name_hash(const char *str)
{
   unsigned int h;
   unsigned char *p;
   /* Empirically, the values 31 and 37 have proven to be good choices for the
      multiplier in a hash function for ASCII strings. */
   unsigned int MULTIPLIER=37;

   h = 0;
   for (p = (unsigned char*)str; *p != '\0'; p++)
      h = MULTIPLIER * h + *p;

   /* Enforce high range of 2147483647 */
   h &= 0x7fffffff;
   
   /* Enforce low range of 10000 */
   if (h < 10000)
      h += 10000;
   
   return h;
}

/**
 * Safely convert a base-10 string into an unsigned long. This function
 * doesn't alter `out' if the conversion fails.
 *
 * \param[in]  str the string source used for the conversion
 * \param[out] out an output variable for the converted value
 * \retval 0 on success, else -1
 */
static int8_t _safe_convert_ulong(const char *str, unsigned long *out)
{
    int8_t result = 0;
    unsigned long val = 0;
    char *endptr = NULL;

    assert(NULL != out);

    errno = 0;
    val = strtoul(str, &endptr, 10);

    if (   (ERANGE == errno && (ULONG_MAX == val || 0 == val))
        || (0 != errno && 0 == val))
    {
        char errtext[256];
        int errnum = errno;

        strerror_r(errnum, errtext, sizeof(errtext));
        syslog(LOG_ERR, "%s: strtoul got error: errno=%d, errtext=`%s'",
               __FILE__, errnum, errtext);

        result = -1;
    }

    if (str != endptr)
    {
        *out = val;
    }
    else
    {
        result = -1;
    }

    return result;
}

/**
 * Parses the configuration for this module. The format is simple:
 *   server <ip[:port]> secret <secret>        (can have multiple server lines)
 *   timeout <seconds>                         (used by all servers)
 *   service <TACACS+ service>                 (defaults to linuxlogin)
 *   protocol <TACACS+ protocol>               (defaults to ssh)
 *   default-hashed-uid <yes/no>               (defaults to no (UID from TACACS+))
 *   default-home <home prefix>                (defaults to HOME from TACACS+. Ex: /home)
 *   default-shell <shell>                     (defaults to SHELL from TACACS+. Ex: /bin/sh)
 *   mapped-group <remote group> <local group> (maps remote to local group)
 *   mapped-shell <remote group> <shell>       (maps remote group to shell)
 *   debug-level <int>                         (currently unused)
 *
 * \param[in] buffer a buffer than can be used to store string values
 * \param[in] buflen the length of the `buffer'
 * \retval enum nss_status NSS_STATUS_SUCCESS on succes, NSS_STATUS_UNAVAIL
 *                         if configuration file cannot be read,
 *                         NSS_STATUS_TRYAGAIN on potentially recoverable
 *                         conditions
 */
static enum nss_status _parse_config(char *buffer, size_t buflen)
{
    enum nss_status status = NSS_STATUS_SUCCESS;
    FILE *fp = NULL;
    struct stat conf_stat;
    char *offset = buffer;
    ptrdiff_t bufleft = buflen - (offset - buffer);
    char fbuf[CONFIG_BUFSZ];

    errno = 0;
    fp = fopen(TACPLUS_CONF_FILE, "r");
    if (NULL == fp)
    {
        char errtext[256];
        int errnum = errno;

        strerror_r(errnum, errtext, sizeof(errtext));
        syslog(LOG_ERR, "%s: fopen got error: errno=%d, errtext=`%s'",
               __FILE__, errnum, errtext);

        errno = errnum;
        return NSS_STATUS_UNAVAIL;
    }

    memset(&conf_stat, 0, sizeof(conf_stat));
    if (0 == fstat(fileno(fp), &conf_stat))
    {
        G_tacplus_conf.mtime = conf_stat.st_mtime;
    }

    // ensure that we have a timeout, by default
    tac_readtimeout_enable = 1;

    // read a line from the file
    while (NULL != fgets(fbuf, sizeof(fbuf), fp))
    {
        char *key = NULL;
        char *val = NULL;
        size_t len = 0;

        // ignore empty lines and comments
        if ('#' == *fbuf || '\n' == *fbuf)
        {
            continue;
        }

        // everything points to the beginning of the line
        key = val = fbuf;

        // the keyword is everything at the beginning of the line
        while ('\0' != *val && !isspace(*val))
        {
            ++val;
        }

        // keyword with no value? silently ignore
        if ('\0' == *val)
        {
            continue;
        }

        // null terminate keyword
        *(val++) = '\0';

        // move past remaining whitespace
        while (isspace(*val))
        {
            ++val;
        }

        len = strlen(val) - 1;
        while (isspace(val[len]))
        {
            --len;
        }
        val[++len] = '\0';

        if (0 == strncmp(key, CONFKEY_SERVER, sizeof(CONFKEY_SERVER)))
        {
            int rv = -1;
            char *srv = val;
            char *secret = NULL;
            struct addrinfo hints;

            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;

            struct addrinfo *server = NULL;
            char *port = NULL;

            // parse server and optional port
            while ('\0' != *srv && !isspace(*srv) && ':' != *srv)
            {
                ++srv;
            }
            if (':' == *srv)
            {
                *srv = '\0';
                port = ++srv;
                while ('\0' != *srv && !isspace(*srv))
                {
                    ++srv;
                }
            }
            *srv = '\0';

            // get ready to parse the next part of line (ex: secret)
            key = ++srv;

            // save server
            srv = val;

            // reset val to key
            val = key;

            // find "secret" keyword
            while ('\0' != *val && !isspace(*val))
            {
                ++val;
            }

            // null terminate keyword
            *(val++) = '\0';

            // no "secret" keyword or no secret value? log it, but continue
            if (0 != strncmp(key, CONFKEY_SECRET, sizeof(CONFKEY_SECRET)) ||
                '\0' == *val)
            {
                syslog(LOG_WARNING, "%s: server=`%s' is missing a secret",
                       __FILE__, srv);
            }
            else
            {
                // secret keyword and value found

                // move past remaining whitespace
                while (isspace(*val))
                {
                    ++val;
                }

                // rest of line is the secret value
                if (bufleft < strlen(val) + 1)
                {
                    errno = ERANGE;
                    status = NSS_STATUS_TRYAGAIN;
                    break;
                }

                secret = offset;
                while ('\0' != *val)
                {
                    *offset++ = *val++;
                }
                // null terminate offset
                *offset = '\0';
                bufleft = buflen - (++offset - buffer);
            }

            if (0 == (rv = getaddrinfo(srv, port ? port : "49", &hints,
                                       &server)))
            {
                assert(NULL != server);

                // allocate new entry
                struct tacplus_server_st *ts = (struct tacplus_server_st*)
                    malloc(sizeof(struct tacplus_server_st));
                ts->server = server;
                ts->secret = secret;
                ts->next = NULL;

                if (NULL == G_tacplus_conf.lastsrv)
                {
                    assert(NULL == G_tacplus_conf.servers);
                    G_tacplus_conf.lastsrv = G_tacplus_conf.servers = ts;
                }
                else
                {
                    assert(NULL != G_tacplus_conf.servers);
                    G_tacplus_conf.lastsrv->next = ts;
                }

                // iterate our linked-list to the end
                while (NULL != G_tacplus_conf.lastsrv->next)
                {
                    G_tacplus_conf.lastsrv = G_tacplus_conf.lastsrv->next;
                }
            }
        }
        else if (0 == strncmp(key, CONFKEY_TIMEOUT, sizeof(CONFKEY_TIMEOUT)))
        {
            unsigned long ulval;
            if (0 == _safe_convert_ulong(val , &ulval))
            {
                G_tacplus_conf.timeout = (0 == ulval ? 5 : ulval);
                tac_timeout = G_tacplus_conf.timeout;
            }
        }
        else if (0 == strncmp(key, CONFKEY_DEBUGLVL,
                              sizeof(CONFKEY_DEBUGLVL)))
        {
            unsigned long ulval;
            if (0 == _safe_convert_ulong(val , &ulval))
            {
                // we *only* have 255 levels of debug, so let's not
                // overflow our uint8_t.
                G_tacplus_conf.debug_level = (255 > ulval ? ulval : 255);
                // this probably doesn't do anything useful
                tac_debug_enable = G_tacplus_conf.debug_level;
            }
        }
        else if (0 == strncmp(key, CONFKEY_SERVICE, sizeof(CONFKEY_SERVICE)))
        {
            if (bufleft < strlen(val) + 1)
            {
                errno = ERANGE;
                status = NSS_STATUS_TRYAGAIN;
                break;
            }

            G_tacplus_conf.service = offset;
            while ('\0' != *val)
            {
                *offset++ = *val++;
            }
            bufleft = buflen - (++offset - buffer);
        }
        else if (0 == strncmp(key, CONFKEY_PROTOCOL,
                              sizeof(CONFKEY_PROTOCOL)))
        {
            if (bufleft < strlen(val) + 1)
            {
                errno = ERANGE;
                status = NSS_STATUS_TRYAGAIN;
                break;
            }

            G_tacplus_conf.protocol = offset;
            while ('\0' != *val)
            {
                *offset++ = *val++;
            }
            bufleft = buflen - (++offset - buffer);
        }
        else if (0 == strncmp(key, CONFKEY_DEF_UID, sizeof(CONFKEY_DEF_UID)))
        {
            if (bufleft < strlen(val) + 1)
            {
                errno = ERANGE;
                status = NSS_STATUS_TRYAGAIN;
                break;
            }

            G_tacplus_conf.default_hashed_uid = offset;
            while ('\0' != *val)
            {
                *offset++ = *val++;
            }
            bufleft = buflen - (++offset - buffer);
        }
        else if (0 == strncmp(key, CONFKEY_DEF_HOME, sizeof(CONFKEY_DEF_HOME)))
        {
            if (bufleft < strlen(val) + 1)
            {
                errno = ERANGE;
                status = NSS_STATUS_TRYAGAIN;
                break;
            }

            G_tacplus_conf.default_home = offset;
            while ('\0' != *val)
            {
                *offset++ = *val++;
            }
            bufleft = buflen - (++offset - buffer);
        }
        else if (0 == strncmp(key, CONFKEY_DEF_SHELL,
                              sizeof(CONFKEY_DEF_SHELL)))
        {
            if (bufleft < strlen(val) + 1)
            {
                errno = ERANGE;
                status = NSS_STATUS_TRYAGAIN;
                break;
            }

            G_tacplus_conf.default_shell = offset;
            while ('\0' != *val)
            {
                *offset++ = *val++;
            }
            bufleft = buflen - (++offset - buffer);
        }
        else if (0 == strncmp(key, CONFKEY_MAPPED_GROUP, sizeof(CONFKEY_MAPPED_GROUP)))
        {
            char *remote_group = NULL;
            char *local_group = NULL;

            // parse remote group
            if (bufleft < strlen(val) + 1)
            {
                errno = ERANGE;
                status = NSS_STATUS_TRYAGAIN;
                break;
            }

            remote_group = offset;
            while ('\0' != *val && !isspace(*val))
            {
                *offset++ = *val++;
            }
            // null terminate offset
            *offset = '\0';
            bufleft = buflen - (++offset - buffer);

            // move past remaining whitespace
            while (isspace(*val))
            {
                ++val;
            }

            // parse local group
            if (bufleft < strlen(val) + 1)
            {
                errno = ERANGE;
                status = NSS_STATUS_TRYAGAIN;
                break;
            }

            local_group = offset;
            while ('\0' != *val && !isspace(*val))
            {
                *offset++ = *val++;
            }
            // null terminate offset
            *offset = '\0';
            bufleft = buflen - (++offset - buffer);

            // allocate new entry
            struct tacplus_group_map_st *ts = (struct tacplus_group_map_st*)
                malloc(sizeof(struct tacplus_group_map_st));
            ts->remote_group = remote_group;
            ts->local_group = local_group;
            ts->next = NULL;

            if (NULL == G_tacplus_conf.last_group_map)
            {
                assert(NULL == G_tacplus_conf.group_map);
                G_tacplus_conf.last_group_map = G_tacplus_conf.group_map = ts;
            }
            else
            {
                assert(NULL != G_tacplus_conf.group_map);
                G_tacplus_conf.last_group_map->next = ts;
            }

            // iterate our linked-list to the end
            while (NULL != G_tacplus_conf.last_group_map->next)
            {
                G_tacplus_conf.last_group_map = G_tacplus_conf.last_group_map->next;
            }
        }
        else if (0 == strncmp(key, CONFKEY_MAPPED_SHELL, sizeof(CONFKEY_MAPPED_SHELL)))
        {
            char *remote_group = NULL;
            char *shell = NULL;

            // parse remote group
            if (bufleft < strlen(val) + 1)
            {
                errno = ERANGE;
                status = NSS_STATUS_TRYAGAIN;
                break;
            }

            remote_group = offset;
            while ('\0' != *val && !isspace(*val))
            {
                *offset++ = *val++;
            }
            // null terminate offset
            *offset = '\0';
            bufleft = buflen - (++offset - buffer);

            // move past remaining whitespace
            while (isspace(*val))
            {
                ++val;
            }

            // parse shell
            if (bufleft < strlen(val) + 1)
            {
                errno = ERANGE;
                status = NSS_STATUS_TRYAGAIN;
                break;
            }

            shell = offset;
            while ('\0' != *val && !isspace(*val))
            {
                *offset++ = *val++;
            }
            // null terminate offset
            *offset = '\0';
            bufleft = buflen - (++offset - buffer);

            // allocate new entry
            struct tacplus_shell_map_st *ts = (struct tacplus_shell_map_st*)
                malloc(sizeof(struct tacplus_shell_map_st));
            ts->remote_group = remote_group;
            ts->shell = shell;
            ts->next = NULL;

            if (NULL == G_tacplus_conf.last_shell_map)
            {
                assert(NULL == G_tacplus_conf.shell_map);
                G_tacplus_conf.last_shell_map = G_tacplus_conf.shell_map = ts;
            }
            else
            {
                assert(NULL != G_tacplus_conf.shell_map);
                G_tacplus_conf.last_shell_map->next = ts;
            }

            // iterate our linked-list to the end
            while (NULL != G_tacplus_conf.last_shell_map->next)
            {
                G_tacplus_conf.last_shell_map = G_tacplus_conf.last_shell_map->next;
            }
        }
        else
        {
            syslog(LOG_WARNING, "%s: unknown configuration key=`%s'",
                   __FILE__, key);
        }
    }

    fclose(fp);
    return status;
}

static void _check_config(int cycle)
{
    struct stat conf_stat;

    memset(&conf_stat, 0, sizeof(conf_stat));
    if (   0 != stat(TACPLUS_CONF_FILE, &conf_stat)
        || conf_stat.st_mtime == G_tacplus_conf.mtime)
    {
        // short-circuit if we can't stat the configuration file
        // or if the modification time hasn't changed
        // NOTE: we'll also reread if mtime moves backwards
        syslog(LOG_DEBUG, "%s: `%s' no change at cycle=%d",
               __FILE__, TACPLUS_CONF_FILE, cycle);
        return;
    }

    syslog(LOG_INFO, "%s: `%s' detected configuration change at cycle=%d",
           __FILE__, TACPLUS_CONF_FILE, cycle);

    // reload our configuration!
}

/**
 * Initialize the module. This should be called only once.
 */
static void _initalize_tacplus(void)
{
    enum nss_status status = NSS_STATUS_SUCCESS;
    struct tacplus_conf_st *conf = &G_tacplus_conf;

    memset(&G_tacplus_conf, 0, sizeof(G_tacplus_conf));
    memset(&G_tacplus_confbuf, 0, sizeof(G_tacplus_confbuf));

    G_tacplus_started = time(NULL);

    syslog(LOG_DEBUG, "%s: started, uid=(%u:%u), gid=(%u:%u)", __FILE__,
           getuid(), geteuid(), getgid(), getegid());

    status = _parse_config(G_tacplus_confbuf, sizeof(G_tacplus_confbuf));

    conf->status = status;
    conf->errnum = errno;
}

/**
 * Normalize the `attribute' name of TACACS+ AV pairs into environment
 * variable-compatible format.
 *
 * Effectively, upper case all ASCII characters, and convert dash (`-')
 * to underscore (`_').
 *
 * NOTE: Currently operates by-contract, with little error handling. In
 *       particular we don't bounds checks the length of the output buffer
 *       beyond the use of an assert. This is an internal function, so it
 *       should be safe, but it'd be worth revisiting if utilization was
 *       ever changed.
 *
 * \param[in] name The original version of the attribute.
 * \param[in] namelen The length of `name'.
 * \param[out] obuf A buffer that will be populated with the normalized
 *                  name, which will always be
 * \param[in] buflen The length of the output buffer, which must be at
 *                   least namelen + 1 in length.
 */
static void _normalize_name(const char *name, size_t namelen,
                            char *obuf, size_t buflen)
{
    size_t i = 0;

    // buflen had better be longer than namelen
    assert(buflen > namelen);

    for (; i < namelen; ++i)
    {
        if ('-' == name[i])
        {
            obuf[i] = '_';
        }
        obuf[i] = toupper(name[i]);
    }

    obuf[i] = '\0';
}

static const char TAC_ATTR_UID[] = "UID";
static const char TAC_ATTR_GID[] = "GID";
static const char TAC_ATTR_HOME[] = "HOME";
static const char TAC_ATTR_SHELL[] = "SHELL";
static const char TAC_ATTR_GROUP[] = "GROUP";

static const char *REQUIRED_TAC_ATTRS[] =
    {
        TAC_ATTR_UID,
        TAC_ATTR_GID,
        TAC_ATTR_HOME,
        TAC_ATTR_SHELL,
        NULL
    };
#define REQUIRED_TAC_ATTRS_LEN (sizeof(REQUIRED_TAC_ATTRS) / sizeof(char*))

/**
 * ... more documentation ...
 */
static int _passwd_from_reply(const struct areply *reply, const char *name,
                              struct passwd *pw, char *buffer, size_t buflen,
                              int *errnop)
{
    struct tac_attrib *attr = NULL;
    enum nss_status status = NSS_STATUS_SUCCESS;
    char *offset = buffer;
    const char *attr_good[REQUIRED_TAC_ATTRS_LEN] = { 0 };
    ptrdiff_t bufleft = buflen - (offset - buffer);
    char *group = NULL;
    char *shell = NULL;
    struct tacplus_group_map_st *group_map_entry = NULL;
    struct tacplus_shell_map_st *shell_map_entry = NULL;

#define mark_attr_good(attrptr)                          \
    for (size_t i = 0; i < REQUIRED_TAC_ATTRS_LEN; ++i)  \
    {                                                    \
        if ((attrptr) == attr_good[i])                   \
        {                                                \
            break;                                       \
        }                                                \
        else if (NULL == attr_good[i])                   \
        {                                                \
            attr_good[i] = (attrptr);                    \
            break;                                       \
        }                                                \
    }

#define is_attr_good(attrptr)                            \
({                                                       \
    bool is_good = false;                                \
    for (size_t i = 0; i < REQUIRED_TAC_ATTRS_LEN; ++i)  \
    {                                                    \
        if ((attrptr) == attr_good[i])                   \
        {                                                \
            is_good = true;                              \
        }                                                \
    }                                                    \
    is_good;                                             \
})

    // nullify the attr_good variable
    memset(attr_good, 0, sizeof(attr_good));

    // let's clear out the buffer -- this will simplify code below
    memset(buffer, '\0', buflen);

    // populate pw_name using the 'name' provided
    if (bufleft < strlen(name) + 1)
    {
        goto buffer_full;
    }

    // set pw_name and pw_gecos to the same value
    pw->pw_name = pw->pw_gecos = offset;
    while ('\0' != *name)
    {
        *offset++ = *name++;
    }
    bufleft = buflen - (++offset - buffer);

    // password is always notset, so use a constant
    pw->pw_passwd = (char*)NO_PASSWD;

    attr = reply->attr;
    while (NULL != attr && NSS_STATUS_SUCCESS == status)
    {
        char *sep = NULL;

        sep = strchr(attr->attr, '=');
        if (NULL == sep)
        {
            sep = strchr(attr->attr, '*');
        }
        if (NULL != sep)
        {
            char tmp[attr->attr_len]; // non-portable, but works for GCC
            char *value = (sep + 1);  // value starts after seperator
            size_t namsz = sep - attr->attr;

            memset(tmp, '\0', sizeof(tmp));

            _normalize_name(attr->attr, namsz, tmp, sizeof(tmp));

            if (0 == strcmp(tmp, TAC_ATTR_UID))
            {
                unsigned long ulval;
                if (0 == _safe_convert_ulong(value , &ulval))
                {
                    pw->pw_uid = ulval;
                    mark_attr_good(TAC_ATTR_UID);
                }
                else
                {
                    *errnop = errno;
                    status = NSS_STATUS_TRYAGAIN;
                }
            }
            if (0 == strcmp(tmp, TAC_ATTR_GID))
            {
                unsigned long ulval;
                if (0 == _safe_convert_ulong(value, &ulval))
                {
                    pw->pw_gid = ulval;
                    mark_attr_good(TAC_ATTR_GID);
                }
                else
                {
                    *errnop = errno;
                    status = NSS_STATUS_TRYAGAIN;
                }
            }
            if (0 == strcmp(tmp, TAC_ATTR_HOME))
            {
                if (bufleft < strlen(value) + 1)
                {
                    goto buffer_full;
                }

                pw->pw_dir = offset;
                while ('\0' != *value)
                {
                    *offset++ = *value++;
                }
                bufleft = buflen - (++offset - buffer);
                mark_attr_good(TAC_ATTR_HOME);
            }
            if (0 == strcmp(tmp, TAC_ATTR_SHELL))
            {
                if (bufleft < strlen(value) + 1)
                {
                    goto buffer_full;
                }

                if (!is_attr_good(TAC_ATTR_SHELL))
                {
                    // If shell was not set via a mapped group, process it
                    pw->pw_shell = offset;
                    mark_attr_good(TAC_ATTR_SHELL);
                }

                while ('\0' != *value)
                {
                    *offset++ = *value++;
                }
                bufleft = buflen - (++offset - buffer);
            }
            if (0 == strcmp(tmp, TAC_ATTR_GROUP))
            {
                if (bufleft < strlen(value) + 1)
                {
                    goto buffer_full;
                }

                group = offset;
                while ('\0' != *value)
                {
                    *offset++ = *value++;
                }
                bufleft = buflen - (++offset - buffer);

                // Iterate through our mapped group list
                for (group_map_entry = G_tacplus_conf.group_map;
                     NULL != group_map_entry;
                     group_map_entry = group_map_entry->next)
                {
                    if (0 == strcmp(group_map_entry->remote_group, group))
                    {
                        // Now find the mapped shell
                        // Iterate through our mapped shell list
                        for (shell_map_entry = G_tacplus_conf.shell_map;
                             NULL != shell_map_entry;
                             shell_map_entry = shell_map_entry->next)
                        {
                            if (0 == strcmp(shell_map_entry->remote_group, group))
                            {
                                // Found group in map, substitute mapped group name
                                shell = shell_map_entry->shell;
                                break;
                            }
                        }

                        // Found group in map, substitute mapped group name
                        group = group_map_entry->local_group;
                        syslog(LOG_WARNING, "%s: mapped group: %s, mapped shell: %s", __FILE__, group, shell);
                        break;
                    }
                }

                // Map group name to gid
                errno = 0;
                struct group *grp = getgrnam(group);
                if (grp)
                {
                    pw->pw_gid = grp->gr_gid;
                    mark_attr_good(TAC_ATTR_GID);

                    // Now that gid is good, check if a shell was mapped
                    if (NULL != shell)
                    {
                        pw->pw_shell = shell;
                        mark_attr_good(TAC_ATTR_SHELL);
                    }
                }
                else
                {
                    *errnop = errno;
                    status = NSS_STATUS_TRYAGAIN;
                }
            }
        }
        else
        {
            syslog(LOG_WARNING,
                   "%s: invalid attribute `%s', no separator",
                   __FILE__, attr->attr);
        }

        attr = attr->next;
    }

    for (size_t o = 0; NULL != REQUIRED_TAC_ATTRS[o]; ++o)
    {
        const char *cur = REQUIRED_TAC_ATTRS[o];
        bool seen = false;

        for (size_t i = 0; NULL != attr_good[i]; ++i)
        {
            if (cur == attr_good[i])
            {
                seen = true;
                break;
            }
        }

        if (!seen)
        {
            if ((0 == strcmp(cur, TAC_ATTR_UID)) &&
                (0 == strcmp(G_tacplus_conf.default_hashed_uid, "yes")))
            {
                pw->pw_uid = name_hash(pw->pw_name);
            }
            else if ((0 == strcmp(cur, TAC_ATTR_HOME)) &&
                     (NULL != G_tacplus_conf.default_home))
            {
                char *dir = (char*) malloc(sizeof(char)*80);
                sprintf(dir, "%s/%s", G_tacplus_conf.default_home, pw->pw_name);
                pw->pw_dir = dir;
            }
            else if ((0 == strcmp(cur, TAC_ATTR_SHELL)) &&
                     (NULL != G_tacplus_conf.default_shell))
            {
                pw->pw_shell = G_tacplus_conf.default_shell;
            }
            else
            {
                syslog(LOG_WARNING, "%s: missing required attribute '%s'",
                       __FILE__, cur);
                status = NSS_STATUS_NOTFOUND;
            }
        }
    }

    return status;

buffer_full:
    *errnop = ERANGE;
    return NSS_STATUS_TRYAGAIN;
}

/**
 * ... document me ...
 */
enum nss_status _nss_tacplus_getpwnam_r(const char *name, struct passwd *pw,
                                        char *buffer, size_t buflen,
                                        int *errnop)
{
    enum nss_status status = NSS_STATUS_NOTFOUND;
    int tac_fd = -1;
    struct tacplus_server_st *server = NULL;
    time_t now = -1;
    uint32_t cycle = 0;

    // If user is "*" or "%q", exit immediately, as this causes hanging on
    // the command line with tab completion if any of the tacacs+ servers
    // are down.  "*" is seen for normal bash tab competion and "%q" is
    // seen when "~" (home dir shortcut) is part of the tab completion.
    if ((0 == strcmp(name, "*")) || (0 == strcmp(name, "%q")))
    {
        return status;
    }

    (void)pthread_once(&G_tacplus_initialized, &_initalize_tacplus);
    now = time(NULL);

    // check to see if we should re-read our configuration
    // once per 32 second cycle
    cycle = (now - G_tacplus_started) >> 5;
    if (   NSS_STATUS_SUCCESS != G_tacplus_conf.status
        || cycle > G_tacplus_cycles)
    {
        G_tacplus_cycles = cycle;
        _check_config(cycle);
    }
    else
    {
        G_tacplus_cycles = cycle;
    }

    if (NSS_STATUS_SUCCESS != G_tacplus_conf.status)
    {
        status = G_tacplus_conf.status;
        *errnop = G_tacplus_conf.errnum;

        assert(NULL == G_tacplus_conf.servers);
    }

    // Iterate through our servers linked list, stop when we get an answer
    // that isn't NOTFOUND. Since we're twisting TACACS+ authorization
    // functionality to provide this facility, we treat AUTHOR_STATUS_FAIL,
    // AUTHOR_STATUS_ERROR, AUTHOR_STATUS_FAIL as "soft" fails, and just
    // move on to the next server. Doing otherwise would result in potentially
    // unexpected behaviors if the user is provisioned on server->ai_next, but
    // not on server.
    for (server = G_tacplus_conf.servers;
         NSS_STATUS_NOTFOUND == status && NULL != server;
         server = server->next)
    {
        void *sin_addr = NULL;

        // the first member of sockaddr_in and sockaddr_in6 are the same, so
        // this should always work.
        uint16_t port = ntohs(((struct sockaddr_in *)
                               server->server->ai_addr)->sin_port);

        // this is ugly, but we need to differentiate IPv6 vs. IPv4 addresses
        // (in practice, this may not be necessary, as I'm not certain if the
        // remainder of this code is capable of handling IPv6, yet.)
        sin_addr = (  AF_INET6 == server->server->ai_family
                    ? (void*)&((struct sockaddr_in6 *)
                               server->server->ai_addr)->sin6_addr
                    : (void*)&((struct sockaddr_in *)
                               server->server->ai_addr)->sin_addr);
        inet_ntop(server->server->ai_family, sin_addr, buffer, buflen);

        syslog(LOG_INFO, "%s: begin lookup: user=`%s', server=`%s:%d'",
               __FILE__, name, buffer, port);

        // connect to the current server
        errno = 0;
        tac_fd = tac_connect_single(server->server, server->secret, NULL, 15);

        if (0 > tac_fd)
        {
            char errtext[256];
            int errnum = errno;

            strerror_r(errnum, errtext, sizeof(errtext));
            syslog(LOG_WARNING,
                   "%s: Connection to TACACS+ server failed: server=`%s:%d', "
                   "errno=%d, errtext=`%s'",
                   __FILE__, buffer, port, errnum, errtext);

             // upon failure, simply move on to the next server in the list
            continue;
        }
        else
        {
            int rv = -1;
            struct tac_attrib *attr = NULL;

            tac_add_attrib(&attr, "service", G_tacplus_conf.service);
            tac_add_attrib(&attr, "protocol", G_tacplus_conf.protocol);

            rv = tac_author_send(tac_fd, name, G_tacplus_conf.protocol,
                                 "unknown", attr);

            tac_free_attrib(&attr);

            if (0 > rv)
            {
                status = NSS_STATUS_TRYAGAIN;
            }
            else
            {
                struct areply reply;

                memset(&reply, '\0', sizeof(reply));
                tac_author_read(tac_fd, &reply);

                if (   (AUTHOR_STATUS_PASS_ADD == reply.status)
                    || (AUTHOR_STATUS_PASS_REPL == reply.status))
                {
                    syslog(LOG_INFO,
                           "%s: found match: user=`%s', server=`%s:%d', "
                           "status=%d, attributes? %s",
                           __FILE__, name, buffer, port, reply.status,
                           (NULL == reply.attr ? "no" : "yes"));
                    status = _passwd_from_reply(&reply, name, pw, buffer,
                                                buflen, errnop);
                }
                else
                {
                    syslog(LOG_INFO,
                           "%s: lookup failed: user=`%s', server=`%s:%d', "
                           "status=%d, msg=%s", __FILE__, name, buffer, port,
                           reply.status, reply.msg);
                }
                if (NULL != reply.attr)
                {
                    tac_free_attrib(&reply.attr);
                }
                free(reply.msg);
            }
        }

        // XXX: there is a potential efficiency to be gained by not
        //      reopening our sockets all the time, but I'm not
        //      convinced it's worth it, especially since we require
        //      nscd to operate, anyhow.
        close(tac_fd);
    }

    return status;
}
