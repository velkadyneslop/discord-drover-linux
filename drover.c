/*
 * discord-drover-linux: LD_PRELOAD port of https://github.com/hdrover/discord-drover
 *
 * What it does, per process it is loaded into:
 *   1. Main Discord process only: inserts --proxy-server=<proxy> into argv
 *      (TCP: chat, updates, voice signalling). http://, https:// (TLS to the
 *      proxy, done by Chromium) and socks5:// are passed through as given.
 *   2. First send on every UDP socket: if the datagram is 74 bytes (Discord's
 *      voice IP-discovery packet), first sends the optional drover-packet.bin,
 *      then two 1-byte datagrams (0x00, 0x01), waits 50 ms, then lets the real
 *      packet through.
 *   3. Plain HTTP proxy with login:password (not https://, where the request
 *      is already encrypted by the time it reaches send()): rewrites the first request sent on a
 *      TCP socket so the User-Agent header becomes Proxy-Authorization
 *      (Chromium cannot take proxy credentials on the command line).
 *
 * Config (drover.ini, drover-packet.bin) is read from the directory this
 * library lives in, or from $DROVER_DIR.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define OPTIONS_FILENAME "drover.ini"
#define PACKET_FILENAME "drover-packet.bin"
#define LOG_FILENAME "drover.log"
#define DISCOVERY_PACKET_LEN 74
#define MAX_PACKET_FILE 65507
#define MAX_FDS 65536

enum { ST_NONE = 0, ST_FRESH_TCP, ST_FRESH_UDP };

static _Atomic unsigned char fd_state[MAX_FDS];

static char base_dir[3072];
static int debug_enabled;

static struct {
    int specified;
    int is_http, is_socks5, is_auth;
    char scheme[16];
    char login[256], password[256];
    char host[256];
    int port;
    char auth_header[1024]; /* "Proxy-Authorization: Basic xxxx" */
} proxy;

static char lib_path[3072];         /* our own path, as it must appear in LD_PRELOAD */
static char self_exe[4096];         /* /proc/self/exe */
static char preload_entry[3200];    /* "LD_PRELOAD=<lib_path>" */
static int in_discord;

static int is_discord_exe(void);

static int (*real_execvp)(const char *, char *const[]);
static int (*real_execve)(const char *, char *const[], char *const[]);
static int (*real_socket)(int, int, int);
static ssize_t (*real_send)(int, const void *, size_t, int);
static ssize_t (*real_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t (*real_sendmsg)(int, const struct msghdr *, int);
static int (*real_sendmmsg)(int, struct mmsghdr *, unsigned int, int);

/* ---------------------------------------------------------------- logging */

static void dlog(const char *fmt, ...)
{
    if (!debug_enabled)
        return;
    char line[1024], path[3200];
    int n = snprintf(line, sizeof line, "[drover %d] ", (int)getpid());
    va_list ap;
    va_start(ap, fmt);
    n += vsnprintf(line + n, sizeof line - (size_t)n - 1, fmt, ap);
    va_end(ap);
    if (n > (int)sizeof line - 2)
        n = (int)sizeof line - 2;
    line[n++] = '\n';
    snprintf(path, sizeof path, "%s/%s", base_dir, LOG_FILENAME);
    int saved = errno;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd >= 0) {
        if (write(fd, line, (size_t)n) < 0) { /* ignore */ }
        close(fd);
    }
    errno = saved;
}

/* ----------------------------------------------------------------- config */

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
        *--e = 0;
    return s;
}

static void lower(char *s)
{
    for (; *s; s++)
        if (*s >= 'A' && *s <= 'Z')
            *s += 32;
}

static void base64(const unsigned char *in, size_t len, char *out)
{
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i;
    for (i = 0; i + 2 < len; i += 3) {
        *out++ = t[in[i] >> 2];
        *out++ = t[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
        *out++ = t[((in[i + 1] & 15) << 2) | (in[i + 2] >> 6)];
        *out++ = t[in[i + 2] & 63];
    }
    if (i < len) {
        *out++ = t[in[i] >> 2];
        if (i + 1 < len) {
            *out++ = t[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
            *out++ = t[(in[i + 1] & 15) << 2];
        } else {
            *out++ = t[(in[i] & 3) << 4];
            *out++ = '=';
        }
        *out++ = '=';
    }
    *out = 0;
}

/* [scheme://][login:password@]host:port  -- same grammar as upstream */
static void parse_proxy(char *url)
{
    memset(&proxy, 0, sizeof proxy);
    url = trim(url);
    if (!*url)
        return;

    char *rest = url;
    char *sep = strstr(url, "://");
    strcpy(proxy.scheme, "http");
    if (sep) {
        size_t n = (size_t)(sep - url);
        if (n == 0 || n >= sizeof proxy.scheme)
            return;
        memcpy(proxy.scheme, url, n);
        proxy.scheme[n] = 0;
        lower(proxy.scheme);
        rest = sep + 3;
    }

    char *at = strrchr(rest, '@');
    if (at) {
        *at = 0;
        char *colon = strchr(rest, ':');
        if (colon) {
            *colon = 0;
            snprintf(proxy.login, sizeof proxy.login, "%s", trim(rest));
            snprintf(proxy.password, sizeof proxy.password, "%s", trim(colon + 1));
        }
        rest = at + 1;
    }

    char *colon = strrchr(rest, ':');
    if (!colon || colon == rest)
        return;
    *colon = 0;
    int port = 0;
    const char *p = colon + 1;
    if (!*p)
        return;
    for (; *p; p++) {
        if (*p < '0' || *p > '9')
            return;
        port = port * 10 + (*p - '0');
        if (port > 65535)
            return;
    }
    if (port == 0)
        return;
    snprintf(proxy.host, sizeof proxy.host, "%s", trim(rest));
    proxy.port = port;

    proxy.is_http = !strcmp(proxy.scheme, "http");
    proxy.is_socks5 = !strcmp(proxy.scheme, "socks5");
    proxy.is_auth = proxy.login[0] && proxy.password[0];
    proxy.specified = 1;

    if (proxy.is_http && proxy.is_auth) {
        char cred[520], b64[700];
        int n = snprintf(cred, sizeof cred, "%s:%s", proxy.login, proxy.password);
        base64((const unsigned char *)cred, (size_t)n, b64);
        snprintf(proxy.auth_header, sizeof proxy.auth_header, "Proxy-Authorization: Basic %s", b64);
    }
}

static void load_options(void)
{
    char path[3200], line[2048];
    snprintf(path, sizeof path, "%s/%s", base_dir, OPTIONS_FILENAME);
    FILE *f = fopen(path, "re");
    if (!f)
        return;
    int in_section = 0;
    while (fgets(line, sizeof line, f)) {
        char *s = trim(line);
        if (*s == ';' || *s == '#' || !*s)
            continue;
        if (*s == '[') {
            lower(s);
            in_section = !strncmp(s, "[drover]", 8);
            continue;
        }
        if (!in_section)
            continue;
        char *eq = strchr(s, '=');
        if (!eq)
            continue;
        *eq = 0;
        char *key = trim(s), *val = trim(eq + 1);
        lower(key);
        if (!strcmp(key, "proxy"))
            parse_proxy(val);
        else if (!strcmp(key, "debug"))
            debug_enabled = (*val == '1' || *val == 'y' || *val == 'Y' || *val == 't' || *val == 'T');
    }
    fclose(f);
}

static void find_base_dir(void)
{
    Dl_info self;
    if (dladdr((void *)&find_base_dir, &self) && self.dli_fname && self.dli_fname[0] == '/') {
        snprintf(lib_path, sizeof lib_path, "%s", self.dli_fname);
        snprintf(preload_entry, sizeof preload_entry, "LD_PRELOAD=%s", lib_path);
    }
    const char *env = getenv("DROVER_DIR");
    if (env && *env) {
        snprintf(base_dir, sizeof base_dir, "%s", env);
        return;
    }
    Dl_info info;
    if (dladdr((void *)&find_base_dir, &info) && info.dli_fname && strchr(info.dli_fname, '/')) {
        snprintf(base_dir, sizeof base_dir, "%s", info.dli_fname);
        *strrchr(base_dir, '/') = 0;
        if (!base_dir[0])
            strcpy(base_dir, "/");
    } else {
        strcpy(base_dir, ".");
    }
}

static void resolve_real(void)
{
    real_execvp = dlsym(RTLD_NEXT, "execvp");
    real_execve = dlsym(RTLD_NEXT, "execve");
    real_socket = dlsym(RTLD_NEXT, "socket");
    real_send = dlsym(RTLD_NEXT, "send");
    real_sendto = dlsym(RTLD_NEXT, "sendto");
    real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    real_sendmmsg = dlsym(RTLD_NEXT, "sendmmsg");
}

/* hooks can be called from other libraries' constructors before ours has run */
#define ENSURE_REAL(fn)                                                                                           \
    do {                                                                                                          \
        if (__builtin_expect(!(fn), 0))                                                                           \
            resolve_real();                                                                                       \
    } while (0)

__attribute__((constructor)) static void drover_init(void)
{
    resolve_real();
    find_base_dir();
    in_discord = is_discord_exe();
    load_options();
    const char *env = getenv("DROVER_DEBUG");
    if (env && *env && *env != '0')
        debug_enabled = 1;
}

/* ------------------------------------------------- argv: --proxy-server=… */

static int is_discord_name(const char *path)
{
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    return !strcmp(name, "Discord") || !strcmp(name, "DiscordCanary") || !strcmp(name, "DiscordPTB") ||
           !strcmp(name, "DiscordDevelopment");
}

static int is_discord_exe(void)
{
    ssize_t n = readlink("/proc/self/exe", self_exe, sizeof self_exe - 1);
    if (n <= 0)
        return 0;
    self_exe[n] = 0;
    return is_discord_name(self_exe);
}

/* ------------------------------------------- keep ourselves in child procs */

/*
 * Launchers such as zypak (Flatpak) remove LD_PRELOAD from the main process's
 * environment once it is running, so Discord's children (renderer = voice,
 * network service = proxy auth) would start without this library. When Discord
 * re-executes itself we put the library back into the child's LD_PRELOAD.
 * Runs between fork and exec: no malloc, no locks.
 */
static size_t env_count(char *const envp[])
{
    size_t n = 0;
    while (envp && envp[n])
        n++;
    return n;
}

static int needs_preload(const char *file, char *const envp[])
{
    if (!in_discord || !lib_path[0] || !file)
        return 0;
    /* Chromium normally re-executes itself as /proc/self/exe */
    if (strcmp(file, "/proc/self/exe") != 0 && strcmp(file, self_exe) != 0 && !is_discord_name(file))
        return 0;
    for (size_t i = 0; envp && envp[i]; i++)
        if (!strncmp(envp[i], "LD_PRELOAD=", 11) && strstr(envp[i] + 11, lib_path))
            return 0;
    return 1;
}

/* fills out[] (room for n + 2 entries); combined must hold preload_entry + ':' + old value */
static void build_env(char *const envp[], char **out, char *combined, size_t combined_size)
{
    size_t j = 0;
    const char *old = NULL;
    for (size_t i = 0; envp && envp[i]; i++) {
        if (!strncmp(envp[i], "LD_PRELOAD=", 11))
            old = envp[i] + 11;
        else
            out[j++] = envp[i];
    }
    if (old && *old) {
        snprintf(combined, combined_size, "%s:%s", preload_entry, old);
        out[j++] = combined;
    } else {
        out[j++] = preload_entry;
    }
    out[j] = NULL;
}

#define WITH_PRELOAD_ENV(envp)                                                                                    \
    size_t n_ = env_count(envp);                                                                                  \
    char **nenv = __builtin_alloca(sizeof(char *) * (n_ + 2));                                                    \
    char combined_[sizeof preload_entry + 4096];                                                                  \
    build_env(envp, nenv, combined_, sizeof combined_)

int execvp(const char *file, char *const argv[])
{
    ENSURE_REAL(real_execvp);
    if (!needs_preload(file, environ))
        return real_execvp(file, argv);
    WITH_PRELOAD_ENV(environ);
    char **saved = environ;
    environ = nenv; /* call the next execvp (not execvpe) so other preloaded hooks still see it */
    int r = real_execvp(file, argv);
    environ = saved;
    return r;
}

int execve(const char *file, char *const argv[], char *const envp[])
{
    ENSURE_REAL(real_execve);
    if (!needs_preload(file, envp))
        return real_execve(file, argv, envp);
    WITH_PRELOAD_ENV(envp);
    return real_execve(file, argv, nenv);
}

typedef int (*main_fn)(int, char **, char **);
typedef int (*start_main_fn)(main_fn, int, char **, void (*)(void), void (*)(void), void (*)(void), void *);

int __libc_start_main(main_fn main, int argc, char **argv, void (*init)(void), void (*fini)(void),
                      void (*rtld_fini)(void), void *stack_end)
{
    start_main_fn real = (start_main_fn)dlsym(RTLD_NEXT, "__libc_start_main");

    if (proxy.specified && argc >= 1 && is_discord_exe()) {
        int skip = 0;
        for (int i = 1; i < argc; i++) {
            /* child processes (--type=renderer etc.) get their proxy config from the main process */
            if (!strncmp(argv[i], "--type=", 7) || !strncmp(argv[i], "--proxy-server", 14))
                skip = 1;
        }
        if (!skip) {
            static char flag[400];
            snprintf(flag, sizeof flag, "--proxy-server=%s://%s:%d", proxy.scheme, proxy.host, proxy.port);
            char **nargv = malloc(sizeof(char *) * ((size_t)argc + 2));
            if (nargv) {
                nargv[0] = argv[0];
                nargv[1] = flag;
                for (int i = 1; i <= argc; i++) /* includes the terminating NULL */
                    nargv[i + 1] = argv[i];
                dlog("main process: added %s", flag);
                argv = nargv;
                argc++;
            }
        }
    }
    return real(main, argc, argv, init, fini, rtld_fini, stack_end);
}

/* ------------------------------------------------------------ socket state */

int socket(int domain, int type, int protocol)
{
    ENSURE_REAL(real_socket);
    int fd = real_socket(domain, type, protocol);
    if (fd >= 0 && fd < MAX_FDS) {
        unsigned char st = ST_NONE;
        if (domain == AF_INET || domain == AF_INET6) {
            int t = type & 0xf;
            if (t == SOCK_STREAM && (protocol == 0 || protocol == 6))
                st = ST_FRESH_TCP;
            else if (t == SOCK_DGRAM && (protocol == 0 || protocol == 17))
                st = ST_FRESH_UDP;
        }
        atomic_store(&fd_state[fd], st);
    }
    return fd;
}

/* Returns the state the fd had if this is its first send, else ST_NONE. */
static int take_first_send(int fd)
{
    if (fd < 0 || fd >= MAX_FDS)
        return ST_NONE;
    unsigned char st = atomic_load_explicit(&fd_state[fd], memory_order_relaxed);
    if (st == ST_NONE)
        return ST_NONE;
    st = atomic_exchange(&fd_state[fd], ST_NONE);
    if (st == ST_NONE)
        return ST_NONE;
    /* the fd number may have been closed and reused for something else */
    int type = 0;
    socklen_t len = sizeof type;
    int saved = errno;
    int ok = getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0;
    errno = saved;
    if (!ok || type != (st == ST_FRESH_TCP ? SOCK_STREAM : SOCK_DGRAM))
        return ST_NONE;
    return st;
}

/* -------------------------------------------------------------- UDP trick */

static void udp_prelude(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    int saved = errno;
    char path[3200];
    snprintf(path, sizeof path, "%s/%s", base_dir, PACKET_FILENAME);
    int pfd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t extra = -1;
    if (pfd >= 0) {
        unsigned char *buf = malloc(MAX_PACKET_FILE);
        if (buf) {
            extra = read(pfd, buf, MAX_PACKET_FILE);
            if (extra > 0)
                real_sendto(fd, buf, (size_t)extra, 0, addr, addrlen);
            free(buf);
        }
        close(pfd);
    }
    unsigned char b = 0;
    ssize_t r0 = real_sendto(fd, &b, 1, 0, addr, addrlen);
    b = 1;
    ssize_t r1 = real_sendto(fd, &b, 1, 0, addr, addrlen);
    dlog("udp fd=%d: voice discovery packet seen; sent prelude (packet file: %zd bytes, 0x00: %zd, 0x01: %zd)",
         fd, extra, r0, r1);
    struct timespec ts = {0, 50 * 1000 * 1000};
    nanosleep(&ts, NULL);
    errno = saved;
}

static size_t iov_total(const struct msghdr *msg)
{
    size_t total = 0;
    for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++)
        total += msg->msg_iov[i].iov_len;
    return total;
}

/* ------------------------------------------------- HTTP proxy auth header */

/*
 * Overwrites the User-Agent header line with a Proxy-Authorization header of
 * exactly the same length (padded with a dummy "X:" header), so byte counts
 * seen by the caller stay correct. Returns a malloc'd copy, or NULL.
 */
static void *http_auth_rewrite(const void *buf, size_t len)
{
    if (!proxy.specified || !proxy.is_http || !proxy.is_auth || len < 16 || len > 65536)
        return NULL;
    const char *p = buf;
    const char *eol = memmem(p, len, "\r\n", 2);
    if (!eol)
        return NULL;
    /* only requests addressed to a proxy: CONNECT, or an absolute http:// URL */
    if (memcmp(p, "CONNECT ", 8) != 0 && !memmem(p, (size_t)(eol - p), " http://", 8))
        return NULL;
    if (memmem(p, len, "\r\nProxy-Authorization: ", 23))
        return NULL;
    const char *ua = memmem(p, len, "\r\nUser-Agent:", 13);
    if (!ua)
        return NULL;
    ua += 2;
    const char *ua_end = memmem(ua, len - (size_t)(ua - p), "\r\n", 2);
    if (!ua_end)
        return NULL;
    size_t ua_len = (size_t)(ua_end - ua);
    size_t hdr_len = strlen(proxy.auth_header);
    if (ua_len < hdr_len + 6) /* need room for "\r\nX: " plus at least one filler byte */
        return NULL;

    char *copy = malloc(len);
    if (!copy)
        return NULL;
    memcpy(copy, buf, len);
    char *w = copy + (ua - p);
    memcpy(w, proxy.auth_header, hdr_len);
    w += hdr_len;
    memcpy(w, "\r\nX: ", 5);
    w += 5;
    memset(w, 'X', ua_len - hdr_len - 5);
    return copy;
}

/* ------------------------------------------------------------------ hooks */

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
    ENSURE_REAL(real_send);
    int st = take_first_send(fd);
    if (st == ST_FRESH_UDP && len == DISCOVERY_PACKET_LEN) {
        udp_prelude(fd, NULL, 0);
    } else if (st == ST_FRESH_TCP) {
        void *copy = http_auth_rewrite(buf, len);
        if (copy) {
            dlog("tcp fd=%d: added proxy authorization to first request", fd);
            ssize_t r = real_send(fd, copy, len, flags);
            int saved = errno;
            free(copy);
            errno = saved;
            return r;
        }
    }
    return real_send(fd, buf, len, flags);
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addrlen)
{
    ENSURE_REAL(real_sendto);
    int st = take_first_send(fd);
    if (st == ST_FRESH_UDP && len == DISCOVERY_PACKET_LEN) {
        udp_prelude(fd, addr, addrlen);
    } else if (st == ST_FRESH_TCP) {
        void *copy = http_auth_rewrite(buf, len);
        if (copy) {
            dlog("tcp fd=%d: added proxy authorization to first request", fd);
            ssize_t r = real_sendto(fd, copy, len, flags, addr, addrlen);
            int saved = errno;
            free(copy);
            errno = saved;
            return r;
        }
    }
    return real_sendto(fd, buf, len, flags, addr, addrlen);
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
    ENSURE_REAL(real_sendmsg);
    if (msg && take_first_send(fd) == ST_FRESH_UDP && iov_total(msg) == DISCOVERY_PACKET_LEN)
        udp_prelude(fd, msg->msg_name, msg->msg_name ? msg->msg_namelen : 0);
    return real_sendmsg(fd, msg, flags);
}

int sendmmsg(int fd, struct mmsghdr *vec, unsigned int vlen, int flags)
{
    ENSURE_REAL(real_sendmmsg);
    if (vec && vlen > 0 && take_first_send(fd) == ST_FRESH_UDP &&
        iov_total(&vec[0].msg_hdr) == DISCOVERY_PACKET_LEN) {
        const struct msghdr *m = &vec[0].msg_hdr;
        udp_prelude(fd, m->msg_name, m->msg_name ? m->msg_namelen : 0);
    }
    return real_sendmmsg(fd, vec, vlen, flags);
}
