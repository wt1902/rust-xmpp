/* Test-only LD_PRELOAD shim: delay, then perform the real durable operation.
 * Scope is strictly the canonical fixture data root selected by the harness.
 * No host mount or durability settings are changed. Log contains no file data.
 * Exceptional XMPP_SYNC_FAIL_SUFFIX=.wal|.rredo injects EIO for matching
 * fixture regular files. Without that explicit fault mode all syncs are real.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static long long ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}
static int sync_call(int fd, const char *operation) {
    int (*real_sync)(int) = dlsym(RTLD_NEXT, operation);
    if (!real_sync) { errno = ENOSYS; return -1; }
    const char *prefix = getenv("XMPP_SLOW_SYNC_ROOT");
    const char *log = getenv("XMPP_SLOW_SYNC_LOG");
    char link[64], path[PATH_MAX];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t length = readlink(link, path, sizeof path - 1);
    if (!prefix || !log || length < 0) return real_sync(fd);
    path[length] = '\0';
    size_t size = strlen(prefix);
    if (strncmp(path, prefix, size) || (path[size] && path[size] != '/'))
        return real_sync(fd);
    struct stat st;
    if (fstat(fd, &st) || (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)))
        return real_sync(fd);
    const char *delay = getenv("XMPP_SLOW_SYNC_MS");
    long ms = delay ? strtol(delay, NULL, 10) : 100;
    if (ms < 0 || ms > 10000) ms = 100;
    long long begin = ns();
    struct timespec wait = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000};
    while (nanosleep(&wait, &wait) && errno == EINTR) {}
    const char *suffix = getenv("XMPP_SYNC_FAIL_SUFFIX");
    int injected = 0;
    if (suffix && (!strcmp(suffix, ".wal") || !strcmp(suffix, ".rredo")) && S_ISREG(st.st_mode)) {
        size_t suffix_length = strlen(suffix);
        injected = (size_t)length >= suffix_length &&
            !strcmp(path + length - suffix_length, suffix);
    }
    int result;
    if (injected) { errno = EIO; result = -1; }
    else result = real_sync(fd);
    int saved_errno = errno;
    long long end = ns();
    /* One append write per operation avoids partial concurrent log records.
     * Paths are not logged: only a path-derived store category. */
    const char *store = strstr(path, "/rust_smacks") ? "sm" :
        strstr(path, "/archive") ? "mam" :
        strstr(path, "/pep") ? "pep" : "other";
    char row[512];
    int count = snprintf(row, sizeof row,
        "{\"op\":\"%s\",\"kind\":\"%s\",\"store\":\"%s\",\"begin_ns\":%lld,\"end_ns\":%lld,\"result\":%d,\"injected\":%s}\n",
        operation, S_ISDIR(st.st_mode) ? "directory" : "file", store, begin, end, result,
        injected ? "true" : "false");
    int output = open(log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (output >= 0) { ssize_t ignored = write(output, row, count); (void)ignored; close(output); }
    errno = saved_errno;
    return result;
}
int fsync(int fd) { return sync_call(fd, "fsync"); }
int fdatasync(int fd) { return sync_call(fd, "fdatasync"); }
