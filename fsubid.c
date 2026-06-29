/*
 * fsubid - subordinate UID/GID allocator with reservations and commit helper.
 *
 * Main features:
 *   - Allocate a free range with a short-lived reservation.
 *   - Commit reservation to /etc/subuid and /etc/subgid under lock.
 *   - Release reservation without commit.
 *   - Validate and inspect ranges.
 *   - Track reservation state (reserved/committed/released/expired).
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

#define FSUBID_VERSION          "1.0.0"

/* ---- tunables ----------------------------------------------------------- */
#define CONF_FILE               "/etc/fsubid.conf"
#define DEFAULT_UID_RANGE       70000
#define DEFAULT_GID_RANGE       70000
#define FIRST_USER_START        100000
#define RES_DIR                 "/run/fsubid/reservations"
#define STATE_DIR               "/run/fsubid/state"
#define LOCK_FILE               "/run/fsubid/fsubid.lock"
#define RES_TTL_SECS            (5 * 60)
#define SUBUID_FILE             "/etc/subuid"
#define SUBGID_FILE             "/etc/subgid"
/* ------------------------------------------------------------------------- */

enum exit_code {
    EX_OK = 0,
    EX_USAGE = 2,
    EX_INVALID_RANGE = 3,
    EX_LOCK = 10,
    EX_IO = 11,
    EX_NOT_FOUND = 12,
    EX_OVERLAP = 13,
    EX_COMMIT = 14
};

enum command {
    CMD_NONE = -1,
    CMD_ALLOCATE = 0,
    CMD_COMMIT,
    CMD_RELEASE,
    CMD_LIST,
    CMD_VALIDATE,
    CMD_WHO_OWNS,
    CMD_STATUS,
    CMD_VERSION
};

struct range {
    long start;
    long count;
};

struct reservation {
    char user[128];
    long start;
    long uid_range;
    long gid_range;
    long ts;
    int pid;
};

struct ranges {
    struct range *items;
    size_t len;
    size_t cap;
};

struct owners {
    char **items;
    size_t len;
    size_t cap;
};

static void diec(int code, const char *msg)
{
    fprintf(stderr, "fsubid: error: %s\n", msg);
    exit(code);
}

static void dief(const char *fmt, const char *arg)
{
    fprintf(stderr, "fsubid: error: ");
    fprintf(stderr, fmt, arg);
    fputc('\n', stderr);
    exit(EX_IO);
}

static void usage(int code)
{
    FILE *out = (code == 0) ? stdout : stderr;
    fprintf(out,
        "fsubid - subordinate uid/gid allocator\n"
        "\n"
        "USAGE:\n"
        "  fsubid allocate [options] [username]\n"
        "  fsubid commit [options] [username]\n"
        "  fsubid release [options]\n"
        "  fsubid list-reservations\n"
        "  fsubid validate-range --start <N> [--uid-range <N>] [--gid-range <N>]\n"
        "  fsubid who-owns-range --start <N>\n"
        "  fsubid status --start <N>\n"
        "  fsubid version\n"
        "\n"
        "COMMON OPTIONS:\n"
        "  -r, --range <N|UID:GID>   Set both ranges with N, or separately UID:GID\n"
        "      --uid-range <N>       Override UID range only\n"
        "      --gid-range <N>       Override GID range only\n"
        "\n"
        "ALLOCATE OPTIONS:\n"
        "      --print-reservation-path   Print reservation file path on stderr\n"
        "\n"
        "COMMIT/RELEASE/STATUS OPTIONS:\n"
        "      --start <N>           Reservation/range start\n"
        "\n"
        "NOTES:\n"
        "  Defaults come from " CONF_FILE " (UID_RANGE and GID_RANGE).\n"
        "  Allocate output format: START:UID_SIZE:GID_SIZE\n"
        "  Creating a range requires the explicit 'allocate' command;\n"
        "  a bare username does nothing and will not allocate.\n"
        "\n"
        "EXIT CODES:\n"
        "  0  success\n"
        "  2  invalid usage\n"
        "  3  invalid range\n"
        " 10  lock error\n"
        " 11  io error\n"
        " 12  not found\n"
        " 13  overlap detected\n"
        " 14  commit failed\n");
    exit(code == 0 ? EX_OK : EX_USAGE);
}

static void trim_trailing(char *s)
{
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' ||
                       s[len - 1] == ' '  || s[len - 1] == '\t'))
        s[--len] = '\0';
}

static long parse_positive_long(const char *s)
{
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || !end || *end != '\0' || v <= 0)
        return -1;
    return v;
}

static int is_digits(const char *s)
{
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
    }
    return 1;
}

static void parse_range_value(const char *arg, long *uid_range, long *gid_range)
{
    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s", arg);

    char *colon = strchr(tmp, ':');
    if (!colon) {
        long both = parse_positive_long(tmp);
        if (both <= 0)
            dief("invalid range value: %s", arg);
        *uid_range = both;
        *gid_range = both;
        return;
    }

    *colon = '\0';
    const char *left = tmp;
    const char *right = colon + 1;

    long u = parse_positive_long(left);
    long g = parse_positive_long(right);
    if (u <= 0 || g <= 0)
        dief("invalid range pair (expected UID:GID): %s", arg);
    *uid_range = u;
    *gid_range = g;
}

static void load_config(long *uid_range, long *gid_range)
{
    *uid_range = DEFAULT_UID_RANGE;
    *gid_range = DEFAULT_GID_RANGE;

    FILE *f = fopen(CONF_FILE, "r");
    if (!f) return;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        trim_trailing(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';

        const char *key = line;
        const char *val = eq + 1;
        long parsed = parse_positive_long(val);
        if (parsed <= 0)
            continue;

        if (strcmp(key, "UID_RANGE") == 0)
            *uid_range = parsed;
        else if (strcmp(key, "GID_RANGE") == 0)
            *gid_range = parsed;
    }
    fclose(f);
}

static const char *state_file_path(long start, char *buf, size_t n)
{
    snprintf(buf, n, "%s/%ld", STATE_DIR, start);
    return buf;
}

static const char *reservation_file_path(long start, char *buf, size_t n)
{
    snprintf(buf, n, "%s/%ld", RES_DIR, start);
    return buf;
}

/* Create all directory components of path (like mkdir -p). */
static void makedirs(const char *path)
{
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            (void)mkdir(tmp, 0755);
            *p = '/';
        }
    }
    (void)mkdir(tmp, 0755);
}

/*
 * Scan a sub{u,g}id file and return the highest (start + size) seen,
 * i.e. the end of the last allocated range.
 */
static long parse_subfile_highest_end(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    long highest = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        /* Format: username:start:size */
        char *p = strchr(line, ':');
        if (!p) continue;
        p++;
        char *q = strchr(p, ':');
        if (!q) continue;
        *q = '\0';
        long start = strtol(p, NULL, 10);
        long size  = strtol(q + 1, NULL, 10);
        long end   = start + size;
        if (end > highest) highest = end;
    }
    fclose(f);
    return highest;
}

static int ranges_push(struct ranges *r, long start, long count)
{
    if (count <= 0 || start < 0) return 0;
    if (r->len == r->cap) {
        size_t next = r->cap == 0 ? 16 : r->cap * 2;
        void *p = realloc(r->items, next * sizeof(*r->items));
        if (!p) return 0;
        r->items = p;
        r->cap = next;
    }
    r->items[r->len].start = start;
    r->items[r->len].count = count;
    r->len++;
    return 1;
}

static void ranges_free(struct ranges *r)
{
    free(r->items);
    r->items = NULL;
    r->len = 0;
    r->cap = 0;
}

static int owners_push_unique(struct owners *o, const char *s)
{
    for (size_t i = 0; i < o->len; i++) {
        if (strcmp(o->items[i], s) == 0)
            return 1;
    }
    if (o->len == o->cap) {
        size_t next = o->cap == 0 ? 8 : o->cap * 2;
        void *p = realloc(o->items, next * sizeof(*o->items));
        if (!p) return 0;
        o->items = p;
        o->cap = next;
    }
    o->items[o->len] = strdup(s);
    if (!o->items[o->len]) return 0;
    o->len++;
    return 1;
}

static void owners_free(struct owners *o)
{
    for (size_t i = 0; i < o->len; i++)
        free(o->items[i]);
    free(o->items);
    o->items = NULL;
    o->len = 0;
    o->cap = 0;
}

static int parse_triplet_line(const char *line, char *owner, size_t owner_n, long *start, long *count)
{
    char buf[512];
    char *p1 = NULL;
    char *p2 = NULL;
    if (!line) return 0;

    snprintf(buf, sizeof(buf), "%s", line);
    trim_trailing(buf);
    if (buf[0] == '\0' || buf[0] == '#')
        return 0;

    p1 = strchr(buf, ':');
    if (!p1) return 0;
    *p1 = '\0';
    p1++;

    p2 = strchr(p1, ':');
    if (!p2) return 0;
    *p2 = '\0';
    p2++;

    long s = strtol(p1, NULL, 10);
    long c = strtol(p2, NULL, 10);
    if (s < 0 || c <= 0) return 0;

    if (owner && owner_n > 0)
        snprintf(owner, owner_n, "%s", buf);
    if (start) *start = s;
    if (count) *count = c;
    return 1;
}

static int ranges_from_file(const char *path, struct ranges *out)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return 1;
        return 0;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        long start = 0;
        long count = 0;
        if (!parse_triplet_line(line, NULL, 0, &start, &count))
            continue;
        if (!ranges_push(out, start, count)) {
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    return 1;
}

static int range_overlaps(long a_start, long a_count, long b_start, long b_count)
{
    long a_end = a_start + a_count - 1;
    long b_end = b_start + b_count - 1;
    return !(a_end < b_start || b_end < a_start);
}

static int overlap_in_ranges(long start, long count, const struct ranges *r)
{
    for (size_t i = 0; i < r->len; i++) {
        if (range_overlaps(start, count, r->items[i].start, r->items[i].count))
            return 1;
    }
    return 0;
}

static int find_owners_in_file(const char *path, long start, long count, struct owners *out)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return 1;
        return 0;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char owner[128];
        long file_start = 0;
        long file_count = 0;

        if (!parse_triplet_line(line, owner, sizeof(owner), &file_start, &file_count))
            continue;

        if (range_overlaps(start, count, file_start, file_count)) {
            if (!owners_push_unique(out, owner)) {
                fclose(f);
                return 0;
            }
        }
    }

    fclose(f);
    return 1;
}

/*
 * Scan live reservation files and return the highest reserved end.
 * Reservation filenames are numeric (the range start offset).
 */
static long reservations_highest_end(long uid_range, long gid_range)
{
    DIR *d = opendir(RES_DIR);
    if (!d) return 0;

    long highest = 0;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;

        /* Accept only all-digit filenames. */
        int all_digits = 1;
        for (const char *p = ent->d_name; *p; p++) {
            if (*p < '0' || *p > '9') { all_digits = 0; break; }
        }
        if (!all_digits) continue;

        long rstart = strtol(ent->d_name, NULL, 10);
        long max_range = uid_range > gid_range ? uid_range : gid_range;
        long rend = rstart + max_range;
        if (rend > highest) highest = rend;
    }
    closedir(d);
    return highest;
}

static int read_reservation(long start, struct reservation *res)
{
    char path[PATH_MAX];
    reservation_file_path(start, path, sizeof(path));

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[512];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);

    memset(res, 0, sizeof(*res));
    res->start = start;

    int parsed = sscanf(line, "user=%127s uid_range=%ld gid_range=%ld pid=%d ts=%ld",
                        res->user, &res->uid_range, &res->gid_range, &res->pid, &res->ts);
    if (parsed != 5) return 0;
    return 1;
}

static int write_state(long start, const char *state)
{
    char path[PATH_MAX];
    state_file_path(start, path, sizeof(path));

    FILE *f = fopen(path, "w");
    if (!f) return 0;
    fprintf(f, "%s\n", state);
    fclose(f);
    return 1;
}

static int read_state(long start, char *state, size_t n)
{
    char path[PATH_MAX];
    state_file_path(start, path, sizeof(path));

    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(state, (int)n, f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    trim_trailing(state);
    return 1;
}

static int append_triplet_if_missing(const char *path, const char *owner, long start, long count)
{
    FILE *f = fopen(path, "r");
    int exists = 0;

    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            char o[128];
            long s = 0, c = 0;
            if (!parse_triplet_line(line, o, sizeof(o), &s, &c))
                continue;
            if (strcmp(o, owner) == 0 && s == start && c == count) {
                exists = 1;
                break;
            }
        }
        fclose(f);
    } else if (errno != ENOENT) {
        return 0;
    }

    if (exists) return 1;

    f = fopen(path, "a");
    if (!f) return 0;
    fprintf(f, "%s:%ld:%ld\n", owner, start, count);
    fclose(f);
    return 1;
}

static int remove_reservation(long start)
{
    char path[PATH_MAX];
    reservation_file_path(start, path, sizeof(path));
    if (unlink(path) != 0 && errno != ENOENT)
        return 0;
    return 1;
}

static int range_committed(long start, long uid_range, long gid_range)
{
    struct ranges r_uid = {0};
    struct ranges r_gid = {0};
    int ok_uid = ranges_from_file(SUBUID_FILE, &r_uid);
    int ok_gid = ranges_from_file(SUBGID_FILE, &r_gid);
    int yes = 0;

    if (!ok_uid || !ok_gid)
        goto out;

    yes = overlap_in_ranges(start, uid_range, &r_uid) && overlap_in_ranges(start, gid_range, &r_gid);

out:
    ranges_free(&r_uid);
    ranges_free(&r_gid);
    return yes;
}

/* Remove reservation files older than RES_TTL_SECS. */
static void gc_stale_reservations(void)
{
    DIR *d = opendir(RES_DIR);
    if (!d) return;

    time_t now = time(NULL);
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", RES_DIR, ent->d_name);
        struct stat st;
        if (stat(path, &st) == 0 && (now - st.st_mtime) > RES_TTL_SECS) {
            long start = strtol(ent->d_name, NULL, 10);
            if (unlink(path) == 0)
                (void)write_state(start, "expired");
        }
    }
    closedir(d);
}

static int open_global_lock(void)
{
    int lock_fd = open(LOCK_FILE, O_CREAT | O_RDWR, 0600);
    if (lock_fd < 0)
        return -1;
    if (flock(lock_fd, LOCK_EX) < 0) {
        close(lock_fd);
        return -1;
    }
    return lock_fd;
}

static void close_global_lock(int fd)
{
    (void)flock(fd, LOCK_UN);
    (void)close(fd);
}

static int command_allocate(const char *target_user, long uid_range, long gid_range, int print_res_path)
{
    long committed_end = 0, e;
    long reserved_end;
    long highest_end;
    long max_range;
    long next_start;
    char res_path[PATH_MAX];

    if (!target_user || target_user[0] == '\0')
        diec(EX_USAGE, "target user is empty; pass a username or set SUDO_USER");
    if (strcmp(target_user, "root") == 0)
        diec(EX_USAGE, "target user is root; refusing");

    int lock_fd = open_global_lock();
    if (lock_fd < 0)
        diec(EX_LOCK, "cannot acquire lock");

    e = parse_subfile_highest_end(SUBUID_FILE); if (e > committed_end) committed_end = e;
    e = parse_subfile_highest_end(SUBGID_FILE); if (e > committed_end) committed_end = e;
    reserved_end = reservations_highest_end(uid_range, gid_range);

    highest_end = committed_end > reserved_end ? committed_end : reserved_end;
    max_range = uid_range > gid_range ? uid_range : gid_range;
    next_start = FIRST_USER_START + max_range;
    if (highest_end > next_start) next_start = highest_end;

    reservation_file_path(next_start, res_path, sizeof(res_path));
    FILE *rf = fopen(res_path, "w");
    if (!rf) {
        close_global_lock(lock_fd);
        diec(EX_IO, "cannot create reservation file");
    }

    fprintf(rf, "user=%s uid_range=%ld gid_range=%ld pid=%d ts=%ld\n",
            target_user, uid_range, gid_range, (int)getpid(), (long)time(NULL));
    fclose(rf);
    (void)write_state(next_start, "reserved");

    close_global_lock(lock_fd);

    printf("%ld:%ld:%ld\n", next_start, uid_range, gid_range);
    if (print_res_path)
        fprintf(stderr, "reservation=%s\n", res_path);
    return EX_OK;
}

static int command_validate(long start, long uid_range, long gid_range)
{
    struct ranges committed = {0};
    struct ranges reserved = {0};
    int ok = 0;

    if (start < FIRST_USER_START)
        diec(EX_INVALID_RANGE, "start is below FIRST_USER_START");
    if (uid_range <= 0 || gid_range <= 0)
        diec(EX_INVALID_RANGE, "ranges must be positive");

    if (!ranges_from_file(SUBUID_FILE, &committed) || !ranges_from_file(SUBGID_FILE, &committed))
        diec(EX_IO, "cannot read committed ranges");

    DIR *d = opendir(RES_DIR);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d))) {
            if (ent->d_name[0] == '.' || !is_digits(ent->d_name))
                continue;
            struct reservation res;
            long s = strtol(ent->d_name, NULL, 10);
            if (!read_reservation(s, &res))
                continue;
            long max_count = res.uid_range > res.gid_range ? res.uid_range : res.gid_range;
            if (!ranges_push(&reserved, res.start, max_count)) {
                closedir(d);
                ranges_free(&committed);
                ranges_free(&reserved);
                diec(EX_IO, "out of memory while validating");
            }
        }
        closedir(d);
    }

    long max_count = uid_range > gid_range ? uid_range : gid_range;
    ok = !overlap_in_ranges(start, max_count, &committed) && !overlap_in_ranges(start, max_count, &reserved);

    ranges_free(&committed);
    ranges_free(&reserved);

    if (!ok) {
        printf("invalid:overlap\n");
        return EX_OVERLAP;
    }

    printf("valid\n");
    return EX_OK;
}

static int command_who_owns(long start)
{
    struct owners owners = {0};
    int ok1 = find_owners_in_file(SUBUID_FILE, start, 1, &owners);
    int ok2 = find_owners_in_file(SUBGID_FILE, start, 1, &owners);

    if (!ok1 || !ok2) {
        owners_free(&owners);
        diec(EX_IO, "cannot read owner data");
    }

    if (owners.len == 0) {
        printf("none\n");
    } else {
        for (size_t i = 0; i < owners.len; i++)
            printf("%s\n", owners.items[i]);
    }

    owners_free(&owners);
    return EX_OK;
}

static int command_list_reservations(void)
{
    DIR *d = opendir(RES_DIR);
    if (!d) {
        if (errno == ENOENT) return EX_OK;
        diec(EX_IO, "cannot open reservation directory");
    }

    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.' || !is_digits(ent->d_name))
            continue;
        long start = strtol(ent->d_name, NULL, 10);
        struct reservation res;
        if (!read_reservation(start, &res))
            continue;
        printf("%ld:%ld:%ld user=%s pid=%d ts=%ld\n",
               res.start, res.uid_range, res.gid_range, res.user, res.pid, res.ts);
    }

    closedir(d);
    return EX_OK;
}

static int command_version(void)
{
    printf("fsubid %s\n", FSUBID_VERSION);
    return EX_OK;
}

static int command_status(long start)
{
    struct reservation res;
    char st[64];

    if (read_reservation(start, &res)) {
        printf("reserved\n");
        return EX_OK;
    }

    if (read_state(start, st, sizeof(st))) {
        printf("%s\n", st);
        return EX_OK;
    }

    if (range_committed(start, 1, 1)) {
        printf("committed\n");
        return EX_OK;
    }

    printf("unknown\n");
    return EX_NOT_FOUND;
}

static int command_release(long start)
{
    int lock_fd = open_global_lock();
    if (lock_fd < 0)
        diec(EX_LOCK, "cannot acquire lock");

    if (!remove_reservation(start)) {
        close_global_lock(lock_fd);
        diec(EX_IO, "cannot remove reservation");
    }

    (void)write_state(start, "released");
    close_global_lock(lock_fd);
    printf("released\n");
    return EX_OK;
}

static int command_commit(long start, const char *target_user)
{
    int lock_fd;
    struct reservation res;
    struct ranges r_uid = {0};
    struct ranges r_gid = {0};

    if (!target_user || target_user[0] == '\0')
        diec(EX_USAGE, "target user is empty; pass username for commit");
    if (strcmp(target_user, "root") == 0)
        diec(EX_USAGE, "target user is root; refusing");

    lock_fd = open_global_lock();
    if (lock_fd < 0)
        diec(EX_LOCK, "cannot acquire lock");

    if (!read_reservation(start, &res)) {
        close_global_lock(lock_fd);
        diec(EX_NOT_FOUND, "reservation not found");
    }

    if (strcmp(res.user, target_user) != 0) {
        close_global_lock(lock_fd);
        diec(EX_USAGE, "reservation user does not match commit user");
    }

    if (!ranges_from_file(SUBUID_FILE, &r_uid) || !ranges_from_file(SUBGID_FILE, &r_gid)) {
        close_global_lock(lock_fd);
        ranges_free(&r_uid);
        ranges_free(&r_gid);
        diec(EX_IO, "cannot read subid files");
    }

    if (overlap_in_ranges(start, res.uid_range, &r_uid) || overlap_in_ranges(start, res.gid_range, &r_gid)) {
        ranges_free(&r_uid);
        ranges_free(&r_gid);
        close_global_lock(lock_fd);
        diec(EX_OVERLAP, "cannot commit: range overlaps existing subid entries");
    }

    if (!append_triplet_if_missing(SUBUID_FILE, target_user, start, res.uid_range) ||
        !append_triplet_if_missing(SUBGID_FILE, target_user, start, res.gid_range)) {
        ranges_free(&r_uid);
        ranges_free(&r_gid);
        close_global_lock(lock_fd);
        diec(EX_COMMIT, "failed to write subid files");
    }

    ranges_free(&r_uid);
    ranges_free(&r_gid);

    if (!remove_reservation(start)) {
        close_global_lock(lock_fd);
        diec(EX_IO, "commit wrote files but failed to remove reservation");
    }

    (void)write_state(start, "committed");
    close_global_lock(lock_fd);

    printf("committed:%ld\n", start);
    return EX_OK;
}

int main(int argc, char *argv[])
{
    long cfg_uid_range = DEFAULT_UID_RANGE;
    long cfg_gid_range = DEFAULT_GID_RANGE;
    load_config(&cfg_uid_range, &cfg_gid_range);

    long uid_range = cfg_uid_range;
    long gid_range = cfg_gid_range;
    long start = -1;
    int have_r = 0;
    int have_uid = 0;
    int have_gid = 0;
    int print_res_path = 0;
    const char *target_user = NULL;
    enum command cmd = CMD_NONE;

    if (argc >= 2) {
        if (strcmp(argv[1], "allocate") == 0) {
            cmd = CMD_ALLOCATE;
            argv++;
            argc--;
        } else if (strcmp(argv[1], "commit") == 0) {
            cmd = CMD_COMMIT;
            argv++;
            argc--;
        } else if (strcmp(argv[1], "release") == 0) {
            cmd = CMD_RELEASE;
            argv++;
            argc--;
        } else if (strcmp(argv[1], "list-reservations") == 0) {
            cmd = CMD_LIST;
            argv++;
            argc--;
        } else if (strcmp(argv[1], "validate-range") == 0) {
            cmd = CMD_VALIDATE;
            argv++;
            argc--;
        } else if (strcmp(argv[1], "who-owns-range") == 0) {
            cmd = CMD_WHO_OWNS;
            argv++;
            argc--;
        } else if (strcmp(argv[1], "status") == 0) {
            cmd = CMD_STATUS;
            argv++;
            argc--;
        } else if (strcmp(argv[1], "version") == 0) {
            cmd = CMD_VERSION;
            argv++;
            argc--;
        }
    }

    makedirs(RES_DIR);
    makedirs(STATE_DIR);
    gc_stale_reservations();

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(0);
        } else if (strcmp(a, "-v") == 0 || strcmp(a, "-V") == 0 || strcmp(a, "--version") == 0) {
            return command_version();
        } else if (strcmp(a, "-r") == 0 || strcmp(a, "--range") == 0) {
            if (i + 1 >= argc)
                diec(EX_USAGE, "missing value for -r/--range");
            if (have_uid || have_gid)
                diec(EX_USAGE, "-r/--range cannot be combined with --uid-range/--gid-range");
            parse_range_value(argv[++i], &uid_range, &gid_range);
            have_r = 1;
        } else if (strcmp(a, "--uid-range") == 0) {
            if (i + 1 >= argc)
                diec(EX_USAGE, "missing value for --uid-range");
            if (have_r)
                diec(EX_USAGE, "--uid-range cannot be combined with -r/--range");
            long v = parse_positive_long(argv[++i]);
            if (v <= 0)
                diec(EX_INVALID_RANGE, "invalid --uid-range value");
            uid_range = v;
            have_uid = 1;
        } else if (strcmp(a, "--gid-range") == 0) {
            if (i + 1 >= argc)
                diec(EX_USAGE, "missing value for --gid-range");
            if (have_r)
                diec(EX_USAGE, "--gid-range cannot be combined with -r/--range");
            long v = parse_positive_long(argv[++i]);
            if (v <= 0)
                diec(EX_INVALID_RANGE, "invalid --gid-range value");
            gid_range = v;
            have_gid = 1;
        } else if (strcmp(a, "--start") == 0) {
            if (i + 1 >= argc)
                diec(EX_USAGE, "missing value for --start");
            start = parse_positive_long(argv[++i]);
            if (start <= 0)
                diec(EX_INVALID_RANGE, "invalid --start value");
        } else if (strcmp(a, "--print-reservation-path") == 0) {
            print_res_path = 1;
        } else if (a[0] == '-') {
            dief("unknown argument: %s", a);
        } else {
            if (target_user)
                diec(EX_USAGE, "multiple usernames provided");
            target_user = a;
        }
    }

    if (!target_user && (cmd == CMD_ALLOCATE || cmd == CMD_COMMIT))
        target_user = getenv("SUDO_USER");

    switch (cmd) {
    case CMD_ALLOCATE:
        return command_allocate(target_user, uid_range, gid_range, print_res_path);
    case CMD_COMMIT:
        if (start <= 0)
            diec(EX_USAGE, "commit requires --start <N>");
        return command_commit(start, target_user);
    case CMD_RELEASE:
        if (start <= 0)
            diec(EX_USAGE, "release requires --start <N>");
        return command_release(start);
    case CMD_LIST:
        return command_list_reservations();
    case CMD_VALIDATE:
        if (start <= 0)
            diec(EX_USAGE, "validate-range requires --start <N>");
        return command_validate(start, uid_range, gid_range);
    case CMD_WHO_OWNS:
        if (start <= 0)
            diec(EX_USAGE, "who-owns-range requires --start <N>");
        return command_who_owns(start);
    case CMD_STATUS:
        if (start <= 0)
            diec(EX_USAGE, "status requires --start <N>");
        return command_status(start);
    case CMD_VERSION:
        return command_version();
    case CMD_NONE:
    default:
        if (target_user) {
            fprintf(stderr,
                "fsubid: error: unknown command '%s'\n"
                "fsubid: to create a range, use: fsubid allocate %s\n",
                target_user, target_user);
            return EX_USAGE;
        }
        usage(1);
    }

    return EX_OK;
}
