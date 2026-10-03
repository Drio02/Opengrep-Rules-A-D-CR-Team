#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void banner(void) {
    char name[32];
    // ruleid: c-gets
    gets(name);
    char out[64];
    // ruleid: c-unbounded-string-copy
    strcpy(out, name);
    // ok: c-unbounded-string-copy
    snprintf(out, sizeof(out), "%s", name);
}

void read_user(void) {
    char user[16];
    // ruleid: c-scanf-unbounded-string
    scanf("%s", user);
    // ok: c-scanf-unbounded-string
    scanf("%15s", user);
}

void handle(int fd) {
    char buf[64];
    // ruleid: c-read-larger-than-buffer
    read(fd, buf, 128);
    // ok: c-read-larger-than-buffer
    read(fd, buf, 64);
    // ruleid: c-off-by-one-null-terminator
    buf[sizeof(buf)] = 0;
}

void copy_name(char *src) {
    char dst[32];
    // ruleid: c-strncpy-no-terminator
    strncpy(dst, src, sizeof(dst));
    puts(dst);
}

void echo(char *msg) {
    // ruleid: c-format-string
    printf(msg);
    // ok: c-format-string
    printf("%s", msg);
    // ruleid: c-format-string
    fprintf(stderr, msg);
}

void notes(char *a) {
    char *p = malloc(32);
    // ruleid: c-double-free
    free(p);
    free(p);
}

void notes2(void) {
    struct note *n = malloc(sizeof(*n));
    free(n);
    // ruleid: c-use-after-free
    puts(n->body);
}

void notes3(void) {
    struct note *n = malloc(sizeof(*n));
    free(n);
    n = NULL;
    // ok: c-use-after-free
    n = malloc(sizeof(*n));
}

void *alloc_items(size_t count, size_t size) {
    // ruleid: c-malloc-multiplication-overflow
    return malloc(count * size);
}

void ping(char *host) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
    // ruleid: c-command-execution-dynamic
    system(cmd);
    // ok: c-command-execution-dynamic
    system("uptime");
}

void tmp(void) {
    char name[L_tmpnam];
    // ruleid: c-insecure-temp-file
    tmpnam(name);
}

void serve(char *path) {
    // ruleid: c-toctou-access-open
    if (access(path, R_OK) == 0) {
        FILE *f = fopen(path, "r");
    }
}

void perms(char *p) {
    // ruleid: c-world-writable-permissions
    chmod(p, 0777);
}

void token(char *out) {
    // ruleid: c-weak-rand-token
    srand(time(NULL));
    // ruleid: c-weak-rand-token, c-unbounded-string-copy
    sprintf(out, "%08x", rand());
}

int login(char *input, char *password) {
    // ruleid: c-strncmp-attacker-length
    if (strncmp(input, password, strlen(input)) == 0) return 1;
    // ruleid: c-timing-unsafe-secret-compare
    return strcmp(password, input) == 0;
}

void copy(char *dst, char *src) {
    int len = atoi(src);
    // ruleid: c-signed-length-check
    if (len > 64) {
        return;
    }
    memcpy(dst, src, len);
}

void freadstr(FILE *f, char **dst) {
    size_t start, len;
    char c;

    start = ftell(f);
    // ruleid: c-char-eof-comparison
    for (len = 0; (c = fgetc(f)) != EOF && c; len++);
    fseek(f, start, SEEK_SET);
}

void freadstr_fixed(FILE *f) {
    size_t len;
    int c;
    // ok: c-char-eof-comparison
    for (len = 0; (c = fgetc(f)) != EOF && c; len++);
}

const char *mhash(const char *str, int len) {
    static char buf[41];
    char *bp;
    int i;
    for (bp = buf, i = 0; i < 20; i++)
        // ruleid: c-sprintf-hex-signed-char, c-unbounded-string-copy, c-weak-rand-token
        bp += sprintf(bp, "%02x", str[i % len] ^ (rand() % 256));
    for (bp = buf, i = 0; i < 20; i++)
        // ok: c-sprintf-hex-signed-char
        bp += snprintf(bp, 3, "%02x", (unsigned char) str[i % len]);
    return buf;
}

void load_note(char **notes, long idx, int filefd) {
    // ruleid: c-off-by-one-null-terminator
    int bytes_read = read(filefd, notes[idx], 0x60);
    notes[idx][bytes_read] = 0;
}

void load_passwd(int fd) {
    char password_buf[40];
    // ok: c-off-by-one-null-terminator
    int bytes_read = read(fd, password_buf, sizeof(password_buf) - 1);
    password_buf[bytes_read] = 0;
}

void die(const char *fmtstr, ...) {
    va_list ap;
    va_start(ap, fmtstr);
    // ok: c-format-string
    vprintf(fmtstr, ap);
    va_end(ap);
    exit(1);
}

int save_submission(char *dirpath, char *infopath) {
    int status = 0;
    FILE *f = fopen(infopath, "w+");
    if (!f) goto fail;
    fclose(f);
exit:
    free(dirpath);
    free(infopath);
    return status;
fail:
    // ok: c-use-after-free
    if (infopath) remove(infopath);
    // ok: c-use-after-free
    if (dirpath) remove(dirpath);
    status = -1;
    goto exit;
}

void notes4(int err) {
    struct note *n = malloc(sizeof(*n));
    free(n);
    if (err) return;
    // ruleid: c-use-after-free
    puts(n->body);
}

int notes5(int err) {
    struct note *n = malloc(sizeof(*n));
    free(n);
    if (err) return -1;
    // ruleid: c-use-after-free
    puts(n->body);
    return 0;
}

#define STORAGE_DIR "/service/data/%s/%s"
void user_path(char *path_buf, char *username) {
    // ok: c-format-string
    snprintf(path_buf, 64, STORAGE_DIR, username, "passwd");
}
