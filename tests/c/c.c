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
