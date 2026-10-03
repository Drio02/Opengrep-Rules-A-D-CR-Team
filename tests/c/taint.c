#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void handle_client(int fd) {
    char buf[256];
    char cmd[300];
    read(fd, buf, sizeof(buf) - 1);
    snprintf(cmd, sizeof(cmd), "grep %s /srv/notes.txt", buf);
    // ruleid: c-taint-command-injection
    system(cmd);
    // ruleid: c-taint-format-string
    printf(buf);
    // ok: c-taint-format-string
    printf("%s", buf);
}

void get_note(int fd, char **notes) {
    char line[32];
    fgets(line, sizeof(line), stdin);
    int idx = atoi(line);
    // ruleid: c-taint-size-or-index
    puts(notes[idx]);
}

void get_note_checked(int fd, char **notes) {
    char line[32];
    fgets(line, sizeof(line), stdin);
    int idx = atoi(line);
    if (idx < 0 || idx >= 16) {
        return;
    }
    // ok: c-taint-size-or-index
    puts(notes[idx]);
}

int main(int argc, char **argv) {
    char *q = getenv("QUERY_STRING");
    // ruleid: c-taint-format-string
    printf(q);
    return 0;
}
