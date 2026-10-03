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

void strip_newline(char *unused) {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    // ok: c-taint-size-or-index
    if (*buf && buf[strlen(buf)-1] == '\n')
        // ok: c-taint-size-or-index
        buf[strlen(buf)-1] = '\0';
}

void strip_newline_unchecked(void) {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    // ruleid: c-taint-size-or-index
    buf[strlen(buf)-1] = '\0';
}

void load_info(struct info *info, FILE *f) {
    int i;
    for (i = 0; i < 3; i++)
        // ok: c-taint-size-or-index
        fread(&info->bbmin[i], sizeof(float), 1, f);
}

#define VALID_NOTE_IDX(idx) ((idx >= 0) && (idx < 10))
void delete_note(char **notes) {
    char line[32];
    fgets(line, sizeof(line), stdin);
    long idx = strtol(line, NULL, 0);
    if (!VALID_NOTE_IDX(idx)) {
        return;
    }
    // ok: c-taint-size-or-index
    free(notes[idx]);
}
