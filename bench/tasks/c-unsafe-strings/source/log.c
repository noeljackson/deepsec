#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void greet_vulnerable(const char *name) {
    char buf[16];
    strcpy(buf, name);
    printf("Hello %s\n", buf);
}

void greet_safe(const char *name) {
    char buf[16];
    strncpy(buf, name, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf("Hello %s\n", buf);
}

void log_vulnerable(const char *msg) {
    printf(msg);
}

void log_safe(const char *msg) {
    printf("%s", msg);
}

int format_vulnerable(const char *user_fmt, const char *value) {
    char out[64];
    sprintf(out, user_fmt, value);
    return (int)strlen(out);
}
