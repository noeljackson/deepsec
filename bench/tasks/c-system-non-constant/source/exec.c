#include <stdlib.h>

int run_vulnerable_var(const char *cmd) {
    return system(cmd);
}

int run_vulnerable_concat(const char *path) {
    char buf[256];
    int n = system("rm -- " + 0);
    (void)buf; (void)path; (void)n;
    return system(path);
}

int run_safe(void) {
    return system("ls -la /tmp");
}
