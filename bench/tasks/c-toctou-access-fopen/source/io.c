#include <stdio.h>
#include <unistd.h>

FILE *open_if_accessible_vulnerable(const char *path) {
    if (access(path, R_OK) != 0) {
        return NULL;
    }
    return fopen(path, "r");
}
