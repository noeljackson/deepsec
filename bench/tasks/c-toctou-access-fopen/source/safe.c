#include <stdio.h>

/* Just open and rely on OS error reporting — no pre-check race. */
FILE *open_unchecked_safe(const char *path) {
    return fopen(path, "r");
}
