#include <string.h>
#include <stdlib.h>

typedef struct {
    int len;
    char data[];
} Packet;

void copy_payload_vulnerable(char *dst, Packet *pkt) {
    memcpy(dst, pkt->data, pkt->len);
}

void copy_payload_safe(char *dst, size_t cap, const char *src, size_t n) {
    if (n > cap) n = cap;
    memcpy(dst, src, n);
}
