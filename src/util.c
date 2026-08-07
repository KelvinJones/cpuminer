#include "util.h"

#include <string.h>
#include <time.h>

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool hex2bin(uint8_t *dst, const char *hex, size_t out_len)
{
    if (!hex)
        return false;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hexval(hex[2 * i]);
        int lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        dst[i] = (uint8_t)((hi << 4) | lo);
    }
    return hex[2 * out_len] == '\0';
}

void bin2hex(char *dst, const uint8_t *src, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        dst[2 * i]     = digits[src[i] >> 4];
        dst[2 * i + 1] = digits[src[i] & 0xf];
    }
    dst[2 * len] = '\0';
}

int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void b64_encode(char *out, const uint8_t *in, size_t len)
{
    static const char t[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, o = 0;
    while (i < len) {
        uint32_t a = in[i++];
        uint32_t b = i < len ? in[i++] : 0;
        uint32_t c = i < len ? in[i++] : 0;
        uint32_t trip = (a << 16) | (b << 8) | c;
        out[o++] = t[(trip >> 18) & 63];
        out[o++] = t[(trip >> 12) & 63];
        out[o++] = t[(trip >> 6) & 63];
        out[o++] = t[trip & 63];
    }
    /* fix up padding */
    size_t rem = len % 3;
    if (rem == 1) { out[o - 1] = '='; out[o - 2] = '='; }
    else if (rem == 2) { out[o - 1] = '='; }
    out[o] = '\0';
}

size_t put_compact_size(uint8_t *out, uint64_t v)
{
    if (v < 253) {
        out[0] = (uint8_t)v;
        return 1;
    }
    if (v <= 0xffff) {
        out[0] = 253;
        out[1] = (uint8_t)v;
        out[2] = (uint8_t)(v >> 8);
        return 3;
    }
    if (v <= 0xffffffff) {
        out[0] = 254;
        out[1] = (uint8_t)v;
        out[2] = (uint8_t)(v >> 8);
        out[3] = (uint8_t)(v >> 16);
        out[4] = (uint8_t)(v >> 24);
        return 5;
    }
    out[0] = 255;
    for (int i = 0; i < 8; i++)
        out[1 + i] = (uint8_t)(v >> (8 * i));
    return 9;
}

bool hex2bin_reversed(uint8_t out[32], const char *hex)
{
    if (!hex2bin(out, hex, 32))
        return false;
    for (int i = 0; i < 16; i++) {
        uint8_t tmp = out[i];
        out[i] = out[31 - i];
        out[31 - i] = tmp;
    }
    return true;
}
