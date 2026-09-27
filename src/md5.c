/* md5.c — RFC 1321. Educational: MD5 is broken for security use. */
#include "hash.h"

#include <string.h>

/* K[i] = floor(2^32 * abs(sin(i+1))), S = per-round shift amounts (RFC 1321) */
static const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static const uint8_t S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

static uint32_t rotl32(uint32_t value, uint8_t count) {
    return (value << count) | (value >> (32 - count));
}

static void md5_block(uint32_t state[4], const uint8_t block[HASH_BLOCK_SIZE],
                      FILE *trace) {
    uint32_t m[16];
    for (int i = 0; i < 16; i++) {
        m[i] = (uint32_t)block[4 * i] | ((uint32_t)block[4 * i + 1] << 8) |
               ((uint32_t)block[4 * i + 2] << 16) |
               ((uint32_t)block[4 * i + 3] << 24);
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    for (uint32_t i = 0; i < 64; i++) {
        uint32_t f;
        uint32_t g;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        uint32_t temp = d;
        d = c;
        c = b;
        b = b + rotl32(a + f + K[i] + m[g], S[i]);
        a = temp;
        if (trace && (i % 4 == 0 || i == 63))
            fprintf(trace, "  step %2u: a=%08x b=%08x c=%08x d=%08x\n", i, a, b, c, d);
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void md5_compress(uint32_t state[4], const uint8_t block[HASH_BLOCK_SIZE]) {
    uint32_t local[4] = {state[0], state[1], state[2], state[3]};
    md5_block(local, block, NULL);
    state[0] = local[0];
    state[1] = local[1];
    state[2] = local[2];
    state[3] = local[3];
}

void md5_trace(const uint8_t block[HASH_BLOCK_SIZE], FILE *out) {
    uint32_t state[4] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
    md5_block(state, block, out);
    fprintf(out, "  state after block: %08x %08x %08x %08x\n",
            state[0], state[1], state[2], state[3]);
}
