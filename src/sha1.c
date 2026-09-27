/* sha1.c — FIPS 180-4 / RFC 3174 SHA-1. Educational: broken for collisions. */
#include "hash.h"

#include <string.h>

static uint32_t rotl32(uint32_t value, uint8_t count) {
    return (value << count) | (value >> (32 - count));
}

static void sha1_block(uint32_t state[5], const uint8_t block[HASH_BLOCK_SIZE],
                       FILE *trace) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[4 * i] << 24) |
               ((uint32_t)block[4 * i + 1] << 16) |
               ((uint32_t)block[4 * i + 2] << 8) | (uint32_t)block[4 * i + 3];
    }
    for (int i = 16; i < 80; i++)
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5a827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcu;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6u;
        }
        uint32_t temp = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = temp;
        if (trace && (i % 20 == 0 || i == 79))
            fprintf(trace, "  round %2d: a=%08x e=%08x\n", i, a, e);
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void sha1_compress(uint32_t state[5], const uint8_t block[HASH_BLOCK_SIZE]) {
    uint32_t local[5] = {state[0], state[1], state[2], state[3], state[4]};
    sha1_block(local, block, NULL);
    for (int i = 0; i < 5; i++) state[i] = local[i];
}

void sha1_trace(const uint8_t block[HASH_BLOCK_SIZE], FILE *out) {
    uint32_t state[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u,
                         0xc3d2e1f0u};
    sha1_block(state, block, out);
    fprintf(out, "  state after block: %08x %08x %08x %08x %08x\n",
            state[0], state[1], state[2], state[3], state[4]);
}
