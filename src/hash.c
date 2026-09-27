/* hash.c — streaming dispatcher, padding, hex output. */
#include "hash.h"

#include <string.h>

void md5_trace(const uint8_t block[HASH_BLOCK_SIZE], FILE *out);
void sha1_trace(const uint8_t block[HASH_BLOCK_SIZE], FILE *out);
void sha256_trace(const uint8_t block[HASH_BLOCK_SIZE], FILE *out);

const char *hash_alg_name(hash_alg alg) {
    switch (alg) {
    case HASH_MD5:
        return "md5";
    case HASH_SHA1:
        return "sha1";
    case HASH_SHA256:
        return "sha256";
    default:
        return "?";
    }
}

size_t hash_digest_size(hash_alg alg) {
    switch (alg) {
    case HASH_MD5:
        return 16;
    case HASH_SHA1:
        return 20;
    case HASH_SHA256:
        return 32;
    default:
        return 0;
    }
}

int hash_alg_from_name(const char *name, hash_alg *out) {
    if (!name)
        return -1;
    if (strcmp(name, "md5") == 0) { *out = HASH_MD5; return 0; }
    if (strcmp(name, "sha1") == 0) { *out = HASH_SHA1; return 0; }
    if (strcmp(name, "sha256") == 0) { *out = HASH_SHA256; return 0; }
    return -1;
}

void hash_init(hash_ctx *ctx, hash_alg alg) {
    memset(ctx, 0, sizeof *ctx);
    ctx->alg = alg;
    switch (alg) {
    case HASH_MD5:
        ctx->state[0] = 0x67452301u;
        ctx->state[1] = 0xefcdab89u;
        ctx->state[2] = 0x98badcfeu;
        ctx->state[3] = 0x10325476u;
        break;
    case HASH_SHA1:
        ctx->state[0] = 0x67452301u;
        ctx->state[1] = 0xefcdab89u;
        ctx->state[2] = 0x98badcfeu;
        ctx->state[3] = 0x10325476u;
        ctx->state[4] = 0xc3d2e1f0u;
        break;
    case HASH_SHA256:
        ctx->state[0] = 0x6a09e667u;
        ctx->state[1] = 0xbb67ae85u;
        ctx->state[2] = 0x3c6ef372u;
        ctx->state[3] = 0xa54ff53au;
        ctx->state[4] = 0x510e527fu;
        ctx->state[5] = 0x9b05688cu;
        ctx->state[6] = 0x1f83d9abu;
        ctx->state[7] = 0x5be0cd19u;
        break;
    }
}

static void compress_state(hash_ctx *ctx, const uint8_t block[HASH_BLOCK_SIZE]) {
    switch (ctx->alg) {
    case HASH_MD5:
        md5_compress(ctx->state, block);
        break;
    case HASH_SHA1:
        sha1_compress(ctx->state, block);
        break;
    case HASH_SHA256:
        sha256_compress(ctx->state, block);
        break;
    }
}

void hash_update(hash_ctx *ctx, const void *data, size_t len) {
    const uint8_t *bytes = data;
    ctx->total_len += len;
    if (ctx->buffered > 0) {
        size_t need = HASH_BLOCK_SIZE - ctx->buffered;
        size_t take = len < need ? len : need;
        memcpy(ctx->buffer + ctx->buffered, bytes, take);
        ctx->buffered += take;
        bytes += take;
        len -= take;
        if (ctx->buffered == HASH_BLOCK_SIZE) {
            compress_state(ctx, ctx->buffer);
            ctx->buffered = 0;
        }
    }
    while (len >= HASH_BLOCK_SIZE) {
        compress_state(ctx, bytes);
        bytes += HASH_BLOCK_SIZE;
        len -= HASH_BLOCK_SIZE;
    }
    if (len > 0) {
        memcpy(ctx->buffer, bytes, len);
        ctx->buffered = len;
    }
}

void hash_final(hash_ctx *ctx, uint8_t out[HASH_MAX_DIGEST], size_t *out_len) {
    uint64_t bit_len = ctx->total_len * 8;
    size_t words = ctx->alg == HASH_SHA256 ? 8 : (ctx->alg == HASH_SHA1 ? 5 : 4);

    /* pad: 0x80, zeros, then the length big-endian (8 bytes for SHA-256,
     * 8 bytes low half for MD5/SHA-1) */
    uint8_t pad[HASH_BLOCK_SIZE * 2];
    memset(pad, 0, sizeof pad);
    pad[0] = 0x80;
    size_t pad_len = (ctx->buffered < 56) ? (56 - ctx->buffered)
                                          : (120 - ctx->buffered);
    hash_update(ctx, pad, pad_len);

    uint8_t length_bytes[8];
    if (ctx->alg == HASH_MD5) {
        /* RFC 1321 stores the bit length little-endian */
        for (int i = 0; i < 8; i++)
            length_bytes[i] = (uint8_t)(bit_len >> (8 * i));
    } else {
        /* FIPS 180-4 stores it big-endian; the top 32 bits are always zero
         * for realistic inputs, so one 8-byte write covers SHA-1 too */
        for (int i = 0; i < 8; i++)
            length_bytes[i] = (uint8_t)(bit_len >> (56 - 8 * i));
    }
    hash_update(ctx, length_bytes, 8);

    size_t digest_len = words * 4;
    for (size_t i = 0; i < words; i++) {
        if (ctx->alg == HASH_MD5) {
            /* RFC 1321: the digest is the state words in little-endian */
            out[4 * i] = (uint8_t)ctx->state[i];
            out[4 * i + 1] = (uint8_t)(ctx->state[i] >> 8);
            out[4 * i + 2] = (uint8_t)(ctx->state[i] >> 16);
            out[4 * i + 3] = (uint8_t)(ctx->state[i] >> 24);
        } else {
            /* FIPS 180-4: big-endian words */
            out[4 * i] = (uint8_t)(ctx->state[i] >> 24);
            out[4 * i + 1] = (uint8_t)(ctx->state[i] >> 16);
            out[4 * i + 2] = (uint8_t)(ctx->state[i] >> 8);
            out[4 * i + 3] = (uint8_t)ctx->state[i];
        }
    }
    if (out_len)
        *out_len = digest_len;
}

void hash_digest(hash_alg alg, const void *data, size_t len,
                 uint8_t out[HASH_MAX_DIGEST], size_t *out_len) {
    hash_ctx ctx;
    hash_init(&ctx, alg);
    hash_update(&ctx, data, len);
    hash_final(&ctx, out, out_len);
}

void hash_hex(const uint8_t *digest, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = digits[digest[i] >> 4];
        out[2 * i + 1] = digits[digest[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

void hash_trace_block(hash_alg alg, const uint8_t block[HASH_BLOCK_SIZE],
                      FILE *out) {
    switch (alg) {
    case HASH_MD5:
        md5_trace(block, out);
        break;
    case HASH_SHA1:
        sha1_trace(block, out);
        break;
    case HASH_SHA256:
        sha256_trace(block, out);
        break;
    }
}
