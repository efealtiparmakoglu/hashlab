/* hash.h — MD5, SHA-1 and SHA-256 from RFC 1321 / FIPS 180-4. */
#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef enum { HASH_MD5 = 0, HASH_SHA1 = 1, HASH_SHA256 = 2 } hash_alg;

#define HASH_MAX_DIGEST 32
#define HASH_BLOCK_SIZE 64

typedef struct {
    hash_alg alg;
    uint32_t state[8]; /* MD5 uses 4, SHA-1 uses 5, SHA-256 uses 8 */
    uint64_t total_len;
    uint8_t buffer[HASH_BLOCK_SIZE];
    size_t buffered;
} hash_ctx;

void hash_init(hash_ctx *ctx, hash_alg alg);
void hash_update(hash_ctx *ctx, const void *data, size_t len);
void hash_final(hash_ctx *ctx, uint8_t out[HASH_MAX_DIGEST], size_t *out_len);

/* one-shot convenience */
void hash_digest(hash_alg alg, const void *data, size_t len,
                 uint8_t out[HASH_MAX_DIGEST], size_t *out_len);

const char *hash_alg_name(hash_alg alg);
size_t hash_digest_size(hash_alg alg);
int hash_alg_from_name(const char *name, hash_alg *out);

/* lowercase hex of digest + NUL; buffer must hold 2*size+1 bytes */
void hash_hex(const uint8_t *digest, size_t len, char *out);

/* block compression, exposed for the step dumper */
void md5_compress(uint32_t state[4], const uint8_t block[HASH_BLOCK_SIZE]);
void sha1_compress(uint32_t state[5], const uint8_t block[HASH_BLOCK_SIZE]);
void sha256_compress(uint32_t state[8], const uint8_t block[HASH_BLOCK_SIZE]);

/* verbose one-block trace: prints the step values to `out` */
void hash_trace_block(hash_alg alg, const uint8_t block[HASH_BLOCK_SIZE],
                      FILE *out);

#endif
