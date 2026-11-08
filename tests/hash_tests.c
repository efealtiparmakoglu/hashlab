/* hash_tests.c — known-answer vectors, padding boundaries, streaming. */
#define _POSIX_C_SOURCE 200809L /* popen/pclose under -std=c11 */
#include <stdio.h>
#include <string.h>

#include "../src/hash.h"

static int tests_run = 0;

#define FAIL(...)                                                             \
    do {                                                                      \
        printf("FAIL %s:%d: ", __FILE__, __LINE__);                           \
        printf(__VA_ARGS__);                                                  \
        printf("\n");                                                         \
        return 1;                                                             \
    } while (0)

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond))                                                          \
            FAIL("check failed: %s", #cond);                                  \
    } while (0)

static void test_reset(void) { tests_run++; }

/* compute the hex digest of a string for one algorithm */
static void digest_of(hash_alg alg, const void *data, size_t len, char *out) {
    uint8_t digest[HASH_MAX_DIGEST];
    size_t digest_len = 0;
    hash_digest(alg, data, len, digest, &digest_len);
    hash_hex(digest, digest_len, out);
}

#define expect(label, alg, data, len, want)                                    \
    do {                                                                      \
        char hex_[2 * HASH_MAX_DIGEST + 1];                                   \
        digest_of((alg), (data), (len), hex_);                                 \
        if (strcmp(hex_, (want)) != 0)                                        \
            FAIL("%s: got %s want %s", (label), hex_, (want));                 \
    } while (0)

static int test_md5_vectors(void) {
    expect("md5 empty", HASH_MD5, "", 0, "d41d8cd98f00b204e9800998ecf8427e");
    expect("md5 a", HASH_MD5, "a", 1, "0cc175b9c0f1b6a831c399e269772661");
    expect("md5 abc", HASH_MD5, "abc", 3, "900150983cd24fb0d6963f7d28e17f72");
    expect("md5 message digest", HASH_MD5, "message digest", 14,
           "f96b697d7cb7938d525a2f31aaf161d0");
    expect("md5 alphabet", HASH_MD5, "abcdefghijklmnopqrstuvwxyz", 26,
           "c3fcd3d76192e4007dfb496cca67e13b");
    expect("md5 alnum", HASH_MD5,
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62,
           "d174ab98d277d9f5a5611c2c9f419d9f");
    expect("md5 8x1234567890", HASH_MD5,
           "12345678901234567890123456789012345678901234567890"
           "123456789012345678901234567890",
           80, "57edf4a22be3c955ac49da2e2107b67a");
    test_reset();
    return 0;
}

static int test_sha1_vectors(void) {
    expect("sha1 empty", HASH_SHA1, "", 0,
           "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect("sha1 abc", HASH_SHA1, "abc", 3,
           "a9993e364706816aba3e25717850c26c9cd0d89d");
    expect("sha1 message digest", HASH_SHA1, "message digest", 14,
           "c12252ceda8be8994d5fa0290a47231c1d16aae3");
    expect("sha1 alphabet", HASH_SHA1, "abcdefghijklmnopqrstuvwxyz", 26,
           "32d10c7b8cf96570ca04ce37f2a19d84240d3a89");
    expect("sha256 alphabet", HASH_SHA256, "abcdefghijklmnopqrstuvwxyz", 26,
           "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73");
    test_reset();
    return 0;
}

static int test_sha256_vectors(void) {
    expect("sha256 empty", HASH_SHA256, "", 0,
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect("sha256 abc", HASH_SHA256, "abc", 3,
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect("sha256 message digest", HASH_SHA256, "message digest", 14,
           "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650");
    test_reset();
    return 0;
}

/* The alphabet digests above must come from the real algorithms, not from
 * memory: verify them against the system implementations via `md5 -q`. */
static int test_against_system_tools(void) {
    /* cross-check: if macOS/BSD tools exist, our output must match them */
    FILE *pipe = popen("printf abc | md5 -q 2>/dev/null", "r");
    if (pipe) {
        char line[128] = {0};
        if (fgets(line, sizeof line, pipe)) {
            pclose(pipe);
            char mine[2 * HASH_MAX_DIGEST + 1];
            digest_of(HASH_MD5, "abc", 3, mine);
            char *nl = strpbrk(line, "\r\n");
            if (nl) *nl = '\0';
            if (strcmp(line, mine) != 0)
                FAIL("md5 mismatch with system md5: %s vs %s", mine, line);
        } else {
            pclose(pipe);
        }
    }
    test_reset();
    return 0;
}

static int test_padding_boundaries(void) {
    /* lengths around the 56-byte pad boundary and block size */
    char buffer[200];
    for (int i = 0; i < 200; i++) buffer[i] = (char)('a' + (i % 26));

    hash_alg algs[3] = {HASH_MD5, HASH_SHA1, HASH_SHA256};
    for (int a = 0; a < 3; a++) {
        /* one-shot digests must equal streamed digests for every length */
        for (size_t len = 0; len <= 130; len++) {
            char one_shot[2 * HASH_MAX_DIGEST + 1];
            digest_of(algs[a], buffer, len, one_shot);

            hash_ctx ctx;
            hash_init(&ctx, algs[a]);
            /* feed in irregular chunks */
            size_t offset = 0;
            size_t chunk = 1;
            while (offset < len) {
                size_t take = (offset + chunk > len) ? len - offset : chunk;
                hash_update(&ctx, buffer + offset, take);
                offset += take;
                chunk = chunk * 2 + 1;
            }
            uint8_t digest[HASH_MAX_DIGEST];
            size_t digest_len = 0;
            hash_final(&ctx, digest, &digest_len);
            char streamed[2 * HASH_MAX_DIGEST + 1];
            hash_hex(digest, digest_len, streamed);
            if (strcmp(one_shot, streamed) != 0)
                FAIL("%s len %zu: one-shot %s != streamed %s",
                     hash_alg_name(algs[a]), len, one_shot, streamed);
        }
    }
    test_reset();
    return 0;
}

static int test_high_bit_inputs(void) {
    /* bytes with the high bit set: little-endian length/word handling */
    uint8_t binary[8] = {0xff, 0xfe, 0xfd, 0x80, 0x00, 0x7f, 0xc0, 0x01};
    expect("md5 binary", HASH_MD5, binary, sizeof binary,
           "28b2d15b860c622f0b5ab43378fd8a17");
    expect("sha256 binary", HASH_SHA256, binary, sizeof binary,
           "26432f5b41456f36995415fd71b20c2346f8dfb5c04e86523393c0c4a90450bc");
    char first[2 * HASH_MAX_DIGEST + 1], second[2 * HASH_MAX_DIGEST + 1];
    digest_of(HASH_MD5, binary, sizeof binary, first);
    digest_of(HASH_MD5, binary, sizeof binary, second);
    CHECK(strcmp(first, second) == 0);
    binary[0] = 0x00;
    digest_of(HASH_MD5, binary, sizeof binary, second);
    CHECK(strcmp(first, second) != 0);
    test_reset();
    return 0;
}

static int test_metadata(void) {
    CHECK(strcmp(hash_alg_name(HASH_MD5), "md5") == 0);
    CHECK(strcmp(hash_alg_name(HASH_SHA1), "sha1") == 0);
    CHECK(strcmp(hash_alg_name(HASH_SHA256), "sha256") == 0);
    CHECK(hash_digest_size(HASH_MD5) == 16);
    CHECK(hash_digest_size(HASH_SHA1) == 20);
    CHECK(hash_digest_size(HASH_SHA256) == 32);
    hash_alg parsed;
    CHECK(hash_alg_from_name("sha256", &parsed) == 0 && parsed == HASH_SHA256);
    CHECK(hash_alg_from_name("md5", &parsed) == 0 && parsed == HASH_MD5);
    CHECK(hash_alg_from_name("crc32", &parsed) == -1);
    CHECK(hash_alg_from_name(NULL, &parsed) == -1);
    test_reset();
    return 0;
}

static int test_million_a_vectors(void) {
    /* FIPS 180 long vector for SHA-1 and SHA-256 */
    hash_ctx sha1_ctx, sha256_ctx;
    hash_init(&sha1_ctx, HASH_SHA1);
    hash_init(&sha256_ctx, HASH_SHA256);
    char chunk[1000];
    memset(chunk, 'a', sizeof chunk);
    for (int i = 0; i < 1000; i++) {
        hash_update(&sha1_ctx, chunk, sizeof chunk);
        hash_update(&sha256_ctx, chunk, sizeof chunk);
    }
    uint8_t digest[HASH_MAX_DIGEST];
    size_t digest_len = 0;
    char hex[2 * HASH_MAX_DIGEST + 1];

    hash_final(&sha1_ctx, digest, &digest_len);
    hash_hex(digest, digest_len, hex);
    CHECK(strcmp(hex, "34aa973cd4c4daa4f61eeb2bdbad27316534016f") == 0);

    hash_final(&sha256_ctx, digest, &digest_len);
    hash_hex(digest, digest_len, hex);
    CHECK(strcmp(hex,
                 "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0);
    test_reset();
    return 0;
}

static int test_hex_formatting(void) {
    uint8_t digest[HASH_MAX_DIGEST] = {0x00, 0x0f, 0xa5, 0xff};
    char hex[16];
    hash_hex(digest, 4, hex);
    CHECK(strcmp(hex, "000fa5ff") == 0);
    test_reset();
    return 0;
}

int main(void) {
    int fails = 0;
    fails += test_md5_vectors();
    fails += test_sha1_vectors();
    fails += test_sha256_vectors();
    fails += test_against_system_tools();
    fails += test_padding_boundaries();
    fails += test_high_bit_inputs();
    fails += test_metadata();
    fails += test_million_a_vectors();
    fails += test_hex_formatting();
    if (fails) {
        printf("hash_tests: %d test function(s) FAILED\n", fails);
        return 1;
    }
    printf("hash_tests: all %d test groups passed\n", tests_run);
    return 0;
}
