/* main.c — hashlab CLI: digest files/stdin, step traces, speed bench. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "hash.h"

static const char *usage_text =
    "hashlab 1.0.0 — MD5 / SHA-1 / SHA-256 from scratch (educational)\n"
    "\n"
    "usage:\n"
    "  hashlab [file|-]                 hash stdin or a file with all three\n"
    "  hashlab <file> --steps           dump the first block's step values\n"
    "  hashlab --bench [MB]             speed comparison (default 8 MB)\n"
    "  hashlab --selftest               run RFC/FIPS known-answer vectors\n"
    "  hashlab -h | --help\n"
    "\n"
    "options:\n"
    "  --alg NAME   one of md5, sha1, sha256 (default: all three)\n"
    "  --steps      per-round trace of the first 64-byte block\n"
    "  --json       machine-readable output\n"
    "\n"
    "MD5 and SHA-1 are broken for security use; they are here to be read.\n";

#define READ_CHUNK (64 * 1024)

static const hash_alg ALL_ALGS[3] = {HASH_MD5, HASH_SHA1, HASH_SHA256};

static int read_all(FILE *fp, uint8_t **out, size_t *out_len) {
    size_t capacity = READ_CHUNK, len = 0;
    uint8_t *buffer = malloc(capacity);
    if (!buffer)
        return -1;
    for (;;) {
        if (len == capacity) {
            capacity *= 2;
            uint8_t *grown = realloc(buffer, capacity);
            if (!grown) {
                free(buffer);
                return -1;
            }
            buffer = grown;
        }
        size_t got = fread(buffer + len, 1, capacity - len, fp);
        len += got;
        if (got == 0)
            break;
    }
    *out = buffer;
    *out_len = len;
    return 0;
}

static void digest_hex(hash_alg alg, const uint8_t *data, size_t len,
                       char *hex, size_t *hex_len) {
    uint8_t digest[HASH_MAX_DIGEST];
    size_t digest_len = 0;
    hash_digest(alg, data, len, digest, &digest_len);
    hash_hex(digest, digest_len, hex);
    *hex_len = digest_len;
}

static int bench(size_t megabytes, int as_json) {
    size_t len = megabytes * 1024 * 1024;
    uint8_t *buffer = malloc(len);
    if (!buffer) {
        fprintf(stderr, "hashlab: cannot allocate %zu MB for the bench\n",
                megabytes);
        return 1;
    }
    for (size_t i = 0; i < len; i++)
        buffer[i] = (uint8_t)(i * 31 + (i >> 13));

    if (as_json)
        printf("{\n");
    for (int i = 0; i < 3; i++) {
        char hex[2 * HASH_MAX_DIGEST + 1];
        size_t hex_len = 0;
        clock_t started = clock();
        digest_hex(ALL_ALGS[i], buffer, len, hex, &hex_len);
        double seconds = (double)(clock() - started) / CLOCKS_PER_SEC;
        double mbps = seconds > 0 ? (double)len / seconds / (1024.0 * 1024.0) : 0.0;
        if (as_json)
            printf("  \"%s\": {\"mbps\": %.1f, \"seconds\": %.4f}%s\n",
                   hash_alg_name(ALL_ALGS[i]), mbps, seconds,
                   i == 2 ? "" : ",");
        else
            printf("%-6s %8.1f MB/s  (%zu MB in %.3fs)\n",
                   hash_alg_name(ALL_ALGS[i]), mbps, megabytes, seconds);
    }
    if (as_json)
        printf("}\n");
    free(buffer);
    return 0;
}

static int selftest(void) {
    struct {
        const char *label;
        hash_alg alg;
        const char *input;
        const char *expect;
    } checks[] = {
        /* RFC 1321 A.5 / RFC 3174 / FIPS 180-4 examples */
        {"md5 empty", HASH_MD5, "", "d41d8cd98f00b204e9800998ecf8427e"},
        {"md5 abc", HASH_MD5, "abc", "900150983cd24fb0d6963f7d28e17f72"},
        {"md5 message digest", HASH_MD5, "message digest",
         "f96b697d7cb7938d525a2f31aaf161d0"},
        {"md5 alphabet", HASH_MD5, "abcdefghijklmnopqrstuvwxyz",
         "c3fcd3d76192e4007dfb496cca67e13b"},
        {"sha1 empty", HASH_SHA1, "",
         "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {"sha1 abc", HASH_SHA1, "abc",
         "a9993e364706816aba3e25717850c26c9cd0d89d"},
        {"sha1 message digest", HASH_SHA1, "message digest",
         "c12252ceda8be8994d5fa0290a47231c1d16aae3"},
        {"sha256 empty", HASH_SHA256, "",
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"sha256 abc", HASH_SHA256, "abc",
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"sha256 message digest", HASH_SHA256, "message digest",
         "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"},
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof checks / sizeof checks[0]; i++) {
        char hex[2 * HASH_MAX_DIGEST + 1];
        size_t hex_len = 0;
        digest_hex(checks[i].alg, (const uint8_t *)checks[i].input,
                   strlen(checks[i].input), hex, &hex_len);
        if (strcmp(hex, checks[i].expect) == 0) {
            printf("PASS  %s\n", checks[i].label);
        } else {
            printf("FAIL  %s: got %s want %s\n", checks[i].label, hex,
                   checks[i].expect);
            failures++;
        }
    }
    /* FIPS 180 long vector: one million 'a' — exercises the length field */
    hash_ctx ctx;
    hash_init(&ctx, HASH_SHA256);
    char chunk[1000];
    memset(chunk, 'a', sizeof chunk);
    for (int i = 0; i < 1000; i++)
        hash_update(&ctx, chunk, sizeof chunk);
    uint8_t digest[HASH_MAX_DIGEST];
    size_t digest_len = 0;
    hash_final(&ctx, digest, &digest_len);
    char hex[2 * HASH_MAX_DIGEST + 1];
    hash_hex(digest, digest_len, hex);
    if (strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0) {
        printf("PASS  sha256 million-a\n");
    } else {
        printf("FAIL  sha256 million-a: got %s\n", hex);
        failures++;
    }
    return failures == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    const char *path = NULL;
    int want_steps = 0, as_json = 0, do_bench = 0, do_selftest = 0;
    size_t bench_mb = 8;
    hash_alg only = HASH_SHA256;
    int have_algo = 0;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            fputs(usage_text, stderr);
            return 2;
        } else if (strcmp(arg, "--steps") == 0) {
            want_steps = 1;
        } else if (strcmp(arg, "--json") == 0) {
            as_json = 1;
        } else if (strcmp(arg, "--selftest") == 0) {
            do_selftest = 1;
        } else if (strcmp(arg, "--bench") == 0) {
            do_bench = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                long mb = strtol(argv[++i], NULL, 10);
                if (mb > 0 && mb <= 4096) bench_mb = (size_t)mb;
            }
        } else if (strcmp(arg, "--alg") == 0 && i + 1 < argc) {
            if (hash_alg_from_name(argv[++i], &only) != 0) {
                fprintf(stderr, "hashlab: unknown algorithm '%s'\n", argv[i]);
                return 2;
            }
            have_algo = 1;
        } else if (arg[0] == '-' && strcmp(arg, "-") != 0) {
            fprintf(stderr, "hashlab: unknown option '%s'\n", arg);
            return 2;
        } else {
            path = arg;
        }
    }

    if (do_selftest)
        return selftest();
    if (do_bench)
        return bench(bench_mb, as_json);

    FILE *fp = stdin;
    if (path && strcmp(path, "-") != 0) {
        fp = fopen(path, "rb");
        if (!fp) {
            fprintf(stderr, "hashlab: cannot open %s\n", path);
            return 1;
        }
    }
    uint8_t *data = NULL;
    size_t len = 0;
    if (read_all(fp, &data, &len) != 0) {
        fprintf(stderr, "hashlab: out of memory reading input\n");
        if (fp != stdin) fclose(fp);
        return 1;
    }
    if (fp != stdin)
        fclose(fp);

    if (want_steps) {
        uint8_t block[HASH_BLOCK_SIZE];
        memset(block, 0, sizeof block);
        size_t take = len < HASH_BLOCK_SIZE ? len : HASH_BLOCK_SIZE;
        memcpy(block, data, take);
        if (take < HASH_BLOCK_SIZE)
            fprintf(stderr,
                    "hashlab: input shorter than one block; padding shown\n");
        for (int i = 0; i < 3; i++) {
            printf("%s first block trace:\n", hash_alg_name(ALL_ALGS[i]));
            hash_trace_block(ALL_ALGS[i], block, stdout);
        }
        free(data);
        return 0;
    }

    int count = have_algo ? 1 : 3;
    if (as_json)
        printf("{\n");
    for (int i = 0; i < count; i++) {
        hash_alg alg = have_algo ? only : ALL_ALGS[i];
        char hex[2 * HASH_MAX_DIGEST + 1];
        size_t hex_len = 0;
        digest_hex(alg, data, len, hex, &hex_len);
        if (as_json)
            printf("  \"%s\": \"%s\"%s\n", hash_alg_name(alg), hex,
                   i == count - 1 ? "" : ",");
        else
            printf("%-6s %s\n", hash_alg_name(alg), hex);
    }
    if (as_json)
        printf("}\n");
    free(data);
    return 0;
}
