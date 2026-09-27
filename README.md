# hashlab

**MD5, SHA-1 and SHA-256 implemented from scratch in C — RFC/FIPS known-answer vectors, per-round step dumps, and a speed comparison. Educational. No dependencies beyond libc.**

```
$ printf 'abc' | hashlab
md5    900150983cd24fb0d6963f7d28e17f72
sha1   a9993e364706816aba3e25717850c26c9cd0d89d
sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

$ hashlab --bench 8
md5       229.7 MB/s  (8 MB in 0.035s)
sha1      338.8 MB/s  (8 MB in 0.024s)
sha256    281.8 MB/s  (8 MB in 0.028s)

$ printf 'abc' | hashlab --steps
md5 first block trace:
  step  0: a=... d=...
  ...
```

Every hash library hides the same thirty lines: pad the message, run a
compression function over 64-byte blocks, append the bit length. hashlab
shows all of it — including the step-by-step register values inside a
block, which is where the magic actually lives.

## Why hashlab

- **Three algorithms, one streaming core.** `hash_update` handles
  arbitrary chunk sizes; the test suite proves one-shot and streamed
  digests agree at *every* length from 0 to 130 bytes, which is where
  padding bugs live (56, 63, 64, 119, 120).
- **Vector-verified, not self-asserted.** The MD5 suite is RFC 1321's
  Appendix A.5 test set; SHA-1/SHA-256 use the FIPS 180 examples plus the
  million-'a' long vector. The test binary additionally shells out to the
  system `md5` when present and fails on any disagreement.
- **Step dumps.** `--steps` prints MD5's rotating a/b/c/d every fourth
  step, SHA-1's round values, and SHA-256's message schedule — the actual
  internal state, not a summary.
- **Speed comparison.** MD5 is faster than SHA-256 here, but so is a
  bicycle faster than a car in a parking lot; the bench exists to make
  the trade-off concrete rather than to crown a winner.
- **Endianness traps documented.** MD5 stores the message length
  little-endian and its state words little-endian too; SHA-1/SHA-256 are
  big-endian throughout. Getting this wrong produces a correct digest for
  the empty string and garbage for everything else — the tests cover both
  paths deliberately.

## Usage

```sh
hashlab file.bin                    # all three digests
cat file.bin | hashlab              # stdin
hashlab file.bin --alg sha256       # one algorithm
hashlab file.bin --json             # {"md5": "...", "sha1": "...", ...}
hashlab file.bin --steps            # per-round trace of the first block
hashlab --bench 64                  # speed comparison, 64 MB
hashlab --selftest                  # known-answer vectors, exit 1 on failure
```

Exit codes: 0 ok, 1 selftest failure or unreadable input, 2 usage error.

## What this is not

Not a crypto library. MD5 is collision-broken, SHA-1 is collision-broken
(SHIDEY 2020), and neither should be used for signatures, certificates or
integrity. They live here to be read. For real work use SHA-256 or
BLAKE2/SHA-3.

## Development

```sh
make test    # 9 test groups + CLI smoke
```

## License

MIT — see [LICENSE](LICENSE).
