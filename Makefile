CC      ?= cc
CFLAGS  ?= -O2 -std=c11 -Wall -Wextra -Wpedantic

SRC = src/hash.c src/md5.c src/sha1.c src/sha256.c src/main.c

all: hashlab

hashlab: $(SRC) src/hash.h
	$(CC) $(CFLAGS) -o $@ $(SRC)

hash_tests: tests/hash_tests.c src/hash.c src/md5.c src/sha1.c src/sha256.c src/hash.h
	$(CC) $(CFLAGS) -o hash_tests tests/hash_tests.c src/hash.c src/md5.c src/sha1.c src/sha256.c

test: hashlab hash_tests
	./hash_tests
	./hashlab --selftest | grep -q '^FAIL' && exit 1; \
	printf 'abc' | ./hashlab --json | grep -q '"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"'; \
	printf 'abc' | ./hashlab --alg md5 | grep -q '900150983cd24fb0d6963f7d28e17f72'; \
	printf 'abc' | ./hashlab --steps | grep -q 'step 63'; \
	./hashlab --bench 2 | grep -q 'sha256' && echo "smoke: selftest/json/single-alg/steps/bench OK"

clean:
	rm -f hashlab hash_tests

.PHONY: all test clean
