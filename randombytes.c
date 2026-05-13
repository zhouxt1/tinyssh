#include "randombytes.h"

#include "haslibrandombytes.h"
#ifndef HASLIBRANDOMBYTES

/* Fuzzing harness: deterministic PRNG instead of /dev/urandom.
 * Every consumer of randomness in TinySSH (KEX cookie, x25519 ephemeral,
 * ed25519 nonce, SNTRUP761 KEM, padding) routes through randombytes(),
 * so replacing this single function makes the whole server deterministic
 * across runs of the same input — required for stable AFL coverage. */

#include <stdint.h>

static uint64_t prng_state;

__attribute__((constructor)) static void init(void) {
    prng_state = 0x123456789abcdef0ULL;
}

static uint64_t xorshift64(void) {
    uint64_t x = prng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    prng_state = x;
    return x;
}

void randombytes(void *xv, long long xlen) {
    unsigned char *x = xv;
    while (xlen > 0) {
        uint64_t r = xorshift64();
        long long n = xlen < 8 ? xlen : 8;
        for (long long j = 0; j < n; j++) {
            x[j] = (unsigned char)(r >> (j * 8));
        }
        x += n;
        xlen -= n;
    }
#ifdef __GNUC__
    __asm__ __volatile__("" : : "r"(xv) : "memory");
#endif
}

const char *randombytes_source(void) { return "deterministic-prng-fuzzing"; }

#endif
