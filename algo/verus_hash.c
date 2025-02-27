#include "verus_hash.h"
#include <stdint.h>
#include <string.h>
#include <immintrin.h>  // AVX, AVX2, AVX512
#include <wmmintrin.h>  // AES-NI

#define SHA3_512_RATE 72
#define SHA3_512_ROUNDS 24

static const uint64_t keccak_rc[SHA3_512_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static void keccak_permute(uint64_t state[25]) {
    for (int round = 0; round < SHA3_512_ROUNDS; round++) {
        __m512i C[5], D[5];

        for (int i = 0; i < 5; i++)
            C[i] = _mm512_xor_si512(
                _mm512_xor_si512(_mm512_set1_epi64(state[i]), _mm512_set1_epi64(state[i + 5])),
                _mm512_xor_si512(_mm512_set1_epi64(state[i + 10]), _mm512_set1_epi64(state[i + 15])));

        for (int i = 0; i < 5; i++)
            D[i] = _mm512_xor_si512(C[(i + 4) % 5], _mm512_slli_epi64(C[(i + 1) % 5], 1));

        for (int i = 0; i < 25; i += 5)
            for (int j = 0; j < 5; j++)
                state[i + j] ^= _mm512_extract_epi64(D[j], 0);

        state[0] ^= keccak_rc[round];
    }
}

static void sha3_512(const uint8_t *input, size_t input_len, uint8_t *output) {
    uint64_t state[25] = {0};
    uint8_t block[SHA3_512_RATE] = {0};

    while (input_len >= SHA3_512_RATE) {
        __m512i *state_vec = (__m512i *)state;
        __m512i *input_vec = (__m512i *)input;

        for (int i = 0; i < SHA3_512_RATE / 64; i++)
            state_vec[i] = _mm512_xor_si512(state_vec[i], input_vec[i]);

        keccak_permute(state);
        input += SHA3_512_RATE;
        input_len -= SHA3_512_RATE;
    }

    memcpy(block, input, input_len);
    block[input_len] = 0x06;
    block[SHA3_512_RATE - 1] |= 0x80;

    __m512i *state_vec = (__m512i *)state;
    __m512i *block_vec = (__m512i *)block;

    for (int i = 0; i < SHA3_512_RATE / 64; i++)
        state_vec[i] = _mm512_xor_si512(state_vec[i], block_vec[i]);

    keccak_permute(state);
    memcpy(output, state, 64);
}

void verus_hash(const void *input, void *output, uint32_t len) {
    sha3_512((const uint8_t *)input, len, (uint8_t *)output);
}
