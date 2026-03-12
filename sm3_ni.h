/*
 *  SPDX-License-Identifier: MIT
 *
 *  SM3 SIMD-accelerated parallel compression for x86-64.
 *  - 4-way SSE2 (sm3_squeeze_4blocks_sse2)
 *  - 8-way AVX2 (sm3_squeeze_8blocks_avx2)
 *  Used to speed up the XOF squeeze phase where independent
 *  SM3(base || counter_i) calls can be computed simultaneously.
 */

#ifndef SM3_NI_H
#define SM3_NI_H

#if defined(__x86_64__)

#include <emmintrin.h>  /* SSE2 */
#include <immintrin.h>  /* AVX2 */
#include <stdint.h>
#include <string.h>

/* ---- SSE2 helper: 32-bit rotate left ---- */
#define SM3_MM_ROL32(x, n) \
  _mm_or_si128(_mm_slli_epi32((x), (n)), _mm_srli_epi32((x), 32 - (n)))

/* ---- SM3 permutation functions ---- */
static inline __m128i sm3_mm_P0(__m128i x) {
  return _mm_xor_si128(_mm_xor_si128(x, SM3_MM_ROL32(x, 9)),
                       SM3_MM_ROL32(x, 17));
}

static inline __m128i sm3_mm_P1(__m128i x) {
  return _mm_xor_si128(_mm_xor_si128(x, SM3_MM_ROL32(x, 15)),
                       SM3_MM_ROL32(x, 23));
}

/* ---- SM3 boolean functions ---- */
/* FF0(x,y,z) = x ^ y ^ z  (rounds 0..15) */
static inline __m128i sm3_mm_FF0(__m128i x, __m128i y, __m128i z) {
  return _mm_xor_si128(_mm_xor_si128(x, y), z);
}

/* FF1(x,y,z) = (x&y) | (x&z) | (y&z)  (rounds 16..63) */
static inline __m128i sm3_mm_FF1(__m128i x, __m128i y, __m128i z) {
  return _mm_or_si128(
      _mm_or_si128(_mm_and_si128(x, y), _mm_and_si128(x, z)),
      _mm_and_si128(y, z));
}

/* GG0(x,y,z) = x ^ y ^ z  (rounds 0..15) */
static inline __m128i sm3_mm_GG0(__m128i x, __m128i y, __m128i z) {
  return _mm_xor_si128(_mm_xor_si128(x, y), z);
}

/* GG1(x,y,z) = ((y^z) & x) ^ z  (rounds 16..63) */
static inline __m128i sm3_mm_GG1(__m128i x, __m128i y, __m128i z) {
  return _mm_xor_si128(_mm_and_si128(_mm_xor_si128(y, z), x), z);
}

/* ---- SM3 round constants (pre-rotated by j mod 32) ---- */
static const uint32_t SM3_SIMD_K[64] = {
    0x79cc4519U, 0xf3988a32U, 0xe7311465U, 0xce6228cbU,
    0x9cc45197U, 0x3988a32fU, 0x7311465eU, 0xe6228cbcU,
    0xcc451979U, 0x988a32f3U, 0x311465e7U, 0x6228cbceU,
    0xc451979cU, 0x88a32f39U, 0x11465e73U, 0x228cbce6U,
    0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
    0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
    0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
    0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
    0x7a879d8aU, 0xf50f3b14U, 0xea1e7629U, 0xd43cec53U,
    0xa879d8a7U, 0x50f3b14fU, 0xa1e7629eU, 0x43cec53dU,
    0x879d8a7aU, 0x0f3b14f5U, 0x1e7629eaU, 0x3cec53d4U,
    0x79d8a7a8U, 0xf3b14f50U, 0xe7629ea1U, 0xcec53d43U,
    0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
    0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
    0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
    0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
};

/* ---- Big-endian read/write helpers ---- */
static inline uint32_t sm3_be32(const uint8_t p[4]) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
         (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static inline void sm3_put_be32(uint8_t p[4], uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)(v);
}

/* ======================================================================
 * sm3_squeeze_4blocks_sse2
 *
 * Computes 4 independent SM3 hashes in parallel:
 *   out[0..31]   = SM3(base || counter_be32(ctr))
 *   out[32..63]  = SM3(base || counter_be32(ctr+1))
 *   out[64..95]  = SM3(base || counter_be32(ctr+2))
 *   out[96..127] = SM3(base || counter_be32(ctr+3))
 *
 * Each message is exactly 36 bytes (base=32 + counter=4), padded to
 * one 64-byte SM3 block.
 * ====================================================================== */
__attribute__((target("sse2")))
static void sm3_squeeze_4blocks_sse2(const uint8_t base[32],
                                      uint32_t      ctr,
                                      uint8_t       out[128]) {
  /* ---- Initialize 4-way state with SM3 IV ---- */
  __m128i A = _mm_set1_epi32((int)0x7380166FU);
  __m128i B = _mm_set1_epi32((int)0x4914B2B9U);
  __m128i C = _mm_set1_epi32((int)0x172442D7U);
  __m128i D = _mm_set1_epi32((int)0xDA8A0600U);
  __m128i E = _mm_set1_epi32((int)0xA96F30BCU);
  __m128i F = _mm_set1_epi32((int)0x163138AAU);
  __m128i G = _mm_set1_epi32((int)0xE38DEE4DU);
  __m128i H = _mm_set1_epi32((int)0xB0FB0E4EU);

  /* Save initial state for final XOR */
  __m128i sA = A, sB = B, sC = C, sD = D;
  __m128i sE = E, sF = F, sG = G, sH = H;

  /* ---- Load message words W[0..15] ---- */
  __m128i W[68];

  /* W[0..7] = base words (same for all 4 lanes, big-endian read) */
  for (int j = 0; j < 8; j++) {
    W[j] = _mm_set1_epi32((int)sm3_be32(base + j * 4));
  }

  /* W[8] = counter (different per lane) */
  W[8] = _mm_set_epi32((int)(ctr + 3), (int)(ctr + 2),
                        (int)(ctr + 1), (int)(ctr));

  /* W[9] = 0x80000000 (padding byte 0x80 at position 36, then zeros) */
  W[9] = _mm_set1_epi32((int)0x80000000U);

  /* W[10..13] = 0 */
  W[10] = _mm_setzero_si128();
  W[11] = _mm_setzero_si128();
  W[12] = _mm_setzero_si128();
  W[13] = _mm_setzero_si128();

  /* W[14] = 0 (high 32 bits of bit-length, nblocks=0 so 0) */
  W[14] = _mm_setzero_si128();

  /* W[15] = 288 (bit-length = 36 bytes * 8 = 288) */
  W[15] = _mm_set1_epi32(288);

  /* ---- Message expansion: W[16..67] ---- */
  for (int j = 16; j < 68; j++) {
    /* W[j] = P1(W[j-16] ^ W[j-9] ^ ROL32(W[j-3], 15))
     *        ^ ROL32(W[j-13], 7) ^ W[j-6] */
    __m128i t = _mm_xor_si128(
        _mm_xor_si128(W[j - 16], W[j - 9]),
        SM3_MM_ROL32(W[j - 3], 15));
    W[j] = _mm_xor_si128(
        _mm_xor_si128(sm3_mm_P1(t), SM3_MM_ROL32(W[j - 13], 7)),
        W[j - 6]);
  }

  /* ---- Compression: 64 rounds ---- */
  __m128i SS0, SS1, SS2;

  /* Rounds 0..15: use FF0/GG0 */
  for (int j = 0; j < 16; j++) {
    __m128i Kj = _mm_set1_epi32((int)SM3_SIMD_K[j]);
    SS0 = SM3_MM_ROL32(A, 12);
    SS1 = SM3_MM_ROL32(
        _mm_add_epi32(_mm_add_epi32(SS0, E), Kj), 7);
    SS2 = _mm_xor_si128(SS1, SS0);

    __m128i TT1 = _mm_add_epi32(
        _mm_add_epi32(sm3_mm_FF0(A, B, C), D),
        _mm_add_epi32(SS2, _mm_xor_si128(W[j], W[j + 4])));
    __m128i TT2 = _mm_add_epi32(
        _mm_add_epi32(sm3_mm_GG0(E, F, G), H),
        _mm_add_epi32(SS1, W[j]));

    D = C;
    C = SM3_MM_ROL32(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = SM3_MM_ROL32(F, 19);
    F = E;
    E = sm3_mm_P0(TT2);
  }

  /* Rounds 16..63: use FF1/GG1 */
  for (int j = 16; j < 64; j++) {
    __m128i Kj = _mm_set1_epi32((int)SM3_SIMD_K[j]);
    SS0 = SM3_MM_ROL32(A, 12);
    SS1 = SM3_MM_ROL32(
        _mm_add_epi32(_mm_add_epi32(SS0, E), Kj), 7);
    SS2 = _mm_xor_si128(SS1, SS0);

    __m128i TT1 = _mm_add_epi32(
        _mm_add_epi32(sm3_mm_FF1(A, B, C), D),
        _mm_add_epi32(SS2, _mm_xor_si128(W[j], W[j + 4])));
    __m128i TT2 = _mm_add_epi32(
        _mm_add_epi32(sm3_mm_GG1(E, F, G), H),
        _mm_add_epi32(SS1, W[j]));

    D = C;
    C = SM3_MM_ROL32(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = SM3_MM_ROL32(F, 19);
    F = E;
    E = sm3_mm_P0(TT2);
  }

  /* ---- Final XOR with initial state ---- */
  A = _mm_xor_si128(A, sA);
  B = _mm_xor_si128(B, sB);
  C = _mm_xor_si128(C, sC);
  D = _mm_xor_si128(D, sD);
  E = _mm_xor_si128(E, sE);
  F = _mm_xor_si128(F, sF);
  G = _mm_xor_si128(G, sG);
  H = _mm_xor_si128(H, sH);

  /* ---- Extract 4 digests (big-endian output) ---- */
  __m128i state[8] = {A, B, C, D, E, F, G, H};
  uint32_t tmp[4];

  for (int w = 0; w < 8; w++) {
    _mm_storeu_si128((__m128i*)tmp, state[w]);
    /* Lane 0 → out[0..31], Lane 1 → out[32..63], etc. */
    sm3_put_be32(out + 0 * 32 + w * 4, tmp[0]);
    sm3_put_be32(out + 1 * 32 + w * 4, tmp[1]);
    sm3_put_be32(out + 2 * 32 + w * 4, tmp[2]);
    sm3_put_be32(out + 3 * 32 + w * 4, tmp[3]);
  }
}

/* ======================================================================
 * AVX2 8-way parallel SM3 squeeze
 * ====================================================================== */

/* ---- AVX2 helper: 32-bit rotate left ---- */
#define SM3_YMM_ROL32(x, n) \
  _mm256_or_si256(_mm256_slli_epi32((x), (n)), _mm256_srli_epi32((x), 32 - (n)))

/* ---- SM3 permutation functions (AVX2) ---- */
ATTR_TARGET_AVX2
static inline __m256i sm3_ymm_P0(__m256i x) {
  return _mm256_xor_si256(_mm256_xor_si256(x, SM3_YMM_ROL32(x, 9)),
                          SM3_YMM_ROL32(x, 17));
}

ATTR_TARGET_AVX2
static inline __m256i sm3_ymm_P1(__m256i x) {
  return _mm256_xor_si256(_mm256_xor_si256(x, SM3_YMM_ROL32(x, 15)),
                          SM3_YMM_ROL32(x, 23));
}

/* ---- SM3 boolean functions (AVX2) ---- */
ATTR_TARGET_AVX2
static inline __m256i sm3_ymm_FF0(__m256i x, __m256i y, __m256i z) {
  return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
}

ATTR_TARGET_AVX2
static inline __m256i sm3_ymm_FF1(__m256i x, __m256i y, __m256i z) {
  return _mm256_or_si256(
      _mm256_or_si256(_mm256_and_si256(x, y), _mm256_and_si256(x, z)),
      _mm256_and_si256(y, z));
}

ATTR_TARGET_AVX2
static inline __m256i sm3_ymm_GG0(__m256i x, __m256i y, __m256i z) {
  return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
}

ATTR_TARGET_AVX2
static inline __m256i sm3_ymm_GG1(__m256i x, __m256i y, __m256i z) {
  return _mm256_xor_si256(_mm256_and_si256(_mm256_xor_si256(y, z), x), z);
}

/* ======================================================================
 * sm3_squeeze_8blocks_avx2
 *
 * Computes 8 independent SM3 hashes in parallel:
 *   out[i*32 .. (i+1)*32-1] = SM3(base || counter_be32(ctr + i))
 * for i = 0..7.  Total output: 256 bytes.
 * ====================================================================== */
ATTR_TARGET_AVX2
static void sm3_squeeze_8blocks_avx2(const uint8_t base[32],
                                      uint32_t      ctr,
                                      uint8_t       out[256]) {
  /* ---- Initialize 8-way state with SM3 IV ---- */
  __m256i A = _mm256_set1_epi32((int)0x7380166FU);
  __m256i B = _mm256_set1_epi32((int)0x4914B2B9U);
  __m256i C = _mm256_set1_epi32((int)0x172442D7U);
  __m256i D = _mm256_set1_epi32((int)0xDA8A0600U);
  __m256i E = _mm256_set1_epi32((int)0xA96F30BCU);
  __m256i F = _mm256_set1_epi32((int)0x163138AAU);
  __m256i G = _mm256_set1_epi32((int)0xE38DEE4DU);
  __m256i H = _mm256_set1_epi32((int)0xB0FB0E4EU);

  /* Save initial state for final XOR */
  __m256i sA = A, sB = B, sC = C, sD = D;
  __m256i sE = E, sF = F, sG = G, sH = H;

  /* ---- Load message words W[0..15] ---- */
  __m256i W[68];

  /* W[0..7] = base words (same for all 8 lanes) */
  for (int j = 0; j < 8; j++) {
    W[j] = _mm256_set1_epi32((int)sm3_be32(base + j * 4));
  }

  /* W[8] = counter (different per lane: ctr, ctr+1, ..., ctr+7) */
  W[8] = _mm256_set_epi32((int)(ctr + 7), (int)(ctr + 6),
                           (int)(ctr + 5), (int)(ctr + 4),
                           (int)(ctr + 3), (int)(ctr + 2),
                           (int)(ctr + 1), (int)(ctr));

  /* W[9] = 0x80000000 (padding) */
  W[9] = _mm256_set1_epi32((int)0x80000000U);

  /* W[10..14] = 0 */
  W[10] = _mm256_setzero_si256();
  W[11] = _mm256_setzero_si256();
  W[12] = _mm256_setzero_si256();
  W[13] = _mm256_setzero_si256();
  W[14] = _mm256_setzero_si256();

  /* W[15] = 288 (bit-length) */
  W[15] = _mm256_set1_epi32(288);

  /* ---- Message expansion: W[16..67] ---- */
  for (int j = 16; j < 68; j++) {
    __m256i t = _mm256_xor_si256(
        _mm256_xor_si256(W[j - 16], W[j - 9]),
        SM3_YMM_ROL32(W[j - 3], 15));
    W[j] = _mm256_xor_si256(
        _mm256_xor_si256(sm3_ymm_P1(t), SM3_YMM_ROL32(W[j - 13], 7)),
        W[j - 6]);
  }

  /* ---- Compression: 64 rounds ---- */
  __m256i SS0, SS1, SS2;

  /* Rounds 0..15: FF0/GG0 */
  for (int j = 0; j < 16; j++) {
    __m256i Kj = _mm256_set1_epi32((int)SM3_SIMD_K[j]);
    SS0 = SM3_YMM_ROL32(A, 12);
    SS1 = SM3_YMM_ROL32(
        _mm256_add_epi32(_mm256_add_epi32(SS0, E), Kj), 7);
    SS2 = _mm256_xor_si256(SS1, SS0);

    __m256i TT1 = _mm256_add_epi32(
        _mm256_add_epi32(sm3_ymm_FF0(A, B, C), D),
        _mm256_add_epi32(SS2, _mm256_xor_si256(W[j], W[j + 4])));
    __m256i TT2 = _mm256_add_epi32(
        _mm256_add_epi32(sm3_ymm_GG0(E, F, G), H),
        _mm256_add_epi32(SS1, W[j]));

    D = C;
    C = SM3_YMM_ROL32(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = SM3_YMM_ROL32(F, 19);
    F = E;
    E = sm3_ymm_P0(TT2);
  }

  /* Rounds 16..63: FF1/GG1 */
  for (int j = 16; j < 64; j++) {
    __m256i Kj = _mm256_set1_epi32((int)SM3_SIMD_K[j]);
    SS0 = SM3_YMM_ROL32(A, 12);
    SS1 = SM3_YMM_ROL32(
        _mm256_add_epi32(_mm256_add_epi32(SS0, E), Kj), 7);
    SS2 = _mm256_xor_si256(SS1, SS0);

    __m256i TT1 = _mm256_add_epi32(
        _mm256_add_epi32(sm3_ymm_FF1(A, B, C), D),
        _mm256_add_epi32(SS2, _mm256_xor_si256(W[j], W[j + 4])));
    __m256i TT2 = _mm256_add_epi32(
        _mm256_add_epi32(sm3_ymm_GG1(E, F, G), H),
        _mm256_add_epi32(SS1, W[j]));

    D = C;
    C = SM3_YMM_ROL32(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = SM3_YMM_ROL32(F, 19);
    F = E;
    E = sm3_ymm_P0(TT2);
  }

  /* ---- Final XOR with saved initial state ---- */
  A = _mm256_xor_si256(A, sA);
  B = _mm256_xor_si256(B, sB);
  C = _mm256_xor_si256(C, sC);
  D = _mm256_xor_si256(D, sD);
  E = _mm256_xor_si256(E, sE);
  F = _mm256_xor_si256(F, sF);
  G = _mm256_xor_si256(G, sG);
  H = _mm256_xor_si256(H, sH);

  /* ---- Extract 8 digests (big-endian output) ---- */
  __m256i state[8] = {A, B, C, D, E, F, G, H};
  uint32_t tmp[8];

  for (int w = 0; w < 8; w++) {
    _mm256_storeu_si256((__m256i*)tmp, state[w]);
    for (int lane = 0; lane < 8; lane++) {
      sm3_put_be32(out + lane * 32 + w * 4, tmp[lane]);
    }
  }

  _mm256_zeroupper();
}

#endif /* __x86_64__ */

#endif /* SM3_NI_H */
