/*
 *  SPDX-License-Identifier: MIT
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#ifndef FAEST_SM4_ALLOW_TTABLE
#define FAEST_SM4_ALLOW_TTABLE 0
#endif

#include "sm4.h"
#if FAEST_SM4_ALLOW_TTABLE
#include "sm4_ni.h"
#endif
#include "cpu.h"
#include "fields.h"
#include "compat.h"
#include "utils.h"

#include <assert.h>
#include <string.h>

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#include <immintrin.h>
#endif

// ============ SM4 S-box (国密标准 GM/T 0002-2012) ============
static const uint8_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// ============ 系统参数 FK ============
static const uint32_t FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

// ============ 固定参数 CK ============
static const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// ============ S-box 查找 ============
uint8_t sm4_sbox(uint8_t in) {
  return SM4_SBOX[in];
}

// ============ 合成置换 τ: τ(A) = (Sbox(a0), Sbox(a1), Sbox(a2), Sbox(a3)) ============
uint32_t sm4_tau(uint32_t a) {
  uint8_t bytes[4];
  sm4_uint32_to_bytes(a, bytes);
  
  bytes[0] = sm4_sbox(bytes[0]);
  bytes[1] = sm4_sbox(bytes[1]);
  bytes[2] = sm4_sbox(bytes[2]);
  bytes[3] = sm4_sbox(bytes[3]);
  
  return sm4_bytes_to_uint32(bytes);
}

// ============ 循环左移 ============
static inline uint32_t sm4_rotl32(uint32_t x, unsigned int n) {
  return (x << n) | (x >> (32 - n));
}

// ============ 线性变换 L (用于加密): L(B) = B ⊕ (B<<<2) ⊕ (B<<<10) ⊕ (B<<<18) ⊕ (B<<<24) ============
uint32_t sm4_linear_l(uint32_t b) {
  return b ^ sm4_rotl32(b, 2) ^ sm4_rotl32(b, 10) ^ sm4_rotl32(b, 18) ^ sm4_rotl32(b, 24);
}

// ============ 线性变换 L' (用于密钥扩展): L'(B) = B ⊕ (B<<<13) ⊕ (B<<<23) ============
uint32_t sm4_linear_l_prime(uint32_t b) {
  return b ^ sm4_rotl32(b, 13) ^ sm4_rotl32(b, 23);
}

// ============ T 变换 (加密用): T(X) = L(τ(X)) ============
static inline uint32_t sm4_t(uint32_t x) {
  return sm4_linear_l(sm4_tau(x));
}

// ============ T' 变换 (密钥扩展用): T'(X) = L'(τ(X)) ============
static inline uint32_t sm4_t_prime(uint32_t x) {
  return sm4_linear_l_prime(sm4_tau(x));
}

#if defined(FAEST_TESTS)
void sm4_increment_iv(uint8_t* iv);
#else
static inline void sm4_increment_iv(uint8_t* iv);
#endif

// ============ 完整 bitsliced SM4（8-way）============

#define SM4_BITSLICE_LANES 64
#define SM4_BITSLICE_MIN_BATCH 16
typedef uint64_t sm4_bs_word_t;

static inline void sm4_bs_sbox_8x8(const sm4_bs_word_t in_bits[8], sm4_bs_word_t out_bits[8]) {
  sm4_bs_word_t b0 = in_bits[0], b1 = in_bits[1], b2 = in_bits[2], b3 = in_bits[3];
  sm4_bs_word_t b4 = in_bits[4], b5 = in_bits[5], b6 = in_bits[6], b7 = in_bits[7];
  sm4_bs_word_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
  sm4_bs_word_t t10, t11, t12, t13, t14, t15, t16, t17, t18, t19, t20;
  sm4_bs_word_t p0, p1, p2, p3;
  sm4_bs_word_t l0, l1, l2, l3;
  sm4_bs_word_t k0, k1, k2, k3, k4;
  sm4_bs_word_t e0, e1, e2, e3, e4, e5, e6, e7, e8, e9;
  sm4_bs_word_t e10, e11, e12, e13, e14, e15, e16, e17;
  sm4_bs_word_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11;
  sm4_bs_word_t m0, m1, m2, m3, m4, m5, m6, m7, m8, m9;
  sm4_bs_word_t g0, g1, g2, g3, g4, g5, g6, g7;

  t1 = b7 ^ b5;
  m6 = b1;
  t2 = b5 ^ b1;
  g5 = ~b0;
  t3 = ~(b0 ^ t2);
  t4 = b6 ^ b2;
  t5 = b3 ^ t3;
  t6 = b4 ^ t1;
  t7 = b1 ^ t5;
  t8 = b1 ^ t4;
  t9 = t6 ^ t8;

  g1 = t7;
  g3 = t5;
  g4 = t2;
  m0 = t6;
  m1 = t3;
  m2 = t8;
  m4 = t4;
  t11 = ~(b3 ^ t1);
  m5 = t11;
  t12 = ~(b6 ^ t9);
  m9 = t12;
  t10 = t6 ^ t7;
  g0 = t10;
  t13 = t4 ^ t10;
  g2 = t13;
  t14 = t2 ^ t11;
  g6 = t14;
  t15 = t12 ^ t14;
  g7 = t15;
  t16 = t3 ^ t12;
  m3 = t16;
  t17 = t11 ^ t16;
  m7 = t17;
  m8 = t9;

  t2 = m0 & m1;
  t3 = g0 & g4;
  t4 = g3 & g7;
  t7 = g3 | g7;
  t11 = m4 & m5;
  t10 = m3 & m2;
  t12 = m3 | m2;
  t6 = g6 | g2;
  t9 = m6 | m7;
  t5 = m8 & m9;
  t8 = m8 | m9;
  t14 = t3 ^ t2;
  t16 = t5 ^ t14;
  t20 = t16 ^ t7;
  t17 = t9 ^ t10;
  t18 = t11 ^ t12;
  p2 = t20 ^ t18;
  p0 = t6 ^ t16;
  t1 = g5 & g1;
  t13 = t1 ^ t2;
  t15 = t13 ^ t4;
  t19 = t6 ^ t15;
  p3 = t19 ^ t17;
  p1 = t8 ^ t15;

  t0 = p1 & p2;
  t1 = p3 & p0;
  t2 = p0 & p2;
  t3 = p1 & p3;
  t4 = t0 & t2;
  t5 = t1 ^ t3;
  t6 = t5 | p0;
  t7 = t2 | p3;
  t8 = t4 ^ t6;
  t9 = t7 ^ t3;
  t10 = t0 ^ t9;
  t11 = p2 | t5;
  l1 = t11 ^ t1;
  t12 = p1 | t2;
  l2 = t12 ^ t5;
  l0 = t10;
  l3 = t8;

  k4 = l2 ^ l3;
  k3 = l1 ^ l3;
  k2 = l0 ^ l2;
  k0 = l0 ^ l1;
  k1 = k2 ^ k3;

  e0 = m1 & k0;
  e1 = g5 & l1;
  r0 = e0 ^ e1;
  e2 = g4 & l0;
  r1 = e2 ^ e1;
  e3 = m7 & k3;
  e4 = m5 & k2;
  r2 = e3 ^ e4;
  e5 = m3 & k1;
  r3 = e5 ^ e4;
  e6 = m9 & k4;
  e7 = g7 & l3;
  r4 = e7 ^ e6;
  e8 = g6 & l2;
  r5 = e8 ^ e6;
  e9 = m0 & k0;
  e10 = g1 & l1;
  r6 = e9 ^ e10;
  e11 = g0 & l0;
  r7 = e11 ^ e10;
  e12 = m6 & k3;
  e13 = m4 & k2;
  r8 = e12 ^ e13;
  e14 = m2 & k1;
  r9 = e14 ^ e13;
  e15 = m8 & k4;
  e16 = g3 & l3;
  r10 = e15 ^ e16;
  e17 = g2 & l2;
  r11 = e17 ^ e16;

  t1 = r7 ^ r9;
  t2 = t1 ^ r1;
  t3 = t2 ^ r3;
  t4 = r5 ^ r3;
  t5 = r4 ^ t4;
  t6 = r0 ^ r4;
  t7 = r11 ^ r7;
  t8 = t1 ^ t4;
  t9 = t1 ^ t6;
  t10 = r2 ^ t5;
  t11 = r10 ^ r8;
  t12 = ~(t3 ^ t11);
  t13 = t10 ^ t12;
  t14 = ~(t3 ^ t7);
  t16 = t6 ^ t14;
  t15 = ~(r10 ^ r6);

  out_bits[0] = t16;
  out_bits[1] = t12;
  out_bits[2] = t9;
  out_bits[3] = t11;
  out_bits[4] = t14;
  out_bits[5] = t8;
  out_bits[6] = t13;
  out_bits[7] = t15;
}

static inline void sm4_bs_transpose32x32_u32_swar(const uint32_t in[32], uint32_t out[32]);
static inline bool sm4_bs_avx2_available(void);
#if (defined(__x86_64__) || defined(__i386__)) && defined(__GNUC__)
__attribute__((target("avx2"))) static void sm4_bs_transpose32x32_u32_avx2(const uint32_t in[32],
                                                                             uint32_t out[32]);
#endif

static inline void sm4_bs_pack_word_slices(const uint32_t words[SM4_BITSLICE_LANES], sm4_bs_word_t slices[32]) {
#if SM4_BITSLICE_LANES == 64
  uint32_t lo[32], hi[32], lo_t[32], hi_t[32];
  memcpy(lo, words, 32 * sizeof(uint32_t));
  memcpy(hi, words + 32, 32 * sizeof(uint32_t));

  if (sm4_bs_avx2_available()) {
    sm4_bs_transpose32x32_u32_avx2(lo, lo_t);
    sm4_bs_transpose32x32_u32_avx2(hi, hi_t);
  } else {
    sm4_bs_transpose32x32_u32_swar(lo, lo_t);
    sm4_bs_transpose32x32_u32_swar(hi, hi_t);
  }

  for (unsigned int bit = 0; bit < 32; ++bit) {
    slices[bit] = ((sm4_bs_word_t)hi_t[bit] << 32) | (sm4_bs_word_t)lo_t[bit];
  }
#else
  for (unsigned int bit = 0; bit < 32; ++bit) {
    sm4_bs_word_t mask = 0;
    for (unsigned int lane = 0; lane < SM4_BITSLICE_LANES; ++lane) {
      mask |= ((sm4_bs_word_t)((words[lane] >> bit) & 1u) << lane);
    }
    slices[bit] = mask;
  }
#endif
}

static inline void sm4_bs_unpack_word_slices(const sm4_bs_word_t slices[32], uint32_t words[SM4_BITSLICE_LANES]) {
#if SM4_BITSLICE_LANES == 64
  uint32_t lo[32], hi[32], lo_t[32], hi_t[32];
  for (unsigned int bit = 0; bit < 32; ++bit) {
    lo[bit] = (uint32_t)(slices[bit]);
    hi[bit] = (uint32_t)(slices[bit] >> 32);
  }

  if (sm4_bs_avx2_available()) {
    sm4_bs_transpose32x32_u32_avx2(lo, lo_t);
    sm4_bs_transpose32x32_u32_avx2(hi, hi_t);
  } else {
    sm4_bs_transpose32x32_u32_swar(lo, lo_t);
    sm4_bs_transpose32x32_u32_swar(hi, hi_t);
  }

  memcpy(words, lo_t, 32 * sizeof(uint32_t));
  memcpy(words + 32, hi_t, 32 * sizeof(uint32_t));
#else
  for (unsigned int lane = 0; lane < SM4_BITSLICE_LANES; ++lane) {
    uint32_t value = 0;
    for (unsigned int bit = 0; bit < 32; ++bit) {
      value |= (uint32_t)(((slices[bit] >> lane) & (sm4_bs_word_t)1u) << bit);
    }
    words[lane] = value;
  }
#endif
}

static inline void sm4_bs_transpose32x32_u32_swar(const uint32_t in[32], uint32_t out[32]) {
  uint32_t x[32];
  memcpy(x, in, 32 * sizeof(uint32_t));
  for (unsigned int j = 16, m = 0x0000FFFFu; j != 0; j >>= 1, m ^= (m << j)) {
    for (unsigned int k = 0; k < 32; k = (k + j + 1u) & ~j) {
      const uint32_t t = (x[k] ^ (x[k + j] >> j)) & m;
      x[k] ^= t;
      x[k + j] ^= (t << j);
    }
  }
  memcpy(out, x, 32 * sizeof(uint32_t));
}

static inline bool sm4_bs_avx2_available(void) {
#if (defined(__x86_64__) || defined(__i386__)) && defined(__GNUC__)
  static int cached = -1;
  if (cached < 0) {
    cached = __builtin_cpu_supports("avx2") ? 1 : 0;
  }
  return cached == 1;
#else
  return false;
#endif
}

#if (defined(__x86_64__) || defined(__i386__)) && defined(__GNUC__)
__attribute__((target("avx2"))) static void sm4_bs_transpose32x32_u32_avx2(const uint32_t in[32],
                                                                             uint32_t out[32]) {
  const __m128i flip = _mm_setr_epi8(0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15);

  __m128i t1 = _mm_shuffle_epi8(_mm_setr_epi32((int)in[0], (int)in[1], (int)in[2], (int)in[3]), flip);
  __m128i t2 = _mm_shuffle_epi8(_mm_setr_epi32((int)in[4], (int)in[5], (int)in[6], (int)in[7]), flip);
  __m128i t3 = _mm_shuffle_epi8(_mm_setr_epi32((int)in[8], (int)in[9], (int)in[10], (int)in[11]), flip);
  __m128i t4 = _mm_shuffle_epi8(_mm_setr_epi32((int)in[12], (int)in[13], (int)in[14], (int)in[15]), flip);
  __m128i t5 = _mm_shuffle_epi8(_mm_setr_epi32((int)in[16], (int)in[17], (int)in[18], (int)in[19]), flip);
  __m128i t6 = _mm_shuffle_epi8(_mm_setr_epi32((int)in[20], (int)in[21], (int)in[22], (int)in[23]), flip);
  __m128i t7 = _mm_shuffle_epi8(_mm_setr_epi32((int)in[24], (int)in[25], (int)in[26], (int)in[27]), flip);
  __m128i t8 = _mm_shuffle_epi8(_mm_setr_epi32((int)in[28], (int)in[29], (int)in[30], (int)in[31]), flip);

  __m128i h = _mm_unpackhi_epi32(t1, t2);
  t1 = _mm_unpacklo_epi32(t1, t2);
  __m128i l = _mm_unpacklo_epi32(t3, t4);
  t3 = _mm_unpackhi_epi32(t3, t4);
  t2 = _mm_unpackhi_epi64(t1, l);
  t1 = _mm_unpacklo_epi64(t1, l);
  t4 = _mm_unpackhi_epi64(h, t3);
  t3 = _mm_unpacklo_epi64(h, t3);

  h = _mm_unpackhi_epi32(t5, t6);
  t5 = _mm_unpacklo_epi32(t5, t6);
  l = _mm_unpacklo_epi32(t7, t8);
  t7 = _mm_unpackhi_epi32(t7, t8);
  t6 = _mm_unpackhi_epi64(t5, l);
  t5 = _mm_unpacklo_epi64(t5, l);
  t8 = _mm_unpackhi_epi64(h, t7);
  t7 = _mm_unpacklo_epi64(h, t7);

  const __m128i lo_vecs[4] = {t1, t2, t3, t4};
  const __m128i hi_vecs[4] = {t5, t6, t7, t8};

  for (unsigned int group = 0; group < 4; ++group) {
    __m256i tmp = _mm256_castsi128_si256(lo_vecs[group]);
    tmp         = _mm256_inserti128_si256(tmp, hi_vecs[group], 1);
    for (unsigned int i = 0; i < 8; ++i) {
      out[group * 8 + (7 - i)] = (uint32_t)_mm256_movemask_epi8(tmp);
      tmp                      = _mm256_slli_epi64(tmp, 1);
    }
  }
}
#endif

static inline void sm4_bs_tau_word(const sm4_bs_word_t in_slices[32], sm4_bs_word_t out_slices[32]) {
  for (unsigned int byte_off = 0; byte_off < 32; byte_off += 8) {
    sm4_bs_word_t sb_in[8];
    sm4_bs_word_t sb_out[8];
    for (unsigned int i = 0; i < 8; ++i) {
      sb_in[i] = in_slices[byte_off + i];
    }
    sm4_bs_sbox_8x8(sb_in, sb_out);
    for (unsigned int i = 0; i < 8; ++i) {
      out_slices[byte_off + i] = sb_out[i];
    }
  }
}

static inline void sm4_bs_linear_l_word(const sm4_bs_word_t in_slices[32], sm4_bs_word_t out_slices[32]) {
  for (unsigned int bit = 0; bit < 32; ++bit) {
    out_slices[bit] = in_slices[bit] ^ in_slices[(bit - 2) & 31] ^ in_slices[(bit - 10) & 31] ^
                      in_slices[(bit - 18) & 31] ^ in_slices[(bit - 24) & 31];
  }
}

static void sm4_encrypt_8blocks_bitslice(const sm4_round_keys_t* rk,
                                         const uint8_t in_blocks[SM4_BITSLICE_LANES][SM4_BLOCK_SIZE],
                                         uint8_t out_blocks[SM4_BITSLICE_LANES][SM4_BLOCK_SIZE]) {
  uint32_t w0[SM4_BITSLICE_LANES], w1[SM4_BITSLICE_LANES], w2[SM4_BITSLICE_LANES], w3[SM4_BITSLICE_LANES];
  for (unsigned int lane = 0; lane < SM4_BITSLICE_LANES; ++lane) {
    w0[lane] = sm4_bytes_to_uint32(in_blocks[lane] + 0);
    w1[lane] = sm4_bytes_to_uint32(in_blocks[lane] + 4);
    w2[lane] = sm4_bytes_to_uint32(in_blocks[lane] + 8);
    w3[lane] = sm4_bytes_to_uint32(in_blocks[lane] + 12);
  }

  sm4_bs_word_t x0[32], x1[32], x2[32], x3[32];
  sm4_bs_pack_word_slices(w0, x0);
  sm4_bs_pack_word_slices(w1, x1);
  sm4_bs_pack_word_slices(w2, x2);
  sm4_bs_pack_word_slices(w3, x3);

  sm4_bs_word_t* s0 = x0;
  sm4_bs_word_t* s1 = x1;
  sm4_bs_word_t* s2 = x2;
  sm4_bs_word_t* s3 = x3;

  for (unsigned int round = 0; round < SM4_ROUNDS; ++round) {
    sm4_bs_word_t t_in[32], t_tau[32], t_l[32], x_new[32];
    const uint32_t rk_word = rk->round_keys[round];
    for (unsigned int bit = 0; bit < 32; ++bit) {
      const sm4_bs_word_t rk_mask = ((rk_word >> bit) & 1u) ? ~(sm4_bs_word_t)0 : 0;
      t_in[bit] = s1[bit] ^ s2[bit] ^ s3[bit] ^ rk_mask;
    }

    sm4_bs_tau_word(t_in, t_tau);
    sm4_bs_linear_l_word(t_tau, t_l);

    for (unsigned int bit = 0; bit < 32; ++bit) {
      x_new[bit] = s0[bit] ^ t_l[bit];
    }

    sm4_bs_word_t* old_s0 = s0;
    s0 = s1;
    s1 = s2;
    s2 = s3;
    s3 = old_s0;
    memcpy(s3, x_new, sizeof(x_new));
  }

  uint32_t y3[SM4_BITSLICE_LANES], y2[SM4_BITSLICE_LANES], y1[SM4_BITSLICE_LANES], y0[SM4_BITSLICE_LANES];
  sm4_bs_unpack_word_slices(s3, y3);
  sm4_bs_unpack_word_slices(s2, y2);
  sm4_bs_unpack_word_slices(s1, y1);
  sm4_bs_unpack_word_slices(s0, y0);

  for (unsigned int lane = 0; lane < SM4_BITSLICE_LANES; ++lane) {
    sm4_uint32_to_bytes(y3[lane], out_blocks[lane] + 0);
    sm4_uint32_to_bytes(y2[lane], out_blocks[lane] + 4);
    sm4_uint32_to_bytes(y1[lane], out_blocks[lane] + 8);
    sm4_uint32_to_bytes(y0[lane], out_blocks[lane] + 12);
  }
}

static void sm4_prg_bitsliced(const sm4_round_keys_t* rk, uint8_t* iv, uint8_t* out, size_t outlen) {
  while ((outlen / SM4_BLOCK_SIZE) >= SM4_BITSLICE_MIN_BATCH) {
    const size_t batch_blocks = (outlen / SM4_BLOCK_SIZE) >= SM4_BITSLICE_LANES
                                    ? SM4_BITSLICE_LANES
                                    : (outlen / SM4_BLOCK_SIZE);
    uint8_t in_blocks[SM4_BITSLICE_LANES][SM4_BLOCK_SIZE];
    uint8_t out_blocks[SM4_BITSLICE_LANES][SM4_BLOCK_SIZE];
    uint8_t ctr[SM4_BLOCK_SIZE];

    memcpy(ctr, iv, SM4_BLOCK_SIZE);

    for (unsigned int lane = 0; lane < SM4_BITSLICE_LANES; ++lane) {
      memcpy(in_blocks[lane], ctr, SM4_BLOCK_SIZE);
      sm4_increment_iv(ctr);
    }

    sm4_encrypt_8blocks_bitslice(rk, (const uint8_t(*)[SM4_BLOCK_SIZE])in_blocks, out_blocks);

    for (size_t lane = 0; lane < batch_blocks; ++lane) {
      memcpy(out + lane * SM4_BLOCK_SIZE, out_blocks[lane], SM4_BLOCK_SIZE);
    }

    for (size_t lane = 0; lane < batch_blocks; ++lane) {
      sm4_increment_iv(iv);
    }

    out += batch_blocks * SM4_BLOCK_SIZE;
    outlen -= batch_blocks * SM4_BLOCK_SIZE;
  }

  while (outlen >= SM4_BLOCK_SIZE) {
    sm4_encrypt_block(rk, iv, out);
    sm4_increment_iv(iv);
    out += SM4_BLOCK_SIZE;
    outlen -= SM4_BLOCK_SIZE;
  }

  if (outlen != 0) {
    uint8_t last_block[SM4_BLOCK_SIZE];
    sm4_encrypt_block(rk, iv, last_block);
    memcpy(out, last_block, outlen);
    faest_explicit_bzero(last_block, sizeof(last_block));
  }
}

// ============ 密钥扩展算法 ============
void sm4_init_round_keys(sm4_round_keys_t* rk, const uint8_t* key) {
  uint32_t K[36]; // K[0..3] 中间密钥, K[4..35] = rk[0..31]
  
  // MK 转换为 K[0..3]
  for (int i = 0; i < 4; i++) {
    K[i] = sm4_bytes_to_uint32(key + 4 * i) ^ FK[i];
  }
  
  // 生成32轮轮密钥
  for (int i = 0; i < 32; i++) {
    K[i + 4] = K[i] ^ sm4_t_prime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
    rk->round_keys[i] = K[i + 4];
  }
}

// ============ SM4 加密算法 ============
void sm4_encrypt_block(const sm4_round_keys_t* rk, const uint8_t* plaintext,
                       uint8_t* ciphertext) {
  uint32_t X[36]; // X[0..3] 输入, X[4..35] 中间状态
  
  // 加载明文
  for (int i = 0; i < 4; i++) {
    X[i] = sm4_bytes_to_uint32(plaintext + 4 * i);
  }
  
  // 32轮迭代: X[i+4] = X[i] ⊕ T(X[i+1] ⊕ X[i+2] ⊕ X[i+3] ⊕ rk[i])
  for (int i = 0; i < 32; i++) {
    X[i + 4] = X[i] ^ sm4_t(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk->round_keys[i]);
  }
  
  // 反序变换输出: (X[35], X[34], X[33], X[32])
  for (int i = 0; i < 4; i++) {
    sm4_uint32_to_bytes(X[35 - i], ciphertext + 4 * i);
  }
}

// ============ IV 递增（用于 CTR 模式）============
#if defined(FAEST_TESTS)
void sm4_increment_iv(uint8_t* iv)
#else
static inline void sm4_increment_iv(uint8_t* iv)
#endif
{
    /* increment low‑order 32‑bit word only; carry is truncated at 4 bytes.
     this matches both the SM4 and PRG_SM4 unit tests. */
  uint32_t counter;
  memcpy(&counter, iv, sizeof(counter));
  counter = htole32(le32toh(counter) + 1);
  memcpy(iv, &counter, sizeof(counter));
}

// ============ PRG 实现（SM4-CTR 模式）============

// 辅助函数：将 tweak 加到 IV 的高位字上
static inline void add_to_upper_word(uint8_t* iv, uint32_t tweak) {
  uint32_t iv0;
  memcpy(&iv0, iv + 12, sizeof(uint32_t));
  iv0 = htole32(le32toh(iv0) + tweak);
  memcpy(iv + 12, &iv0, sizeof(uint32_t));
}

// SM4-CTR 模式的 PRG 实现
void sm4_prg(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
             unsigned int bits, size_t outlen) {
  assert(bits == 128 && "sm4_prg: only 128-bit lambda is supported");
  (void)bits;
  
  // 初始化轮密钥
  sm4_round_keys_t rk;
  sm4_init_round_keys(&rk, key);
  
  // 准备内部 IV（加上 tweak）
  uint8_t internal_iv[SM4_BLOCK_SIZE];
  memcpy(internal_iv, iv, SM4_BLOCK_SIZE);
  add_to_upper_word(internal_iv, tweak);

#if defined(__x86_64__) || defined(_M_X64)
#if FAEST_SM4_ALLOW_TTABLE
  /* T-table + multi-block parallel CTR path */
  sm4_prg_ttable(rk.round_keys, internal_iv, out, outlen);
  faest_explicit_bzero(&rk, sizeof(rk));
  faest_explicit_bzero(internal_iv, sizeof(internal_iv));
  return;
#endif
#endif

  sm4_prg_bitsliced(&rk, internal_iv, out, outlen);

  faest_explicit_bzero(&rk, sizeof(rk));
  faest_explicit_bzero(internal_iv, sizeof(internal_iv));
}

void sm4_prg_2_lambda(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
                      unsigned int bits) {
  const unsigned int lambda_bytes = bits / 8;

  sm4_prg(key, iv, tweak, out, bits, 2 * lambda_bytes);
}

void sm4_prg_4_lambda(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
                      unsigned int bits) {
  const unsigned int lambda_bytes = bits / 8;

  sm4_prg(key, iv, tweak, out, bits, 4 * lambda_bytes);
}

// ============ 辅助函数：逆仿射（用于见证）============
static inline uint8_t sm4_rotl8(uint8_t v, unsigned int n) {
  return (uint8_t)((v << n) | (v >> (8 - n)));
}

static inline uint8_t sm4_inverse_affine(uint8_t sbox_out) {
  uint8_t y = sbox_out ^ 0xD6;  // 0xD6 是 SM4 仿射常数 C
  return (uint8_t)(sm4_rotl8(y, 7) ^ sm4_rotl8(y, 5) ^ sm4_rotl8(y, 1));
}

/**
 * SM4 GF(2^4) 逆范数（仅用于 ZK 约束见证）
 * 计算 x^238 = x^(-17) in SM4 GF(2^8)，并提取位 (0,2,4,5) 得到4位值
 * 这是 GF(2^4)/GF(2) 的多项式基坐标表示，对应基 {1, β, β², β³} (β=0x0c)
 */
uint8_t sm4_invnorm(uint8_t x) {
  // 238 = 0b11101110: compute x^238 using square-and-multiply in SM4 GF(2^8)
  uint8_t y = bf8_square_sm4(x);        // x^2
  x         = bf8_square_sm4(y);        // x^4
  y         = bf8_mul_sm4(x, y);        // x^6
  x         = bf8_square_sm4(x);        // x^8
  y         = bf8_mul_sm4(x, y);        // x^14
  x         = bf8_square_sm4(x);        // x^16
  x         = bf8_square_sm4(x);        // x^32
  y         = bf8_mul_sm4(x, y);        // x^46
  x         = bf8_square_sm4(x);        // x^64
  y         = bf8_mul_sm4(x, y);        // x^110
  x         = bf8_square_sm4(x);        // x^128
  x         = bf8_mul_sm4(x, y);        // x^238
  // Extract bits at positions (0, 2, 4, 5) → output bits (0, 1, 2, 3)
  // Basis: bit0→coeff of 1, bit1→coeff of β=0x0c, bit2→coeff of β²=0x50, bit3→coeff of β³=0x2a
  return set_bit(get_bit(x, 0), 0) ^ set_bit(get_bit(x, 2), 1) ^
         set_bit(get_bit(x, 4), 2) ^ set_bit(get_bit(x, 5), 3);
}

// ============ 扩展见证（ZK 证明用）============
void sm4_extend_witness(uint8_t* w, const uint8_t* key, const uint8_t* in,
                        const faest_paramset_t* params) {
  const bool is_em = (params->Ske == 0); // 检查是否为 EM 模式
#if !defined(NDEBUG)
  uint8_t* const w_out = w;
#endif


  const uint8_t* actual_key = key;
  const uint8_t* actual_in  = in;

  
  // EM 模式：交换 key 和 input
  if (is_em) {
    const uint8_t* tmp = actual_key;
    actual_key         = actual_in;
    actual_in          = tmp;
  }
  
  // 步骤 1: 生成轮密钥
  sm4_round_keys_t rk;
  sm4_init_round_keys(&rk, actual_key);

  // 维护 K[0..35]（用于生成 τ(X) 以写入正确的 inv_norm）
  uint32_t K[SM4_ROUNDS + 4];
  for (unsigned int i = 0; i < 4; ++i) {
    K[i] = sm4_bytes_to_uint32(actual_key + 4 * i) ^ FK[i];
  }
  for (unsigned int round = 0; round < SM4_ROUNDS; ++round) {
    K[round + 4] = rk.round_keys[round];
  }
  
  // 步骤 2: 记录密钥扩展见证（标准模式需要，EM 模式跳过）
  if (!is_em) {
    const unsigned int nk = params->lambda / 32; // SM4-128: nk = 4
    // 记录初始密钥（nk 个字），使用 K[0..3] = MK ^ FK
    for (unsigned int i = 0; i != nk; ++i) {
      sm4_uint32_to_bytes(K[i], w);
      w += 4;
    }
    
    // 记录全部 32 轮密钥 K[4..35]
    for (unsigned int round = 0; round < SM4_ROUNDS; ++round) {
      sm4_uint32_to_bytes(rk.round_keys[round], w);
      w += 4;
    }

    // 记录密钥扩展 S-box 逆元（显式 squared_state 方案）:
    //   round % 4 == 0 →
    //      2 字节 invnorm nibble + 4 字节 x^2 + 4 字节 x^16
    //   round % 4 != 0 → 4 个 full-8bit 原始逆元，每个 1 字节
    for (unsigned int round = 0; round < SM4_ROUNDS; ++round) {
      uint32_t x = K[round + 1] ^ K[round + 2] ^ K[round + 3] ^ CK[round];
      uint8_t x_bytes[4];
      sm4_uint32_to_bytes(x, x_bytes);

      if (round % 4 == 0) {
        // invnorm 轮：打包 4 个 4-bit nibble 进 2 字节
        // w[0] = (nibble[1] << 4) | nibble[0]
        // w[1] = (nibble[3] << 4) | nibble[2]
        uint8_t n0 = sm4_invnorm(x_bytes[0]);
        uint8_t n1 = sm4_invnorm(x_bytes[1]);
        uint8_t n2 = sm4_invnorm(x_bytes[2]);
        uint8_t n3 = sm4_invnorm(x_bytes[3]);
        *w++ = (uint8_t)((n1 << 4) | (n0 & 0xF));
        *w++ = (uint8_t)((n3 << 4) | (n2 & 0xF));

        // 显式 squared_state: x^2（4 bytes）
        for (unsigned int j = 0; j < 4; ++j) {
          *w++ = bf8_square_sm4(x_bytes[j]);
        }

        // 显式 squared_state: x^16（4 bytes）
        for (unsigned int j = 0; j < 4; ++j) {
          uint8_t x16 = x_bytes[j];
          for (unsigned int k = 0; k < 4; ++k) {
            x16 = bf8_square_sm4(x16);
          }
          *w++ = x16;
        }
      } else {
        // full-8bit 轮：4 字节原始逆元
        for (unsigned int j = 0; j < 4; j++) {
          *w++ = sm4_inverse_affine(sm4_sbox(x_bytes[j]));
        }
      }
    }
  } else {
    const unsigned int lambda_bytes = params->lambda / 8;
    
    // EM 模式：保存 OWF key 到扩展见证
    memcpy(w, actual_in, lambda_bytes);
    w += lambda_bytes;
  }
  
#if !defined(NDEBUG)
  assert(w - w_out == params->Lke / 8);
#endif
  
  // 步骤 3: 记录加密过程中间状态（显式 squared_state 方案）:
  //   quad q (4轮一组), round = q*4 + r_in_quad (r_in_quad = 0,1,2,3)
  //   r_in_quad == 0: invnorm 轮，2字节 nibble + 4字节 x^2 + 4字节 x^16
  //   r_in_quad == 1,2,3: full-8bit 轮，4字节原始逆元
  //   quad_bytes = 22，共 8 个 quad = 176 字节 = 1408 bits
  uint32_t state[4];
  for (int i = 0; i < 4; i++) {
    state[i] = sm4_bytes_to_uint32(actual_in + 4 * i);
  }

  for (unsigned int round = 1; round <= params->R; round++) {
    uint32_t temp = state[1] ^ state[2] ^ state[3] ^ rk.round_keys[round - 1];
    uint8_t temp_bytes[4];
    sm4_uint32_to_bytes(temp, temp_bytes);

    const unsigned int r0 = round - 1;  // 0-indexed round
    if (r0 % 4 == 0) {
      // invnorm 轮：打包 4 个 nibble 进 2 字节
      uint8_t n0 = sm4_invnorm(temp_bytes[0]);
      uint8_t n1 = sm4_invnorm(temp_bytes[1]);
      uint8_t n2 = sm4_invnorm(temp_bytes[2]);
      uint8_t n3 = sm4_invnorm(temp_bytes[3]);
      *w++ = (uint8_t)((n1 << 4) | (n0 & 0xF));
      *w++ = (uint8_t)((n3 << 4) | (n2 & 0xF));

      // 显式 squared_state: x^2（4 bytes）
      for (unsigned int j = 0; j < 4; ++j) {
        *w++ = bf8_square_sm4(temp_bytes[j]);
      }

      // 显式 squared_state: x^16（4 bytes）
      for (unsigned int j = 0; j < 4; ++j) {
        uint8_t x16 = temp_bytes[j];
        for (unsigned int k = 0; k < 4; ++k) {
          x16 = bf8_square_sm4(x16);
        }
        *w++ = x16;
      }
    } else {
      // full-8bit 轮：4字节原始逆元
      for (int j = 0; j < 4; j++) {
        *w++ = sm4_inverse_affine(sm4_sbox(temp_bytes[j]));
      }
    }

    if (round < params->R) {
      uint32_t new_word = state[0] ^ sm4_t(temp);
      state[0] = state[1];
      state[1] = state[2];
      state[2] = state[3];
      state[3] = new_word;
    }
  }

  assert(w - w_out == params->l / 8);
}
