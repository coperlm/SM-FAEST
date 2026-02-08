/*
 *  SPDX-License-Identifier: MIT
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include <assert.h>
#include <string.h>

#include "owf.h"
#include "aes.h"
#include "utils.h"

#if defined(HAVE_AESNI)
#include "cpu.h"
#include "aesni.h"

ATTR_TARGET_AESNI static void owf_128_aesni(const uint8_t* key, const uint8_t* input,
                                            uint8_t* output) {
  __m128i rk[AES_ROUNDS_128 + 1];
  aes128_expand_key_aesni(rk, key);

  __m128i m = _mm_xor_si128(_mm_loadu_si128((const __m128i_u*)input), rk[0]);
  for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
    m = _mm_aesenc_si128(m, rk[round]);
  }
  m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_128]);
  _mm_storeu_si128((__m128i_u*)output, m);
}

ATTR_TARGET_AESNI static void owf_em_128_aesni(const uint8_t* key, const uint8_t* input,
                                               uint8_t* output) {
  __m128i rk[AES_ROUNDS_128 + 1];
  aes128_expand_key_aesni(rk, input);

  __m128i mkey = _mm_loadu_si128((const __m128i_u*)key);
  __m128i m    = _mm_xor_si128(mkey, rk[0]);
  for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
    m = _mm_aesenc_si128(m, rk[round]);
  }
  m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_128]);
  m = _mm_xor_si128(m, mkey);
  _mm_storeu_si128((__m128i_u*)output, m);
}

#if defined(HAVE_AVX2)
ATTR_TARGET_AESNI_AVX2 static void owf_128_aesni_avx2(const uint8_t* key, const uint8_t* input,
                                                      uint8_t* output) {
  __m128i rk[AES_ROUNDS_128 + 1];
  aes128_expand_key_aesni_avx2(rk, key);

  __m128i m = _mm_xor_si128(_mm_loadu_si128((const __m128i_u*)input), rk[0]);
  for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
    m = _mm_aesenc_si128(m, rk[round]);
  }
  m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_128]);
  _mm_storeu_si128((__m128i_u*)output, m);
}

ATTR_TARGET_AESNI_AVX2 static void owf_em_128_aesni_avx2(const uint8_t* key, const uint8_t* input,
                                                         uint8_t* output) {
  __m128i rk[AES_ROUNDS_128 + 1];
  aes128_expand_key_aesni_avx2(rk, input);

  __m128i mkey = _mm_loadu_si128((const __m128i_u*)key);
  __m128i m    = _mm_xor_si128(mkey, rk[0]);
  for (unsigned int round = 1; round != AES_ROUNDS_128; ++round) {
    m = _mm_aesenc_si128(m, rk[round]);
  }
  m = _mm_aesenclast_si128(m, rk[AES_ROUNDS_128]);
  m = _mm_xor_si128(m, mkey);
  _mm_storeu_si128((__m128i_u*)output, m);
}
#endif
#endif

void owf_128(const uint8_t* key, const uint8_t* input, uint8_t* output) {
#if defined(HAVE_AESNI)
#if defined(HAVE_AVX2)
  if (CPU_SUPPORTS_AESNI_AVX2) {
    owf_128_aesni_avx2(key, input, output);
    return;
  }
#endif
  if (CPU_SUPPORTS_AESNI) {
    owf_128_aesni(key, input, output);
    return;
  }
#endif

  generic_aes_ecb_t ctx;
  int ret = generic_aes_ecb_new(&ctx, key, 128);
  assert(ret == 0);
  (void)ret;

  ret = generic_aes_ecb_encrypt(&ctx, output, input, 1);
  assert(ret == 0);
  (void)ret;

  generic_aes_ecb_free(&ctx);
}

void owf_em_128(const uint8_t* key, const uint8_t* input, uint8_t* output) {
#if defined(HAVE_AESNI)
#if defined(HAVE_AVX2)
  if (CPU_SUPPORTS_AESNI_AVX2) {
    owf_em_128_aesni_avx2(key, input, output);
    return;
  }
#endif
  if (CPU_SUPPORTS_AESNI) {
    owf_em_128_aesni(key, input, output);
    return;
  }
#endif

  // same as owf_128 with swapped keys and the additional xor
  owf_128(input, key, output);
  xor_u8_array(output, key, output, 16);
}


