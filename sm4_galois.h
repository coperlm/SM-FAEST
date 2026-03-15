/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef FAEST_SM4_GALOIS_H
#define FAEST_SM4_GALOIS_H

#include "fields.h"
#include "macros.h"

#include <stdint.h>

FAEST_BEGIN_C_DECL

typedef struct {
  uint8_t x2;
  uint8_t x4;
  uint8_t x8;
  uint8_t x16;
} sm4_galois_conjugates_t;

static inline uint8_t sm4_galois_squared_state(uint8_t x) {
  return bf8_square_sm4(x);
}

static inline void sm4_galois_conjugates(uint8_t x, sm4_galois_conjugates_t* out) {
  out->x2  = bf8_square_sm4(x);
  out->x4  = bf8_square_sm4(out->x2);
  out->x8  = bf8_square_sm4(out->x4);
  out->x16 = bf8_square_sm4(out->x8);
}

static inline uint8_t sm4_galois_field_trace(uint8_t x) {
  uint8_t t = x;
  uint8_t p = x;
  for (unsigned int i = 0; i < 7; ++i) {
    p = bf8_square_sm4(p);
    t ^= p;
  }
  uint8_t acc = 0;
  for (unsigned int i = 0; i < 8; ++i) {
    acc ^= (uint8_t)((t >> i) & 1u);
  }
  return (uint8_t)(acc & 1u);
}

static inline uint8_t sm4_galois_field_norm(uint8_t x) {
  sm4_galois_conjugates_t conj;
  sm4_galois_conjugates(x, &conj);
  return bf8_mul_sm4(x, conj.x16);
}

static inline uint8_t sm4_galois_invnorm_path(uint8_t x) {
  const uint8_t norm = sm4_galois_field_norm(x);
  if (norm == 0) {
    return 0;
  }
  return bf8_inv_sm4(norm);
}

FAEST_END_C_DECL

#endif
