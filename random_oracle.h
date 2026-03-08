/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef FAEST_RANDOM_ORACLE_H
#define FAEST_RANDOM_ORACLE_H

#include "hash_shake.h"
#include "macros.h"

FAEST_BEGIN_C_DECL

// implementation of H_0

typedef hash_context H0_context_t;

void H0_init(H0_context_t* H0_ctx, unsigned int security_param);
void H0_update(H0_context_t* H0_ctx, const uint8_t* src, size_t len);
void H0_final(H0_context_t* H0_ctx, uint8_t* seed, size_t seed_len, uint8_t* commitment,
              size_t commitment_len);
void H0_final_for_squeeze(H0_context_t* H0_ctx);
// only for use with H0_final_for_squeeze
void H0_squeeze(H0_context_t* H0_ctx, uint8_t* dst, size_t len);
void H0_clear(H0_context_t* H0_ctx);

typedef hash_context_x4 H0_context_x4_t;

void H0_x4_init(H0_context_x4_t* H0_ctx, unsigned int security_param);
void H0_x4_update(H0_context_x4_t* H0_ctx, const uint8_t* src0, const uint8_t* src1,
                  const uint8_t* src2, const uint8_t* src3, size_t len);
void H0_x4_final(H0_context_x4_t* ctx, uint8_t* seed0, uint8_t* seed1, uint8_t* seed2,
                 uint8_t* seed3, size_t seed_len, uint8_t* commitment0, uint8_t* commitment1,
                 uint8_t* commitment2, uint8_t* commitment3, size_t commitment_len);

// implementation of H_1

typedef hash_context H1_context_t;

void H1_init(H1_context_t* H1_ctx, unsigned int security_param);
void H1_update(H1_context_t* H1_ctx, const uint8_t* src, size_t len);
void H1_final(H1_context_t* H1_ctx, uint8_t* digest, size_t len);

// implementation of H_2

typedef hash_context H2_context_t;

void H2_init(H2_context_t* ctx, unsigned int security_param);
void H2_copy(H2_context_t* new_ctx, const H2_context_t* ctx);
void H2_update(H2_context_t* ctx, const uint8_t* src, size_t len);
void H2_update_u32_le(H2_context_t* ctx, uint32_t v);
void H2_0_final(H2_context_t* ctx, uint8_t* digest, size_t len);
void H2_1_final(H2_context_t* ctx, uint8_t* digest, size_t len);
void H2_2_final(H2_context_t* ctx, uint8_t* digest, size_t len);
void H2_3_final(H2_context_t* ctx, uint8_t* digest, size_t len);

// implementation for H_3

typedef hash_context H3_context_t;

void H3_init(H3_context_t* ctx, unsigned int security_param);
void H3_update(H3_context_t* ctx, const uint8_t* src, size_t len);
void H3_final(H3_context_t* ctx, uint8_t* digest, size_t len, uint8_t* iv);

// implementation for H_4

typedef hash_context H4_context_t;

void H4_init(H4_context_t* ctx, unsigned int security_param);
void H4_update(H4_context_t* ctx, const uint8_t* pre_iv);
void H4_final(H4_context_t* ctx, uint8_t* iv);

FAEST_END_C_DECL

/* ---------------------------------------------------------------------------
 * SM3-based oracle implementations for SM4 parameter sets.
 *
 * Included here so that any translation unit which includes random_oracle.h
 * automatically gains access to SM_H0–SM_H4 and H2_uni_context_t without
 * needing an extra #include.  AES paths are unaffected — the SM3 symbols are
 * only ever referenced behind faest_is_sm4(params) guards.
 * --------------------------------------------------------------------------- */
#include "sm_random_oracle.h"

#include <stdbool.h>

FAEST_BEGIN_C_DECL

/*
 * H2_uni_context_t — polymorphic H2 context for the cross-call challenge flow.
 *
 * faest_impl.c maintains an H2 context across hash_challenge_2_init →
 * hash_challenge_2_update_v_tilde (×λ) → hash_challenge_2_finalize, and
 * similarly for challenge_3.  This union bundles both path contexts so that
 * the callers do not need to declare separate variables for each path.
 *
 * Invariant: the `is_sm4` flag is set by the _init function and must not be
 * modified afterwards.  H2_uni_clear() reads it to dispatch correctly.
 */
typedef struct {
  bool          is_sm4;   /* set at init; determines which union branch is live */
  union {
    H2_context_t    shake;  /* active when !is_sm4 — AES+SHAKE path             */
    SM_H2_context_t sm3;    /* active when  is_sm4 — SM4+SM3  path             */
  };
} H2_uni_context_t;

/*
 * H2_uni_clear — securely erase whichever branch of H2_uni_context_t is live.
 *
 * Must be called on any early-exit or error code-path to prevent the
 * base secret (SM3 path) or Keccak state (SHAKE path) from leaking.
 */
static inline void H2_uni_clear(H2_uni_context_t* ctx) {
  if (ctx->is_sm4) {
    sm3_xof_clear(&ctx->sm3);
  } else {
    hash_clear(&ctx->shake);
  }
}

FAEST_END_C_DECL

#endif
