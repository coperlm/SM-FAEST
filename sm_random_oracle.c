/*
 *  SPDX-License-Identifier: MIT
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include <string.h>

#include "sm_random_oracle.h"
#include "instances.h"

/* Domain separation bytes (identical values to random_oracle.c).
 * The 2-byte prefix { SM_SUITE_BYTE, sm_domain_Hx } is injected by
 * sm3_xof_init_with_prefix() at context-initialisation time, ensuring
 * prefix-based domain isolation on the Merkle-Damgård structure.       */
static const uint8_t sm_domain_H0   = 0x00;
static const uint8_t sm_domain_H1   = 0x01;
static const uint8_t sm_domain_H2_0 = 0x08;
static const uint8_t sm_domain_H2_1 = 0x09;
static const uint8_t sm_domain_H2_2 = 0x0A;
static const uint8_t sm_domain_H2_3 = 0x0B;
static const uint8_t sm_domain_H3   = 0x03;
static const uint8_t sm_domain_H4   = 0x04;

/* (security_param parameter is accepted for API symmetry with SHAKE oracles
 *  but is unused: SM3 has a fixed 256-bit capacity, so both 128- and 256-bit
 *  security levels use the same SM3 call.)                               */

/* =========================================================================
 * H0 — seed/commitment XOF (streaming)
 * ========================================================================= */

void SM_H0_init(SM_H0_context_t* ctx, unsigned int security_param) {
  (void)security_param;
  sm3_xof_init_with_prefix(ctx, sm_domain_H0);
}

void SM_H0_update(SM_H0_context_t* ctx, const uint8_t* src, size_t len) {
  sm3_xof_update(ctx, src, len);
}

void SM_H0_final_for_squeeze(SM_H0_context_t* ctx) {
  sm3_xof_finalize(ctx);  /* Extract: base = SM3(prefix || absorbed_data) */
}

void SM_H0_squeeze(SM_H0_context_t* ctx, uint8_t* dst, size_t len) {
  sm3_xof_squeeze(ctx, dst, len);
}

void SM_H0_clear(SM_H0_context_t* ctx) {
  /* Securely erase the base secret and all other fields.                  */
  sm3_xof_clear(ctx);
}

/* =========================================================================
 * H1 — leaf commitment and fold hash (one-shot)
 * ========================================================================= */

void SM_H1_init(SM_H1_context_t* ctx, unsigned int security_param) {
  (void)security_param;
  sm3_xof_init_with_prefix(ctx, sm_domain_H1);
}

void SM_H1_update(SM_H1_context_t* ctx, const uint8_t* src, size_t len) {
  sm3_xof_update(ctx, src, len);
}

void SM_H1_final(SM_H1_context_t* ctx, uint8_t* digest, size_t len) {
  sm3_xof_finalize(ctx);
  sm3_xof_squeeze(ctx, digest, len);
  sm3_xof_clear(ctx);
}

/* =========================================================================
 * H2 — challenge derivation (sub-domain injected at init)
 * ========================================================================= */

void SM_H2_0_init(SM_H2_context_t* ctx, unsigned int security_param) {
  (void)security_param;
  sm3_xof_init_with_prefix(ctx, sm_domain_H2_0);
}

void SM_H2_1_init(SM_H2_context_t* ctx, unsigned int security_param) {
  (void)security_param;
  sm3_xof_init_with_prefix(ctx, sm_domain_H2_1);
}

void SM_H2_2_init(SM_H2_context_t* ctx, unsigned int security_param) {
  (void)security_param;
  sm3_xof_init_with_prefix(ctx, sm_domain_H2_2);
}

void SM_H2_3_init(SM_H2_context_t* ctx, unsigned int security_param) {
  (void)security_param;
  sm3_xof_init_with_prefix(ctx, sm_domain_H2_3);
}

void SM_H2_update(SM_H2_context_t* ctx, const uint8_t* src, size_t len) {
  sm3_xof_update(ctx, src, len);
}

void SM_H2_update_u32_le(SM_H2_context_t* ctx, uint32_t v) {
  /* Encode v as little-endian uint32 (matching FAEST's H2_update_u32_le).  */
  uint8_t buf[4];
  buf[0] = (uint8_t)(v      );
  buf[1] = (uint8_t)(v >>  8);
  buf[2] = (uint8_t)(v >> 16);
  buf[3] = (uint8_t)(v >> 24);
  sm3_xof_update(ctx, buf, 4);
}

void SM_H2_copy(SM_H2_context_t* dst, const SM_H2_context_t* src) {
  /* Copy context in absorb phase (before finalize).  The SM3_CTX inside
   * sm3_xof_ctx_t is a plain value type: memcpy is correct and safe.     */
  memcpy(dst, src, sizeof(*src));
}

void SM_H2_final(SM_H2_context_t* ctx, uint8_t* digest, size_t len) {
  sm3_xof_finalize(ctx);
  sm3_xof_squeeze(ctx, digest, len);
  sm3_xof_clear(ctx);
}

/* =========================================================================
 * H3 — root key + IV derivation (one-shot, two sequential outputs)
 * ========================================================================= */

void SM_H3_init(SM_H3_context_t* ctx, unsigned int security_param) {
  (void)security_param;
  sm3_xof_init_with_prefix(ctx, sm_domain_H3);
}

void SM_H3_update(SM_H3_context_t* ctx, const uint8_t* src, size_t len) {
  sm3_xof_update(ctx, src, len);
}

void SM_H3_final(SM_H3_context_t* ctx,
                 uint8_t* digest, size_t digest_len,
                 uint8_t* iv) {
  /* Squeeze digest_len bytes for root_key, then IV_SIZE bytes for iv_pre.
   * Both are derived from the same Extract base, maintaining continuity
   * across the split — identical semantics to H3_final with SHAKE.       */
  sm3_xof_finalize(ctx);
  sm3_xof_squeeze(ctx, digest, digest_len);
  sm3_xof_squeeze(ctx, iv, IV_SIZE);
  sm3_xof_clear(ctx);
}

/* =========================================================================
 * H4 — IV re-derivation from iv_pre (one-shot)
 * ========================================================================= */

void SM_H4_init(SM_H4_context_t* ctx, unsigned int security_param) {
  (void)security_param;
  sm3_xof_init_with_prefix(ctx, sm_domain_H4);
}

void SM_H4_update(SM_H4_context_t* ctx, const uint8_t* pre_iv) {
  sm3_xof_update(ctx, pre_iv, IV_SIZE);
}

void SM_H4_final(SM_H4_context_t* ctx, uint8_t* iv) {
  sm3_xof_finalize(ctx);
  sm3_xof_squeeze(ctx, iv, IV_SIZE);
  sm3_xof_clear(ctx);
}
