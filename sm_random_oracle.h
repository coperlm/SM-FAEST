/*
 *  SPDX-License-Identifier: MIT
 *
 *  SM3-based implementations of the FAEST random oracles H0–H4.
 *  Used exclusively for SM4 parameter sets (faest_is_sm4(params) == true).
 *  AES parameter sets continue to use the SHAKE implementations in
 *  random_oracle.c — this file does not modify those paths.
 *
 *  Domain separation: each oracle uses a 2-byte prefix { 0x53, domain_byte }
 *  fed as the very first SM3 input, matching the byte assignments in
 *  random_oracle.c:
 *    H0  → 0x00    H1  → 0x01
 *    H2^0→ 0x08    H2^1→ 0x09    H2^2→ 0x0A    H2^3→ 0x0B
 *    H3  → 0x03    H4  → 0x04
 *
 *  NOTE: H2 has four sub-domains; to preserve prefix injection semantics the
 *  sub-domain is chosen at SM_H2_X_init time (not at finalization).  Each
 *  challenge function in faest_impl.c uses exactly one sub-domain per call,
 *  so the domain is fully determined at construction.
 */

#ifndef FAEST_SM_RANDOM_ORACLE_H
#define FAEST_SM_RANDOM_ORACLE_H

#include "hash_sm3.h"     /* sm3_xof_ctx_t, SM_SUITE_BYTE, helpers */
#include "macros.h"
#include "instances.h"    /* IV_SIZE */

#include <stddef.h>
#include <stdint.h>

FAEST_BEGIN_C_DECL

/* -------------------------------------------------------------------------
 * Context typedefs — all are thin aliases for sm3_xof_ctx_t.
 * Each oracle uses a unique 2-byte prefix at init so contexts are
 * logically incompatible even though the struct layout is identical.
 * ---------------------------------------------------------------------- */
typedef sm3_xof_ctx_t SM_H0_context_t;
typedef sm3_xof_ctx_t SM_H1_context_t;
typedef sm3_xof_ctx_t SM_H2_context_t;   /* sub-domain injected at _X_init */
typedef sm3_xof_ctx_t SM_H3_context_t;
typedef sm3_xof_ctx_t SM_H4_context_t;

/* =========================================================================
 * H0  —  seed/commitment XOF (streaming)
 *
 * Usage pattern:
 *   SM_H0_init → SM_H0_update → SM_H0_final_for_squeeze
 *   → SM_H0_squeeze (× N)
 *   → SM_H0_clear
 *
 * The base secret value lives in ctx->base after final_for_squeeze.
 * Call SM_H0_clear when the streaming session ends or on any error return.
 * ========================================================================= */
void SM_H0_init(SM_H0_context_t* ctx, unsigned int security_param);
void SM_H0_update(SM_H0_context_t* ctx, const uint8_t* src, size_t len);
void SM_H0_final_for_squeeze(SM_H0_context_t* ctx);
void SM_H0_squeeze(SM_H0_context_t* ctx, uint8_t* dst, size_t len);
void SM_H0_clear(SM_H0_context_t* ctx);

/* =========================================================================
 * H1  —  leaf commitment and fold hash (one-shot)
 * ========================================================================= */
void SM_H1_init(SM_H1_context_t* ctx, unsigned int security_param);
void SM_H1_update(SM_H1_context_t* ctx, const uint8_t* src, size_t len);
void SM_H1_final(SM_H1_context_t* ctx, uint8_t* digest, size_t len);

/* =========================================================================
 * H2  —  challenge derivation hash (sub-domain at init, one-shot or streaming)
 *
 * There are four sub-oracles.  The sub-domain is injected as the second byte
 * of the prefix at SM_H2_X_init time.  SM_H2_update / SM_H2_copy /
 * SM_H2_final are domain-agnostic — they operate on whichever sub-oracle
 * context was initialised.
 *
 * Sub-domain mapping (inherits FAEST's original domain_sep bytes):
 *   SM_H2_0_init  →  prefix { 0x53, 0x08 }  (μ binding / H2^0)
 *   SM_H2_1_init  →  prefix { 0x53, 0x09 }  (chall_1 / H2^1)
 *   SM_H2_2_init  →  prefix { 0x53, 0x0A }  (chall_2 / H2^2)
 *   SM_H2_3_init  →  prefix { 0x53, 0x0B }  (chall_3 / H2^3)
 * ========================================================================= */
void SM_H2_0_init(SM_H2_context_t* ctx, unsigned int security_param);
void SM_H2_1_init(SM_H2_context_t* ctx, unsigned int security_param);
void SM_H2_2_init(SM_H2_context_t* ctx, unsigned int security_param);
void SM_H2_3_init(SM_H2_context_t* ctx, unsigned int security_param);

void SM_H2_update(SM_H2_context_t* ctx, const uint8_t* src, size_t len);
void SM_H2_update_u32_le(SM_H2_context_t* ctx, uint32_t v);

/* Copy the context in absorb phase (before final).  Used by
 * hash_challenge_3_final to produce multiple chall_3 outputs cheaply.      */
void SM_H2_copy(SM_H2_context_t* dst, const SM_H2_context_t* src);

/* Finalize (Extract + Squeeze + clear).  Produces exactly `len` bytes.     */
void SM_H2_final(SM_H2_context_t* ctx, uint8_t* digest, size_t len);

/* =========================================================================
 * H3  —  root key + IV derivation (one-shot)
 * ========================================================================= */
void SM_H3_init(SM_H3_context_t* ctx, unsigned int security_param);
void SM_H3_update(SM_H3_context_t* ctx, const uint8_t* src, size_t len);
/* Outputs digest[0..len-1] then iv[0..IV_SIZE-1] in a single squeeze.      */
void SM_H3_final(SM_H3_context_t* ctx,
                 uint8_t* digest, size_t len,
                 uint8_t* iv);

/* =========================================================================
 * H4  —  IV re-derivation (one-shot)
 * ========================================================================= */
void SM_H4_init(SM_H4_context_t* ctx, unsigned int security_param);
void SM_H4_update(SM_H4_context_t* ctx, const uint8_t* pre_iv);
void SM_H4_final(SM_H4_context_t* ctx, uint8_t* iv);

FAEST_END_C_DECL

#endif /* FAEST_SM_RANDOM_ORACLE_H */
