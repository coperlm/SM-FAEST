/*
 *  SPDX-License-Identifier: MIT
 *
 *  SM3-based XOF (Extract-then-Expand KDF) for FAEST SM4 parameter sets.
 *
 *  Construction (two-phase, aligned with GM/T 0003.4-2012 and HKDF RFC 5869):
 *    Step 1 (Extract):  base = SM3( {SM_SUITE_BYTE, domain_sep} || inputs... )
 *    Step 2 (Expand):   Block_i = SM3( base || i_be32 ),  i = 1, 2, ...
 *    Output = Block_1 || Block_2 || ... [0..klen-1]
 *
 *  The 2-byte prefix { SM_SUITE_BYTE=0x53, domain_sep } provides:
 *    - Global isolation from SHAKE outputs (0x53 namespace tag)
 *    - Per-oracle domain separation (inheriting FAEST's original domain bytes)
 *    - Front-loaded prefix injection (safe on Merkle-Damgard structures)
 *
 *  Counter encoding: big-endian uint32 (portable byte-level, no htobe32 dep),
 *    starting from 1 (aligned with GM/T 0003.4-2012 §6.3).
 *
 *  Quantum security: in the QROM, the Extract step is a PRF on inputs; the
 *    Expand step produces independent random oracle queries, yielding 128-bit
 *    quantum security for SM4_128S (lambda = 128).
 */

#ifndef FAEST_HASH_SM3_H
#define FAEST_HASH_SM3_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "gmssl/sm3.h"
#include "compat.h"   /* faest_explicit_bzero */

#ifdef __cplusplus
extern "C" {
#endif

/* 32-byte SM3 digest output size */
#define SM3_XOF_BLOCK_SIZE  SM3_DIGEST_SIZE   /* 32 */

/*
 * SM suite namespace byte.
 * Ensures every SM3-path oracle output is globally domain-separated from
 * SHAKE-path outputs (they share no 2-byte prefix with any SHAKE token).
 * Value 0x53 = ASCII 'S' (mnemonic: SM/Shang Mi).
 */
#define SM_SUITE_BYTE  ((uint8_t)0x53u)

/*
 * sm3_xof_ctx_t — streaming XOF context.
 *
 * Lifecycle:
 *   1. sm3_xof_init_with_prefix()  — absorb phase begins (prefix injected)
 *   2. sm3_xof_update() × N        — feed arbitrary-length input
 *   3. sm3_xof_finalize()           — Extract: base = SM3(prefix || inputs)
 *   4. sm3_xof_squeeze() × M        — Expand: stream output bytes
 *   5. sm3_xof_clear()              — wipe all sensitive fields
 *
 * The `base` field (32 bytes) is the only persistent secret; it is zeroed by
 * sm3_xof_clear() via faest_explicit_bzero.
 */
typedef struct {
  SM3_CTX  absorb;       /* running SM3 state during absorb phase            */
  uint8_t  base[32];     /* Extract result = SM3(prefix || absorbed_data)    */
  uint32_t ctr;          /* Expand counter; starts at 1 (GM/T 0003.4-2012)  */
  uint8_t  blk[32];      /* Current Expand block buffer                      */
  uint8_t  blk_pos;      /* Cursor into blk[] (0-31); 32 = block exhausted  */
} sm3_xof_ctx_t;

/* ---------------------------------------------------------------------------
 * Internal helper: write uint32 in big-endian order (portable, no header dep)
 * --------------------------------------------------------------------------- */
static inline void sm3_xof_put_be32(uint8_t out[4], uint32_t v) {
  out[0] = (uint8_t)(v >> 24);
  out[1] = (uint8_t)(v >> 16);
  out[2] = (uint8_t)(v >>  8);
  out[3] = (uint8_t)(v      );
}

/* ---------------------------------------------------------------------------
 * sm3_xof_init_with_prefix
 *   Begin absorb phase.  Immediately feeds the 2-byte prefix
 *   { SM_SUITE_BYTE, domain_sep } as the very first input to SM3.
 *   This guarantees domain isolation even if all subsequent inputs are equal.
 * --------------------------------------------------------------------------- */
static inline void sm3_xof_init_with_prefix(sm3_xof_ctx_t* ctx,
                                             uint8_t        domain_sep) {
  const uint8_t prefix[2] = { SM_SUITE_BYTE, domain_sep };
  sm3_init(&ctx->absorb);
  sm3_update(&ctx->absorb, prefix, 2);
  memset(ctx->base,  0, 32);
  ctx->ctr     = 0;
  ctx->blk_pos = 32;       /* sentinel: no squeeze block yet */
  memset(ctx->blk, 0, 32);
}

/* ---------------------------------------------------------------------------
 * sm3_xof_update
 *   Feed arbitrary-length data into the absorb state.
 * --------------------------------------------------------------------------- */
static inline void sm3_xof_update(sm3_xof_ctx_t*  ctx,
                                   const uint8_t* data,
                                   size_t          len) {
  sm3_update(&ctx->absorb, data, len);
}

/* ---------------------------------------------------------------------------
 * sm3_xof_finalize
 *   Extract: compute base = SM3(prefix || absorbed_data).
 *   Transitions the context from absorb phase to squeeze phase.
 *   Must be called exactly once after all sm3_xof_update() calls.
 * --------------------------------------------------------------------------- */
static inline void sm3_xof_finalize(sm3_xof_ctx_t* ctx) {
  sm3_finish(&ctx->absorb, ctx->base);
  /* Clear absorb state now that base is computed */
  faest_explicit_bzero(&ctx->absorb, sizeof(ctx->absorb));
  ctx->ctr     = 1;
  ctx->blk_pos = 32;       /* trigger first Expand on next squeeze call */
}

/* ---------------------------------------------------------------------------
 * sm3_xof_squeeze
 *   Expand: produce 'len' output bytes.  May be called repeatedly.
 *   Each exhausted 32-byte block triggers a new Expand call:
 *     Block_i = SM3( base || i_be32 )
 * --------------------------------------------------------------------------- */
static inline void sm3_xof_squeeze(sm3_xof_ctx_t* ctx,
                                    uint8_t*       out,
                                    size_t         len) {
  /* Drain any remaining cached bytes first */
  if (ctx->blk_pos < 32) {
    size_t avail = 32 - ctx->blk_pos;
    size_t take  = avail < len ? avail : len;
    memcpy(out, ctx->blk + ctx->blk_pos, take);
    ctx->blk_pos = (uint8_t)(ctx->blk_pos + (uint8_t)take);
    out += take;
    len -= take;
  }

  /* Remainder: scalar, one block at a time */
  while (len > 0) {
    if (ctx->blk_pos >= 32) {
      SM3_CTX tmp;
      uint8_t ctr_bytes[4];
      sm3_xof_put_be32(ctr_bytes, ctx->ctr++);
      sm3_init(&tmp);
      sm3_update(&tmp, ctx->base, 32);
      sm3_update(&tmp, ctr_bytes, 4);
      sm3_finish(&tmp, ctx->blk);
      faest_explicit_bzero(&tmp, sizeof(tmp));
      ctx->blk_pos = 0;
    }
    size_t avail = (size_t)(32 - ctx->blk_pos);
    size_t take  = avail < len ? avail : len;
    memcpy(out, ctx->blk + ctx->blk_pos, take);
    ctx->blk_pos = (uint8_t)(ctx->blk_pos + (uint8_t)take);
    out += take;
    len -= take;
  }
}

/* ---------------------------------------------------------------------------
 * sm3_xof_clear
 *   Securely zero all fields, including the sensitive `base`.
 *   Must be called after the last squeeze, or on any error code-path.
 * --------------------------------------------------------------------------- */
static inline void sm3_xof_clear(sm3_xof_ctx_t* ctx) {
  faest_explicit_bzero(ctx, sizeof(*ctx));
}

/* ---------------------------------------------------------------------------
 * sm3_xof_one_shot
 *   Convenience: absorb a single data buffer and produce klen output bytes.
 *   The context is fully initialised, used, and cleared internally.
 * --------------------------------------------------------------------------- */
static inline void sm3_xof_one_shot(uint8_t        domain_sep,
                                     const uint8_t* data,
                                     size_t         dlen,
                                     uint8_t*       out,
                                     size_t         klen) {
  sm3_xof_ctx_t ctx;
  sm3_xof_init_with_prefix(&ctx, domain_sep);
  if (data && dlen) {
    sm3_xof_update(&ctx, data, dlen);
  }
  sm3_xof_finalize(&ctx);
  sm3_xof_squeeze(&ctx, out, klen);
  sm3_xof_clear(&ctx);
}

#ifdef __cplusplus
}
#endif

#endif /* FAEST_HASH_SM3_H */
