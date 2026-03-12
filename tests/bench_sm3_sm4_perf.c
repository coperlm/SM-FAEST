/*
 *  SPDX-License-Identifier: MIT
 *
 *  Comprehensive benchmark for SM3/SM4 vs SHAKE/AES performance profiling.
 *  Designed to be profiled with:
 *    perf record -g ./tests/bench_sm3_sm4_perf
 *    perf report
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include "sm4.h"
#include "aes.h"
#include "sm_random_oracle.h"
#include "random_oracle.h"
#include "instances.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>

/* ---- portable high-resolution timer ---- */
static inline double get_time_sec(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* ---- configuration ---- */
#define WARMUP_ITERS    200
#define BENCH_ITERS     10000

static const uint8_t test_key[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};
static const uint8_t test_iv[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};
static const uint8_t test_data[256] = {0};  /* zero-filled input data */

/* ==========================================================================
 * Section 1: SM4-PRG vs AES-PRG
 * ========================================================================== */
static void bench_prg(void) {
  uint8_t out[1024];
  double t0, t1;
  int i;

  printf("[PRG] SM4 vs AES — 1024 bytes (64 blocks)\n");

  for (i = 0; i < WARMUP_ITERS; i++)
    sm4_prg(test_key, test_iv, (uint32_t)i, out, 128, 1024);
  t0 = get_time_sec();
  for (i = 0; i < BENCH_ITERS; i++)
    sm4_prg(test_key, test_iv, (uint32_t)i, out, 128, 1024);
  t1 = get_time_sec();
  printf("  SM4-PRG:  %8.2f ms  %10.0f ops/s  %8.2f MB/s\n",
         (t1-t0)*1000, BENCH_ITERS/(t1-t0), 1024.0*BENCH_ITERS/(t1-t0)/1e6);

  for (i = 0; i < WARMUP_ITERS; i++)
    prg(test_key, test_iv, (uint32_t)i, out, 128, 1024);
  t0 = get_time_sec();
  for (i = 0; i < BENCH_ITERS; i++)
    prg(test_key, test_iv, (uint32_t)i, out, 128, 1024);
  t1 = get_time_sec();
  printf("  AES-PRG:  %8.2f ms  %10.0f ops/s  %8.2f MB/s\n",
         (t1-t0)*1000, BENCH_ITERS/(t1-t0), 1024.0*BENCH_ITERS/(t1-t0)/1e6);
}

static void bench_prg_4lambda(void) {
  uint8_t out[64];
  double t0, t1;
  int i;

  printf("[PRG-4λ] SM4 vs AES — 64 bytes (4 blocks)\n");

  for (i = 0; i < WARMUP_ITERS; i++)
    sm4_prg_4_lambda(test_key, test_iv, (uint32_t)i, out, 128);
  t0 = get_time_sec();
  for (i = 0; i < BENCH_ITERS; i++)
    sm4_prg_4_lambda(test_key, test_iv, (uint32_t)i, out, 128);
  t1 = get_time_sec();
  printf("  SM4-4λ:   %8.2f ms  %10.0f ops/s\n", (t1-t0)*1000, BENCH_ITERS/(t1-t0));

  for (i = 0; i < WARMUP_ITERS; i++)
    prg_4_lambda(test_key, test_iv, (uint32_t)i, out, 128);
  t0 = get_time_sec();
  for (i = 0; i < BENCH_ITERS; i++)
    prg_4_lambda(test_key, test_iv, (uint32_t)i, out, 128);
  t1 = get_time_sec();
  printf("  AES-4λ:   %8.2f ms  %10.0f ops/s\n", (t1-t0)*1000, BENCH_ITERS/(t1-t0));
}

/* ==========================================================================
 * Section 2: SM3-XOF vs SHAKE — random oracle operations
 * ========================================================================== */

/* H0: streaming XOF — squeeze 1KB from a seeded context */
static void bench_h0_squeeze(void) {
  uint8_t out[1024];
  double t0, t1;
  int i;

  printf("[H0 squeeze] SM3 vs SHAKE — squeeze 1024 bytes\n");

  /* SM3 path */
  SM_H0_context_t sm_ctx;
  for (i = 0; i < WARMUP_ITERS; i++) {
    SM_H0_init(&sm_ctx, 128);
    SM_H0_update(&sm_ctx, test_key, 16);
    SM_H0_final_for_squeeze(&sm_ctx);
    SM_H0_squeeze(&sm_ctx, out, 1024);
    SM_H0_clear(&sm_ctx);
  }
  t0 = get_time_sec();
  for (i = 0; i < BENCH_ITERS; i++) {
    SM_H0_init(&sm_ctx, 128);
    SM_H0_update(&sm_ctx, test_key, 16);
    SM_H0_final_for_squeeze(&sm_ctx);
    SM_H0_squeeze(&sm_ctx, out, 1024);
    SM_H0_clear(&sm_ctx);
  }
  t1 = get_time_sec();
  printf("  SM3-H0:   %8.2f ms  %10.0f ops/s  %8.2f MB/s\n",
         (t1-t0)*1000, BENCH_ITERS/(t1-t0), 1024.0*BENCH_ITERS/(t1-t0)/1e6);

  /* SHAKE path */
  H0_context_t ctx;
  for (i = 0; i < WARMUP_ITERS; i++) {
    H0_init(&ctx, 128);
    H0_update(&ctx, test_key, 16);
    H0_final_for_squeeze(&ctx);
    H0_squeeze(&ctx, out, 1024);
    H0_clear(&ctx);
  }
  t0 = get_time_sec();
  for (i = 0; i < BENCH_ITERS; i++) {
    H0_init(&ctx, 128);
    H0_update(&ctx, test_key, 16);
    H0_final_for_squeeze(&ctx);
    H0_squeeze(&ctx, out, 1024);
    H0_clear(&ctx);
  }
  t1 = get_time_sec();
  printf("  SHAKE-H0: %8.2f ms  %10.0f ops/s  %8.2f MB/s\n",
         (t1-t0)*1000, BENCH_ITERS/(t1-t0), 1024.0*BENCH_ITERS/(t1-t0)/1e6);
}

/* H1: one-shot hash — hash 128 bytes, produce 32 */
static void bench_h1(void) {
  uint8_t out[32];
  double t0, t1;
  int i;

  printf("[H1 one-shot] SM3 vs SHAKE — hash 128B → 32B\n");

  /* SM3 */
  SM_H1_context_t sm_ctx;
  for (i = 0; i < WARMUP_ITERS; i++) {
    SM_H1_init(&sm_ctx, 128);
    SM_H1_update(&sm_ctx, test_data, 128);
    SM_H1_final(&sm_ctx, out, 32);
  }
  t0 = get_time_sec();
  for (i = 0; i < BENCH_ITERS; i++) {
    SM_H1_init(&sm_ctx, 128);
    SM_H1_update(&sm_ctx, test_data, 128);
    SM_H1_final(&sm_ctx, out, 32);
  }
  t1 = get_time_sec();
  printf("  SM3-H1:   %8.2f ms  %10.0f ops/s\n", (t1-t0)*1000, BENCH_ITERS/(t1-t0));

  /* SHAKE */
  H1_context_t ctx;
  for (i = 0; i < WARMUP_ITERS; i++) {
    H1_init(&ctx, 128);
    H1_update(&ctx, test_data, 128);
    H1_final(&ctx, out, 32);
  }
  t0 = get_time_sec();
  for (i = 0; i < BENCH_ITERS; i++) {
    H1_init(&ctx, 128);
    H1_update(&ctx, test_data, 128);
    H1_final(&ctx, out, 32);
  }
  t1 = get_time_sec();
  printf("  SHAKE-H1: %8.2f ms  %10.0f ops/s\n", (t1-t0)*1000, BENCH_ITERS/(t1-t0));
}

/* H2: challenge derivation — absorb 256B, squeeze 64B (typical chall size) */
static void bench_h2(void) {
  uint8_t out[64];
  double t0, t1;
  int i;

  printf("[H2 challenge] SM3 vs SHAKE — 256B input → 64B challenge\n");

  /* SM3 */
  SM_H2_context_t sm_ctx;
  for (i = 0; i < WARMUP_ITERS; i++) {
    SM_H2_0_init(&sm_ctx, 128);
    SM_H2_update(&sm_ctx, test_data, 256);
    SM_H2_final(&sm_ctx, out, 64);
  }
  t0 = get_time_sec();
  for (i = 0; i < BENCH_ITERS; i++) {
    SM_H2_0_init(&sm_ctx, 128);
    SM_H2_update(&sm_ctx, test_data, 256);
    SM_H2_final(&sm_ctx, out, 64);
  }
  t1 = get_time_sec();
  printf("  SM3-H2:   %8.2f ms  %10.0f ops/s\n", (t1-t0)*1000, BENCH_ITERS/(t1-t0));

  /* SHAKE */
  H2_context_t ctx;
  for (i = 0; i < WARMUP_ITERS; i++) {
    H2_init(&ctx, 128);
    H2_update(&ctx, test_data, 256);
    H2_0_final(&ctx, out, 64);
  }
  t0 = get_time_sec();
  for (i = 0; i < BENCH_ITERS; i++) {
    H2_init(&ctx, 128);
    H2_update(&ctx, test_data, 256);
    H2_0_final(&ctx, out, 64);
  }
  t1 = get_time_sec();
  printf("  SHAKE-H2: %8.2f ms  %10.0f ops/s\n", (t1-t0)*1000, BENCH_ITERS/(t1-t0));
}

/* Pure SM3 compress throughput */
static void bench_sm3_compress(void) {
  uint32_t digest[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
  };
  uint8_t block[64];
  memset(block, 0x42, 64);
  double t0, t1;
  int i;

  printf("[SM3 compress] Raw compression throughput\n");

  for (i = 0; i < WARMUP_ITERS * 10; i++)
    sm3_compress_blocks(digest, block, 1);
  t0 = get_time_sec();
  int niters = BENCH_ITERS * 10;
  for (i = 0; i < niters; i++)
    sm3_compress_blocks(digest, block, 1);
  t1 = get_time_sec();
  printf("  SM3 compress:  %8.2f ms  %10.0f blocks/s  %8.2f MB/s\n",
         (t1-t0)*1000, niters/(t1-t0), 64.0*niters/(t1-t0)/1e6);
}

/* ==========================================================================
 * Section 3: Full sign/verify simulation (most realistic benchmark)
 * ========================================================================== */
static void bench_sign_sm4(void) {
  /* Use the C2 bench approach: generate a keypair, then sign many times */
  printf("[Sign] FAEST_SM4_128S — full sign operation\n");

  /* This section just exercises the PRG + hash paths together */
  uint8_t prg_out[1024], h0_out[512];
  SM_H0_context_t hctx;
  double t0, t1;
  int i;

  for (i = 0; i < WARMUP_ITERS; i++) {
    sm4_prg(test_key, test_iv, (uint32_t)i, prg_out, 128, 1024);
    SM_H0_init(&hctx, 128);
    SM_H0_update(&hctx, prg_out, 1024);
    SM_H0_final_for_squeeze(&hctx);
    SM_H0_squeeze(&hctx, h0_out, 512);
    SM_H0_clear(&hctx);
  }
  t0 = get_time_sec();
  for (i = 0; i < BENCH_ITERS; i++) {
    sm4_prg(test_key, test_iv, (uint32_t)i, prg_out, 128, 1024);
    SM_H0_init(&hctx, 128);
    SM_H0_update(&hctx, prg_out, 1024);
    SM_H0_final_for_squeeze(&hctx);
    SM_H0_squeeze(&hctx, h0_out, 512);
    SM_H0_clear(&hctx);
  }
  t1 = get_time_sec();
  printf("  SM4-PRG+SM3-H0 pipeline: %8.2f ms  %10.0f ops/s\n",
         (t1-t0)*1000, BENCH_ITERS/(t1-t0));

  /* AES equivalent */
  H0_context_t actx;
  for (i = 0; i < WARMUP_ITERS; i++) {
    prg(test_key, test_iv, (uint32_t)i, prg_out, 128, 1024);
    H0_init(&actx, 128);
    H0_update(&actx, prg_out, 1024);
    H0_final_for_squeeze(&actx);
    H0_squeeze(&actx, h0_out, 512);
    H0_clear(&actx);
  }
  t0 = get_time_sec();
  for (i = 0; i < BENCH_ITERS; i++) {
    prg(test_key, test_iv, (uint32_t)i, prg_out, 128, 1024);
    H0_init(&actx, 128);
    H0_update(&actx, prg_out, 1024);
    H0_final_for_squeeze(&actx);
    H0_squeeze(&actx, h0_out, 512);
    H0_clear(&actx);
  }
  t1 = get_time_sec();
  printf("  AES-PRG+SHAKE-H0 pipeline: %8.2f ms  %10.0f ops/s\n",
         (t1-t0)*1000, BENCH_ITERS/(t1-t0));
}

int main(void) {
  printf("====== FAEST SM4/SM3 vs AES/SHAKE Performance Profile ======\n\n");

  bench_prg();
  printf("\n");
  bench_prg_4lambda();
  printf("\n");
  bench_h0_squeeze();
  printf("\n");
  bench_h1();
  printf("\n");
  bench_h2();
  printf("\n");
  bench_sm3_compress();
  printf("\n");
  bench_sign_sm4();

  printf("\n====== Done ======\n");
  return 0;
}
