/*
 *  SPDX-License-Identifier: MIT
 *
 *  Micro-benchmark:  SM4-PRG  vs  AES-PRG  throughput comparison
 *  Compile:
 *    cc -O2 -march=native -DHAVE_CONFIG_H -I.. -I../build_release \
 *       bench_prg_compare.c ../sm4.c ../aes.c ../fields.c ../compat.c \
 *       ../utils.c ../cpu.c -o bench_prg_compare -lm
 *
 *  (or simply build with meson and run from build_release/)
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include "sm4.h"
#include "aes.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* ---- portable high-resolution timer ---- */
static inline double get_time_sec(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* ---- benchmark configuration ---- */
#define WARMUP_ITERS    100
#define BENCH_ITERS     5000
#define PRG_OUT_BYTES   1024   /* 64 blocks */

static const uint8_t test_key[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};

static const uint8_t test_iv[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

/* ---- run a benchmark ---- */
typedef void (*prg_fn_t)(const uint8_t* key, const uint8_t* iv,
                          uint32_t tweak, uint8_t* out,
                          unsigned int bits, size_t outlen);

static double bench_prg(prg_fn_t fn, unsigned int bits, size_t outlen,
                        int iters, const char* label) {
  uint8_t out[PRG_OUT_BYTES];
  /* warmup */
  for (int i = 0; i < WARMUP_ITERS; i++)
    fn(test_key, test_iv, (uint32_t)i, out, bits, outlen);

  double t0 = get_time_sec();
  for (int i = 0; i < iters; i++)
    fn(test_key, test_iv, (uint32_t)i, out, bits, outlen);
  double t1 = get_time_sec();

  double elapsed = t1 - t0;
  double ops = iters / elapsed;
  double mbps = (double)outlen * iters / elapsed / 1e6;
  printf("  %-28s  %8d iters  %8.2f ms  %10.0f ops/s  %8.2f MB/s\n",
         label, iters, elapsed * 1000.0, ops, mbps);
  return elapsed;
}

/* Wrapper for AES PRG to match sm4_prg signature */
static void aes_prg_wrapper(const uint8_t* key, const uint8_t* iv,
                            uint32_t tweak, uint8_t* out,
                            unsigned int bits, size_t outlen) {
  prg(key, iv, tweak, out, bits, outlen);
}

int main(void) {
  printf("=== PRG Throughput Benchmark: SM4 vs AES ===\n");
  printf("  Output size: %d bytes per call (%d blocks)\n\n",
         PRG_OUT_BYTES, PRG_OUT_BYTES / 16);

  /* --- 1. General PRG (variable length) --- */
  printf("[1] PRG %d bytes (full CTR loop)\n", PRG_OUT_BYTES);
  double t_sm4 = bench_prg(sm4_prg, 128, PRG_OUT_BYTES, BENCH_ITERS, "SM4-PRG (optimized)");
  double t_aes = bench_prg(aes_prg_wrapper, 128, PRG_OUT_BYTES, BENCH_ITERS, "AES-PRG (AES-NI)");
  printf("  -> SM4/AES ratio: %.2fx\n\n", t_sm4 / t_aes);

  /* --- 2. PRG 2*lambda (32 bytes = 2 blocks) --- */
  printf("[2] PRG 2*lambda (32 bytes, 2 blocks)\n");

  uint8_t sm4_out2[32], aes_out2[32];
  /* warmup */
  for (int i = 0; i < WARMUP_ITERS; i++) {
    sm4_prg_2_lambda(test_key, test_iv, (uint32_t)i, sm4_out2, 128);
    prg_2_lambda(test_key, test_iv, (uint32_t)i, aes_out2, 128);
  }

  double t0, t1;
  t0 = get_time_sec();
  for (int i = 0; i < BENCH_ITERS; i++)
    sm4_prg_2_lambda(test_key, test_iv, (uint32_t)i, sm4_out2, 128);
  t1 = get_time_sec();
  t_sm4 = t1 - t0;
  printf("  %-28s  %8d iters  %8.2f ms  %10.0f ops/s  %8.2f MB/s\n",
         "SM4-PRG-2λ", BENCH_ITERS, t_sm4 * 1000.0,
         BENCH_ITERS / t_sm4, 32.0 * BENCH_ITERS / t_sm4 / 1e6);

  t0 = get_time_sec();
  for (int i = 0; i < BENCH_ITERS; i++)
    prg_2_lambda(test_key, test_iv, (uint32_t)i, aes_out2, 128);
  t1 = get_time_sec();
  t_aes = t1 - t0;
  printf("  %-28s  %8d iters  %8.2f ms  %10.0f ops/s  %8.2f MB/s\n",
         "AES-PRG-2λ (AES-NI)", BENCH_ITERS, t_aes * 1000.0,
         BENCH_ITERS / t_aes, 32.0 * BENCH_ITERS / t_aes / 1e6);
  printf("  -> SM4/AES ratio: %.2fx\n\n", t_sm4 / t_aes);

  /* --- 3. PRG 4*lambda (64 bytes = 4 blocks) --- */
  printf("[3] PRG 4*lambda (64 bytes, 4 blocks)\n");

  uint8_t sm4_out4[64], aes_out4[64];
  for (int i = 0; i < WARMUP_ITERS; i++) {
    sm4_prg_4_lambda(test_key, test_iv, (uint32_t)i, sm4_out4, 128);
    prg_4_lambda(test_key, test_iv, (uint32_t)i, aes_out4, 128);
  }

  t0 = get_time_sec();
  for (int i = 0; i < BENCH_ITERS; i++)
    sm4_prg_4_lambda(test_key, test_iv, (uint32_t)i, sm4_out4, 128);
  t1 = get_time_sec();
  t_sm4 = t1 - t0;
  printf("  %-28s  %8d iters  %8.2f ms  %10.0f ops/s  %8.2f MB/s\n",
         "SM4-PRG-4λ", BENCH_ITERS, t_sm4 * 1000.0,
         BENCH_ITERS / t_sm4, 64.0 * BENCH_ITERS / t_sm4 / 1e6);

  t0 = get_time_sec();
  for (int i = 0; i < BENCH_ITERS; i++)
    prg_4_lambda(test_key, test_iv, (uint32_t)i, aes_out4, 128);
  t1 = get_time_sec();
  t_aes = t1 - t0;
  printf("  %-28s  %8d iters  %8.2f ms  %10.0f ops/s  %8.2f MB/s\n",
         "AES-PRG-4λ (AES-NI)", BENCH_ITERS, t_aes * 1000.0,
         BENCH_ITERS / t_aes, 64.0 * BENCH_ITERS / t_aes / 1e6);
  printf("  -> SM4/AES ratio: %.2fx\n\n", t_sm4 / t_aes);

  /* --- 4. Single-block encryption comparison --- */
  printf("[4] Single-block encryption\n");

  sm4_round_keys_t sm4_rk;
  sm4_init_round_keys(&sm4_rk, test_key);
  uint8_t sm4_blk_in[16], sm4_blk_out[16];
  memcpy(sm4_blk_in, test_iv, 16);

  for (int i = 0; i < WARMUP_ITERS; i++)
    sm4_encrypt_block(&sm4_rk, sm4_blk_in, sm4_blk_out);

  t0 = get_time_sec();
  for (int i = 0; i < BENCH_ITERS * 10; i++)
    sm4_encrypt_block(&sm4_rk, sm4_blk_in, sm4_blk_out);
  t1 = get_time_sec();
  t_sm4 = t1 - t0;
  int enc_iters = BENCH_ITERS * 10;
  printf("  %-28s  %8d iters  %8.2f ms  %10.0f ops/s\n",
         "SM4 encrypt_block", enc_iters, t_sm4 * 1000.0,
         enc_iters / t_sm4);

  printf("\n=== Summary ===\n");
  printf("SM4 uses T-table + 4-block interleaved CTR (software)\n");
  printf("AES uses AES-NI hardware instructions\n");
  printf("Lower SM4/AES ratio = closer performance to AES-NI\n");

  return 0;
}
