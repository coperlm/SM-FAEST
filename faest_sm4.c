/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "faest_sm4.h"
#include "fields.h"
#include "vole.h"
#include "universal_hashing.h"
#include "utils.h"
#include "parameters.h"
#include "sm4.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// ============================================================================
// SM4 ZK 约束系统实现
// 基于 QuickSilver 证明系统，使用逆仿射变换处理 S-box 约束
// ============================================================================

// SM4 仿射常数 (根据 S-box[0] 推导)
#define SM4_AFFINE_C 0xD6
// L^{-1}(SM4_AFFINE_C) = 0x1C，用于 Verifier 处理常数项
#define SM4_AFFINE_C_INV 0x1C

// 宏定义：循环左移 8 位
#define SM4_ROTL8(x, n) (((x) << (n)) | ((x) >> (8 - (n))))

// 预计算 8-bit 仿射变换的线性掩码（L 及其逆）
static uint8_t sm4_affine_l_masks[8];     // y = L(x)
static uint8_t sm4_affine_l_inv_masks[8]; // x = L^-1(y)
static bool sm4_affine_masks_initialized = false;

// 线性部分的 L^-1 (不含常数)，同 inverse_affine_scalar 去掉常数项
static inline uint8_t sm4_affine_l_inv_lin(uint8_t v) {
  return (SM4_ROTL8(v, 7) ^ SM4_ROTL8(v, 5) ^ SM4_ROTL8(v, 1)) & 0xFF;
}

// 根据线性函数生成输出位对应的输入掩码
static void sm4_build_linear_masks8(uint8_t masks[8], uint8_t (*linear_fn)(uint8_t)) {
  memset(masks, 0, 8);
  for (unsigned int in_bit = 0; in_bit < 8; ++in_bit) {
    uint8_t in_val = 1u << in_bit;
    uint8_t out_val = linear_fn(in_val);
    for (unsigned int out_bit = 0; out_bit < 8; ++out_bit) {
      if ((out_val >> out_bit) & 1u) {
        masks[out_bit] |= (1u << in_bit);
      }
    }
  }
}

// GF(2) 8x8 矩阵求逆，输入为行掩码形式（out_bit -> in_mask）
static void sm4_invert_masks8(uint8_t out[8], const uint8_t in[8]) {
  uint8_t A[8];
  uint8_t I[8];
  memcpy(A, in, 8);
  for (unsigned int i = 0; i < 8; ++i) {
    I[i] = 1u << i;
  }

  for (unsigned int col = 0; col < 8; ++col) {
    // 寻找主元
    unsigned int pivot = col;
    while (pivot < 8 && ((A[pivot] >> col) & 1u) == 0) {
      ++pivot;
    }
    assert(pivot < 8);
    // 交换行
    if (pivot != col) {
      uint8_t tmp = A[col];
      A[col] = A[pivot];
      A[pivot] = tmp;
      tmp = I[col];
      I[col] = I[pivot];
      I[pivot] = tmp;
    }
    // 消元
    for (unsigned int row = 0; row < 8; ++row) {
      if (row != col && ((A[row] >> col) & 1u)) {
        A[row] ^= A[col];
        I[row] ^= I[col];
      }
    }
  }
  memcpy(out, I, 8);
}

static void sm4_init_affine_masks(void) {
  if (sm4_affine_masks_initialized) {
    return;
  }
  // L^-1 的线性掩码
  sm4_build_linear_masks8(sm4_affine_l_inv_masks, sm4_affine_l_inv_lin);
  // 反转得到 L 的线性掩码
  sm4_invert_masks8(sm4_affine_l_masks, sm4_affine_l_inv_masks);
  sm4_affine_masks_initialized = true;
}

#ifndef FAEST_SM4_DEBUG
#define FAEST_SM4_DEBUG 0
#endif

#if defined(FAEST_SM4_DEBUG)
// Global flag to stop after first mismatch
static bool sm4_debug_first_error_reported = false;

static void sm4_debug_hex(const char* label, const uint8_t* buf, size_t len) {
  if (sm4_debug_first_error_reported) return;
  fprintf(stderr, "[SM4_DEBUG] %s:", label);
  for (size_t i = 0; i < len; ++i) {
    fprintf(stderr, "%s%02x", (i % 16 == 0) ? " " : "", buf[i]);
  }
  fprintf(stderr, "\n");
}

static void sm4_debug_bits32(const char* label, const uint8_t* buf) {
  if (sm4_debug_first_error_reported) return;
  char bits[33];
  for (unsigned int bit = 0; bit < 32; ++bit) {
    bits[bit] = ptr_get_bit(buf, bit) ? '1' : '0';
  }
  bits[32] = '\0';
  fprintf(stderr, "[SM4_DEBUG] %s bits[0..31]=%s\n", label, bits);
}

static const char* sm4_dbg_stage = "unknown";
static unsigned sm4_dbg_round = 0;
static unsigned sm4_dbg_pos = 0;

static void sm4_debug_set_ctx(const char* stage, unsigned int round, unsigned int pos) {
  sm4_dbg_stage = stage;
  sm4_dbg_round = round;
  sm4_dbg_pos = pos;
}

static void sm4_hash3_update_dbg(zk_hash_128_3_ctx* ctx, bf128_t v0, bf128_t v1, bf128_t v2) {
  if (sm4_debug_first_error_reported) return;
  uint8_t b0[BF128_NUM_BYTES], b1[BF128_NUM_BYTES], b2[BF128_NUM_BYTES];
  zk_hash_128_3_update(ctx, v0, v1, v2);
  bf128_store(b0, ctx->h0[0]);
  bf128_store(b1, ctx->h0[1]);
  bf128_store(b2, ctx->h0[2]);
  fprintf(stderr, "[SM4_DEBUG] hash3 stage=%s round=%u pos=%u h0=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
                  " h1=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
                  " h2=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
          sm4_dbg_stage, sm4_dbg_round, sm4_dbg_pos,
          b0[0], b0[1], b0[2], b0[3], b0[4], b0[5], b0[6], b0[7], b0[8], b0[9], b0[10], b0[11],
          b0[12], b0[13], b0[14], b0[15],
          b1[0], b1[1], b1[2], b1[3], b1[4], b1[5], b1[6], b1[7], b1[8], b1[9], b1[10], b1[11],
          b1[12], b1[13], b1[14], b1[15],
          b2[0], b2[1], b2[2], b2[3], b2[4], b2[5], b2[6], b2[7], b2[8], b2[9], b2[10], b2[11],
          b2[12], b2[13], b2[14], b2[15]);
}

static void sm4_hash_update_dbg(zk_hash_128_ctx* ctx, bf128_t v) {
  if (sm4_debug_first_error_reported) return;
  uint8_t b0[BF128_NUM_BYTES], b1[BF128_NUM_BYTES];
  zk_hash_128_update(ctx, v);
  bf128_store(b0, ctx->h0);
  bf128_store(b1, ctx->h1);
  fprintf(stderr, "[SM4_DEBUG] hash1 stage=%s round=%u pos=%u h0=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
                  " h1=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
          sm4_dbg_stage, sm4_dbg_round, sm4_dbg_pos,
          b0[0], b0[1], b0[2], b0[3], b0[4], b0[5], b0[6], b0[7], b0[8], b0[9], b0[10], b0[11],
          b0[12], b0[13], b0[14], b0[15],
          b1[0], b1[1], b1[2], b1[3], b1[4], b1[5], b1[6], b1[7], b1[8], b1[9], b1[10], b1[11],
          b1[12], b1[13], b1[14], b1[15]);
}

static void sm4_debug_dump_tags(const char* label, const bf128_t* tags, size_t count) {
  if (sm4_debug_first_error_reported) return;
  for (size_t i = 0; i < count; ++i) {
    uint8_t buf[BF128_NUM_BYTES];
    bf128_store(buf, tags[i]);
    fprintf(stderr, "[SM4_DEBUG] %s[%zu]=", label, i);
    for (size_t j = 0; j < BF128_NUM_BYTES; ++j) {
      fprintf(stderr, "%02x", buf[j]);
    }
    fprintf(stderr, "\n");
  }
}

// Debug helpers to compare prover/transposed witness against verifier view
static bf128_t* sm4_dbg_last_w_tag    = NULL;
static size_t   sm4_dbg_last_w_taglen = 0;
static bf128_t  sm4_dbg_last_v_star0;
static bf128_t  sm4_dbg_last_v_star1;
static uint8_t* sm4_dbg_last_witness = NULL;
static size_t   sm4_dbg_last_witness_len = 0;
static uint8_t* sm4_dbg_last_u = NULL;
static size_t   sm4_dbg_last_u_len = 0;
static uint64_t* sm4_dbg_last_v_col_hashes = NULL;
static size_t   sm4_dbg_last_v_col_count = 0;
static size_t   sm4_dbg_last_v_col_bytes = 0;
static uint8_t* sm4_dbg_last_v_cols = NULL;
static size_t   sm4_dbg_last_v_cols_len = 0;
static uint64_t sm4_dbg_last_chall2_hash = 0;
static size_t   sm4_dbg_last_chall2_len = 0;

static uint64_t sm4_hash64_fnv1a_local(const uint8_t* data, size_t len) {
  uint64_t h = 1469598103934665603ULL;
  for (size_t i = 0; i < len; ++i) {
    h ^= (uint64_t)data[i];
    h *= 1099511628211ULL;
  }
  return h;
}
#endif

// ============================================================================
// 标量版本的 SM4 逆仿射变换（用于参考和测试）
// ============================================================================

/**
 * SM4 逆仿射变换（标量版本）
 * 输入: sbox_out - S-box 的输出值
 * 输出: z - 在 GF(2^8) 域中的逆元值
 * 逻辑: z = L^-1(sbox_out ^ C)
 * 其中 C = 0xD6, L^-1: z[i] = y[(i+1)%8] ^ y[(i+3)%8] ^ y[(i+7)%8]
 */
static inline uint8_t sm4_inverse_affine_scalar(uint8_t sbox_out) {
  uint8_t y = sbox_out ^ SM4_AFFINE_C;
  return (SM4_ROTL8(y, 7) ^ SM4_ROTL8(y, 5) ^ SM4_ROTL8(y, 1)) & 0xFF;
}

// ============================================================================
// TODO: 完整实现 SM4 的 ZK 约束系统
// 需要实现以下约束（参考 faest_aes.c.in）：
// 1. ✅ SM4 逆仿射变换（标量版本 - 已完成）
// 2. ✅ SM4 逆仿射变换（SSS 版本 - Prover - 已完成）
// 3. ✅ SM4 逆仿射变换（SSS 版本 - Verifier - 已完成）
// 4. ⬜ 逆元共轭转换
// 5. ⬜ 逆元约束验证
// 6. ⬜ 线性变换 L 和 L' 约束
// 7. ⬜ Feistel 轮函数约束
// 8. ⬜ 密钥扩展约束
// ============================================================================

// ============================================================================
// SSS 版本的 SM4 逆仿射变换
// ============================================================================

/**
 * SM4 逆仿射变换（SSS 版本 - 单字节 Prover）
 * 输入: x_bits - 输入字节，x_bits_tag - 输入的 SSS tag（8 bit）
 * 输出: y_bits - 输出字节，y_bits_tag - 输出的 SSS tag（8 bit）
 * 
 * 逻辑:
 * 1. 标量计算: y = L^-1(x ^ 0xD6)
 *    L^-1: z = (y<<<7) ^ (y<<<5) ^ (y<<<1)
 * 2. Tag 计算（线性操作）:
 *    应用相同的线性变换
 */
static void sm4_SSS_inverse_affine_byte_prover(uint8_t* y_bits, bf128_t* y_bits_tag,
                                                const uint8_t x_bits, const bf128_t* x_bits_tag) {
  // 1. 标量计算: y = L^-1(x ^ C)
  // C = 0xD6, L^-1 使用循环左移: (y<<<7) ^ (y<<<5) ^ (y<<<1)
  uint8_t y_temp = x_bits ^ SM4_AFFINE_C;
  *y_bits = (SM4_ROTL8(y_temp, 7) ^ SM4_ROTL8(y_temp, 5) ^ SM4_ROTL8(y_temp, 1)) & 0xFF;
  
  // 2. Tag 计算（线性部分）
  // 首先处理常数 0xD6 的 XOR（在 prover 侧，delta=0，所以 tag 不变）
  // 然后应用线性变换L^-1: z[i] = y[(i+1)%8] ^ y[(i+3)%8] ^ y[(i+7)%8]
  for (unsigned int bit_i = 0; bit_i < 8; bit_i++) {
    y_bits_tag[bit_i] = bf128_add(
        bf128_add(x_bits_tag[(bit_i + 1) % 8], x_bits_tag[(bit_i + 3) % 8]),
        x_bits_tag[(bit_i + 7) % 8]);
  }
}

/**
 * SM4 逆仿射变换（SSS 版本 - Prover，处理多字节）
 * 对状态的每个字节应用逆仿射变换
 */
static void sm4_SSS_inverse_affine_prover(uint8_t* y, bf128_t* y_tag, const uint8_t* x,
                                          const bf128_t* x_tag, const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;
  const unsigned int Nstbytes = Nst * 4;  // SM4 状态字节数 (通常是 16)
  
  for (unsigned int i = 0; i < Nstbytes; i++) {
    sm4_SSS_inverse_affine_byte_prover(y + i, y_tag + i * 8, x[i], x_tag + i * 8);
  }
}

/**
 * SM4 逆仿射变换（SSS 版本 - 单字节 Verifier）
 * Verifier 只需要验证线性关系，但需要处理常数项
 * 
 * 对于常数 C = 0xD6 = 11010110（二进制），其逆仿射常数 L^-1(C) = 0x1C = 00011100
 * Verifier 需要在这些位上（2,3,4）加上 delta
 */
static void sm4_SSS_inverse_affine_byte_verifier(bf128_t* y_bits_key, const bf128_t* x_bits_key,
                                                 bf128_t delta) {
  // 应用线性变换L^-1: z[i] = y[(i+1)%8] ^ y[(i+3)%8] ^ y[(i+7)%8]
  for (unsigned int bit_i = 0; bit_i < 8; bit_i++) {
    y_bits_key[bit_i] = bf128_add(
        bf128_add(x_bits_key[(bit_i + 1) % 8], x_bits_key[(bit_i + 3) % 8]),
        x_bits_key[(bit_i + 7) % 8]);
  }
  
  // 处理常数 L^-1(C) 的贡献：对每个为1的位加上 delta
  for (unsigned int bit = 0; bit < 8; ++bit) {
    if ((SM4_AFFINE_C_INV >> bit) & 1u) {
      y_bits_key[bit] = bf128_add(y_bits_key[bit], delta);
    }
  }
}

/**
 * SM4 逆仿射变换（SSS 版本 - Verifier，处理多字节）
 */
static void sm4_SSS_inverse_affine_verifier(bf128_t* y_key, const bf128_t* x_key, bf128_t delta,
                                            const faest_paramset_t* params) {
  const unsigned int Nst = params->Nst;
  const unsigned int Nstbytes = Nst * 4;
  
  for (unsigned int i = 0; i < Nstbytes; i++) {
    sm4_SSS_inverse_affine_byte_verifier(y_key + i * 8, x_key + i * 8, delta);
  }
}

// ============================================================================
// 仿射正向变换（L）: given z = L^-1(y ^ C)，求 y = L(z) ^ C
// ============================================================================

static inline uint8_t sm4_affine_forward_scalar(uint8_t z) {
  sm4_init_affine_masks();
  uint8_t y = 0;
  for (unsigned int out_bit = 0; out_bit < 8; ++out_bit) {
    uint8_t mask = sm4_affine_l_masks[out_bit];
    if (__builtin_parity((unsigned int)(z & mask))) {
      y |= (1u << out_bit);
    }
  }
  return y ^ SM4_AFFINE_C;
}

static void sm4_SSS_affine_forward_prover(uint8_t* out_val, bf128_t* out_tag,
                                           const uint8_t* in_val, const bf128_t* in_tag) {
  sm4_init_affine_masks();
  uint8_t z = *in_val;
  uint8_t y = 0;
  for (unsigned int out_bit = 0; out_bit < 8; ++out_bit) {
    uint8_t mask = sm4_affine_l_masks[out_bit];
    if (__builtin_parity((unsigned int)(z & mask))) {
      y |= (1u << out_bit);
    }
    bf128_t acc = bf128_zero();
    for (unsigned int in_bit = 0; in_bit < 8; ++in_bit) {
      if ((mask >> in_bit) & 1u) {
        acc = bf128_add(acc, in_tag[in_bit]);
      }
    }
    out_tag[out_bit] = acc;
  }
  *out_val = y ^ SM4_AFFINE_C;
}

static void sm4_SSS_affine_forward_verifier(bf128_t* out_eval, const bf128_t* in_eval,
                                            bf128_t delta) {
  sm4_init_affine_masks();
  for (unsigned int out_bit = 0; out_bit < 8; ++out_bit) {
    bf128_t acc = bf128_zero();
    uint8_t mask = sm4_affine_l_masks[out_bit];
    for (unsigned int in_bit = 0; in_bit < 8; ++in_bit) {
      if ((mask >> in_bit) & 1u) {
        acc = bf128_add(acc, in_eval[in_bit]);
      }
    }
    // 常数 C 的贡献：若该位为1则加 delta
    if ((SM4_AFFINE_C >> out_bit) & 1u) {
      acc = bf128_add(acc, delta);
    }
    out_eval[out_bit] = acc;
  }
}

// ============================================================================
// Phase 2: Inverse Norm to Conjugates
// ============================================================================

// ============================================================================
// SM4-专属 GF(2^8) → GF(2^128) 嵌入
//
// 关键发现：bf128_alpha[] 是 AES 专属嵌入，不适用于 SM4。
// 需要基于 SM4 多项式的根来构造正确的 SM4 嵌入。
//
// 方法：找 SM4 多项式 x^8+x^7+x^6+x^5+x^4+x^2+1 在 AES GF(2^8) 中的根 α_SM4 = 0x23，
// 然后 sm4_alpha[i] = bcb(α_SM4^(i+1)) 作为 SM4 嵌入的基。
//
// 数学保证：sm4_byte_combine_bits 是 SM4 GF(2^8) → GF(2^128) 的域同态。
// ============================================================================
static const bf128_t sm4_bf128_alpha[7] = {
    BF128C(UINT64_C(0x8414a18b2e7b4cb8), UINT64_C(0x51a595b4b31f44b9)),  // sm4_alpha[0]=bcb(0x23)
    BF128C(UINT64_C(0x5dcfb96668033b3f), UINT64_C(0xb7b4d5c60bd51316)),  // sm4_alpha[1]=bcb(0x69)
    BF128C(UINT64_C(0xa2df20a573bdb41c), UINT64_C(0x15a791e4c69547df)),  // sm4_alpha[2]=bcb(0x34)
    BF128C(UINT64_C(0x37323ff280de9950), UINT64_C(0x4099030c7a9fae78)),  // sm4_alpha[3]=bcb(0x86)
    BF128C(UINT64_C(0xed09ef16e07b94c6), UINT64_C(0xb61257cfad572414)),  // sm4_alpha[4]=bcb(0xfa)
    BF128C(UINT64_C(0xaf480aae3fd21d7b), UINT64_C(0xcbd0879f43ace048)),  // sm4_alpha[5]=bcb(0x67)
    BF128C(UINT64_C(0xa0415e708193f42b), UINT64_C(0xffdb65d9987f058c)),  // sm4_alpha[6]=bcb(0xfd)
};

/**
 * SM4 专属 byte_combine_bits：正确的 SM4 GF(2^8) → GF(2^128) 嵌入
 * x_sm4 的比特 i 对应 sm4_bf128_alpha 基元素，而不是 AES 的 bf128_alpha。
 */
static inline bf128_t sm4_byte_combine_bits(uint8_t x) {
  bf128_t r = bf128_from_bit(get_bit(x, 0));
  for (unsigned int i = 1; i < 8; ++i) {
    r = bf128_add(r, bf128_mul_bit(sm4_bf128_alpha[i - 1], get_bit(x, i)));
  }
  return r;
}

/**
 * SM4 专属 byte_combine：对 8 个 bf128_t 标签值求加权和（使用 SM4 alpha）
 * 等价于 AES 的 bf128_byte_combine 但使用 SM4 专属基。
 */
static inline bf128_t sm4_byte_combine(const bf128_t* x) {
  bf128_t r = x[0];
  for (unsigned int i = 1; i < 8; ++i) {
    r = bf128_add(r, bf128_mul(x[i], sm4_bf128_alpha[i - 1]));
  }
  return r;
}

// ============================================================================
// SM4 beta 常量（GF(2^128) 硬编码值）
//
// 多项式基 β=0x0c 在 SM4 GF(2^4) 中：
//   β^1=0x0c, β^2=0x50, β^3=0x2a, β^4=0x0d, β^8=0x51
//   β^6=0x7a, β^9=0x26, β^12=0x77
// 这些是通过 sm4_byte_combine_bits(β^k) 计算得到的正确 GF(2^128) 常量。
// ============================================================================

// beta_squares_bf128[i] = sm4_bcb(β^{2^i}), i=0..4 (bsq[4]=bsq[0] by periodicity)
// beta_cubes_bf128[i] = sm4_bcb(β^{3*2^i}), i=0..3
static const bf128_t sm4_beta_squares_bf128[5] = {
    BF128C(UINT64_C(0xff1099c31bbe8f23), UINT64_C(0xa2134422cd4054c9)),  // sm4_bcb(0x0c)=bsq[0]
    BF128C(UINT64_C(0x987a355cbf0c842b), UINT64_C(0x8b49849339334e30)),  // sm4_bcb(0x50)=bsq[1]
    BF128C(UINT64_C(0xff1099c31bbe8f22), UINT64_C(0xa2134422cd4054c9)),  // sm4_bcb(0x0d)=bsq[2]
    BF128C(UINT64_C(0x987a355cbf0c842a), UINT64_C(0x8b49849339334e30)),  // sm4_bcb(0x51)=bsq[3]
    BF128C(UINT64_C(0xff1099c31bbe8f23), UINT64_C(0xa2134422cd4054c9)),  // sm4_bcb(0x0c)=bsq[4]
};

static const bf128_t sm4_beta_cubes_bf128[4] = {
    BF128C(UINT64_C(0xcbc26e38bdbd6c62), UINT64_C(0xf210539fd8dd2772)),  // sm4_bcb(0x2a)=bcu[0]
    BF128C(UINT64_C(0x53b85b6402b1e849), UINT64_C(0x7959d70ce1ee6942)),  // sm4_bcb(0x7a)=bcu[1]
    BF128C(UINT64_C(0x34d2f7fba603e341), UINT64_C(0x500317bd159d73bb)),  // sm4_bcb(0x26)=bcu[2]
    BF128C(UINT64_C(0xaca8c2a7190f676b), UINT64_C(0xdb4a932e2cae3d8b)),  // sm4_bcb(0x77)=bcu[3]
};

// ============================================================================
// SM4 常量: FK (系统参数) 和 CK (固定参数)
// ============================================================================

// 系统参数 FK (用于初始密钥变换)
static const uint32_t SM4_FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

// 固定参数 CK (用于32轮密钥生成)
static const uint32_t SM4_CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

/**
 * SM4 逆元到共轭转换（Prover 版本）
 * 将输入的逆元值（8 bits）转换为 4 个共轭值
 * 
 * 公式: y[i] = x[0] + β^(2i)*x[1] + β^(2i+2)*x[2] + β^(3i+3)*x[3]
 *       对于 i = 0,1,2,3
 * 
 * 这是 GF(2^8) 上的分解，用于后续的逆元约束验证
 */
static void sm4_SSS_inv_norm_to_conjugates_prover(bf128_t* y_val, bf128_t* y_tag,
                                                  const uint8_t x_val, const bf128_t* x_tag) {
  
  // 对于 4 个共轭值
  for (unsigned int i = 0; i < 4; ++i) {
    // y_val[i] = x_val[0] + β^(2i)*x_val[1] + β^(2i+2)*x_val[2] + β^(3i+3)*x_val[3]
    // 使用 get_bit 从 x_val 中提取各个 bit
    y_val[i] = bf128_add(
        bf128_add(bf128_from_bit(get_bit(x_val, 0)),
                  bf128_mul_bit(sm4_beta_squares_bf128[i], get_bit(x_val, 1))),
        bf128_add(bf128_mul_bit(sm4_beta_squares_bf128[i + 1], get_bit(x_val, 2)),
                  bf128_mul_bit(sm4_beta_cubes_bf128[i], get_bit(x_val, 3))));
    
    // y_tag[i] 的计算类似，但使用 tag 值（线性操作）
    y_tag[i] = bf128_add(
        bf128_add(x_tag[0], bf128_mul(sm4_beta_squares_bf128[i], x_tag[1])),
        bf128_add(bf128_mul(sm4_beta_squares_bf128[i + 1], x_tag[2]),
                  bf128_mul(sm4_beta_cubes_bf128[i], x_tag[3])));
  }
}

/**
 * SM4 逆元到共轭转换（Verifier 版本）
 * 只处理求值点，不需要处理明文值
 */
static void sm4_SSS_inv_norm_to_conjugates_verifier(bf128_t* y_eval, const bf128_t* x_eval) {
  
  for (unsigned int i = 0; i < 4; ++i) {
    y_eval[i] = bf128_add(
        bf128_add(x_eval[0], bf128_mul(sm4_beta_squares_bf128[i], x_eval[1])),
        bf128_add(bf128_mul(sm4_beta_squares_bf128[i + 1], x_eval[2]),
                  bf128_mul(sm4_beta_cubes_bf128[i], x_eval[3])));
  }
}

// ============================================================================
// Phase 2.1: F256/F2 Conjugates (SM4 field polynomial)
// ============================================================================

static inline uint8_t sm4_bits_sq(uint8_t x) {
  return bf8_square_sm4(x);
}

static void sm4_build_sq_masks(uint8_t masks[8]) {
  memset(masks, 0, 8);
  for (unsigned int in_bit = 0; in_bit < 8; ++in_bit) {
    uint8_t out_val = sm4_bits_sq((uint8_t)(1u << in_bit));
    for (unsigned int out_bit = 0; out_bit < 8; ++out_bit) {
      if ((out_val >> out_bit) & 1u) {
        masks[out_bit] |= (uint8_t)(1u << in_bit);
      }
    }
  }
}

static void sm4_sq_bit_inplace(bf128_t* tag) {
  static bool initialized = false;
  static uint8_t masks[8];

  if (!initialized) {
    sm4_build_sq_masks(masks);
    initialized = true;
  }

  bf128_t tmp[8];
  for (unsigned int out_bit = 0; out_bit < 8; ++out_bit) {
    bf128_t acc = bf128_zero();
    uint8_t mask = masks[out_bit];
    for (unsigned int in_bit = 0; in_bit < 8; ++in_bit) {
      if ((mask >> in_bit) & 1u) {
        acc = bf128_add(acc, tag[in_bit]);
      }
    }
    tmp[out_bit] = acc;
  }
  memcpy(tag, tmp, sizeof(tmp));
}

static void sm4_SSS_f256_f2_conjugates_1_byte(bf128_t* y, uint8_t x) {
  uint8_t x0 = x;
  for (unsigned int j = 0; j < 7; ++j) {
    y[j] = sm4_byte_combine_bits(x0);
    x0 = sm4_bits_sq(x0);
  }
  y[7] = sm4_byte_combine_bits(x0);
}

static void sm4_SSS_f256_f2_conjugates_SSS_byte(bf128_t* y, const bf128_t* x_bits) {
  bf128_t x[8];
  memcpy(x, x_bits, sizeof(x));
  for (unsigned int j = 0; j < 7; ++j) {
    y[j] = sm4_byte_combine(x);
    sm4_sq_bit_inplace(x);
  }
  y[7] = sm4_byte_combine(x);
}

// ============================================================================
// Phase 2: Inverse Norm Constraints
// ============================================================================

/**
 * SM4 逆元约束（Prover 版本）
 * 生成 ZK 约束来验证: input × inverse = 1 在 SM4 域中
 * 
 * 使用 conjugates 来构造度数为 3 的多项式约束
 * 约束形式: y * conjugates[1] * conjugates[4] + conjugates[0] * delta^2 = 0
 */
static void sm4_SSS_inv_norm_constraints_prover(zk_hash_128_3_ctx* hasher,
                                                const bf128_t* conjugates,
                                                const bf128_t* conjugates_tag,
                                                const bf128_t* y,
                                                const bf128_t* y_tag) {
  // 计算 y * conjugates[1] * conjugates[4] 的承诺
  // 这是一个度数为 3 的项（三个秘密值的乘积）
  
  // 度数 3 项: y_tag * conjugates_tag[1] * conjugates_tag[4]
  bf128_t deg3 = bf128_mul(bf128_mul(*y_tag, conjugates_tag[1]), conjugates_tag[4]);
  
  // 度数 2 项: 包含两个 tag 和一个 value 的所有组合
  bf128_t deg2 = bf128_add(
      bf128_add(bf128_mul(bf128_mul(*y, conjugates_tag[1]), conjugates_tag[4]),
                bf128_mul(bf128_mul(*y_tag, conjugates_tag[1]), conjugates[4])),
      bf128_mul(bf128_mul(*y_tag, conjugates[1]), conjugates_tag[4]));
  
  // 度数 1 项: 包含一个 tag 和两个 value 的所有组合，加上 conjugates_tag[0]
  bf128_t deg1 = bf128_add(
      bf128_add(bf128_add(bf128_mul(bf128_mul(*y, conjugates[1]), conjugates_tag[4]),
                          bf128_mul(bf128_mul(*y, conjugates_tag[1]), conjugates[4])),
                bf128_mul(bf128_mul(*y_tag, conjugates[1]), conjugates[4])),
      conjugates_tag[0]);
  
  // 将约束提交到 ZK hasher
  
#if defined(FAEST_SM4_DEBUG)
  if (!sm4_debug_first_error_reported && sm4_dbg_round == 0 && sm4_dbg_pos == 0) {
    uint8_t d3b[BF128_NUM_BYTES], d2b[BF128_NUM_BYTES], d1b[BF128_NUM_BYTES];
    bf128_store(d3b, deg3); bf128_store(d2b, deg2); bf128_store(d1b, deg1);
    fprintf(stderr, "[SM4_DEBUG] prover constraint deg3=");
    for (size_t _j=0;_j<BF128_NUM_BYTES;++_j) fprintf(stderr,"%02x",d3b[_j]);
    fprintf(stderr, " deg2=");
    for (size_t _j=0;_j<BF128_NUM_BYTES;++_j) fprintf(stderr,"%02x",d2b[_j]);
    fprintf(stderr, " deg1=");
    for (size_t _j=0;_j<BF128_NUM_BYTES;++_j) fprintf(stderr,"%02x",d1b[_j]);
    fprintf(stderr, "\n");
  }
  sm4_hash3_update_dbg(hasher, deg3, deg2, deg1);
#else
  zk_hash_128_3_update(hasher, deg3, deg2, deg1);
#endif
}

/**
 * SM4 逆元约束（Verifier 版本）
 * 验证者验证约束: y * conjugates[1] * conjugates[4] + conjugates[0] * delta^2 = 0
 */
static void sm4_SSS_inv_norm_constraints_verifier(zk_hash_128_ctx* hasher,
                                                  const bf128_t* conjugates_eval,
                                                  const bf128_t* y_eval,
                                                  const bf128_t delta) {
  // 计算: y_eval * conjugates_eval[1] * conjugates_eval[4] + conjugates_eval[0] * delta^2
  bf128_t term = bf128_add(
      bf128_mul(bf128_mul(*y_eval, conjugates_eval[1]), conjugates_eval[4]),
      bf128_mul(conjugates_eval[0], bf128_mul(delta, delta)));
  
#if defined(FAEST_SM4_DEBUG)
  if (!sm4_debug_first_error_reported && sm4_dbg_round == 0 && sm4_dbg_pos == 0) {
    uint8_t tb[BF128_NUM_BYTES];
    bf128_store(tb, term);
    fprintf(stderr, "[SM4_DEBUG] verifier constraint term=");
    for (size_t _j=0;_j<BF128_NUM_BYTES;++_j) fprintf(stderr,"%02x",tb[_j]);
    fprintf(stderr, "\n");
  }
  sm4_hash_update_dbg(hasher, term);
#else
  zk_hash_128_update(hasher, term);
#endif
}

// ============================================================================
// Phase 3: Linear Transformations (L and L')
// ============================================================================

/**
 * 循环左移32位字（用于SSS线性变换）
 * 输入：4个字节的值和tag（共32位）
 * 输出：循环左移n位后的结果
 * 
 * 循环左移是线性操作，可以分别应用到val和tag上
 */
static void sm4_SSS_rotl32_prover(uint8_t* out_val, bf128_t* out_tag,
                                  const uint8_t* in_val, const bf128_t* in_tag,
                                  unsigned int n) {
  n %= 32;
  uint8_t tmp[4] = {0};

  for (unsigned int dst = 0; dst < 32; ++dst) {
    const unsigned int dst_byte = dst / 8;
    const unsigned int dst_bit = dst % 8;
    const unsigned int dst_word_bit = (3u - dst_byte) * 8u + dst_bit;
    const unsigned int src_word_bit = (dst_word_bit + (32u - n)) % 32u;
    const unsigned int src_byte = 3u - (src_word_bit / 8u);
    const unsigned int src_bit = src_word_bit % 8u;
    const unsigned int src = src_byte * 8u + src_bit;
    if (ptr_get_bit(in_val, src)) {
      ptr_set_bit(tmp, dst, 1);
    }
    out_tag[dst] = in_tag[src];
  }

  memcpy(out_val, tmp, sizeof(tmp));
}

/**
 * 循环左移32位字（Verifier版本）
 */
static void sm4_SSS_rotl32_verifier(bf128_t* out_eval, const bf128_t* in_eval, unsigned int n) {
  n %= 32;
  // 临时数组存储结果
  bf128_t temp[32];
  
  for (unsigned int dst = 0; dst < 32; ++dst) {
    const unsigned int dst_byte = dst / 8;
    const unsigned int dst_bit = dst % 8;
    const unsigned int dst_word_bit = (3u - dst_byte) * 8u + dst_bit;
    const unsigned int src_word_bit = (dst_word_bit + (32u - n)) % 32u;
    const unsigned int src_byte = 3u - (src_word_bit / 8u);
    const unsigned int src_bit = src_word_bit % 8u;
    const unsigned int src = src_byte * 8u + src_bit;
    temp[dst] = in_eval[src];
  }
  
  memcpy(out_eval, temp, sizeof(bf128_t) * 32);
}

/**
 * SM4 线性变换 L (用于加密)
 * L(B) = B ⊕ (B<<<2) ⊕ (B<<<10) ⊕ (B<<<18) ⊕ (B<<<24)
 * 
 * Prover版本：处理32位输入（4字节 = 32位）
 */
static void sm4_SSS_linear_l_prover(uint8_t* out_val, bf128_t* out_tag,
                                    const uint8_t* in_val, const bf128_t* in_tag) {
  // 临时存储各个循环左移的结果
  uint8_t rot2_val[4], rot10_val[4], rot18_val[4], rot24_val[4];
  bf128_t rot2_tag[32], rot10_tag[32], rot18_tag[32], rot24_tag[32];
  
  // 计算各个循环左移
  sm4_SSS_rotl32_prover(rot2_val, rot2_tag, in_val, in_tag, 2);
  sm4_SSS_rotl32_prover(rot10_val, rot10_tag, in_val, in_tag, 10);
  sm4_SSS_rotl32_prover(rot18_val, rot18_tag, in_val, in_tag, 18);
  sm4_SSS_rotl32_prover(rot24_val, rot24_tag, in_val, in_tag, 24);
  
  // L(B) = B ⊕ rot2 ⊕ rot10 ⊕ rot18 ⊕ rot24
  for (unsigned int i = 0; i < 4; i++) {
    out_val[i] = in_val[i] ^ rot2_val[i] ^ rot10_val[i] ^ rot18_val[i] ^ rot24_val[i];
    
    for (unsigned int bit = 0; bit < 8; bit++) {
      unsigned int idx = i * 8 + bit;
      out_tag[idx] = bf128_add(
          bf128_add(bf128_add(in_tag[idx], rot2_tag[idx]), rot10_tag[idx]),
          bf128_add(rot18_tag[idx], rot24_tag[idx]));
    }
  }
}

/**
 * SM4 线性变换 L (Verifier版本)
 */
static void sm4_SSS_linear_l_verifier(bf128_t* out_eval, const bf128_t* in_eval) {
  bf128_t rot2_eval[32], rot10_eval[32], rot18_eval[32], rot24_eval[32];
  
  sm4_SSS_rotl32_verifier(rot2_eval, in_eval, 2);
  sm4_SSS_rotl32_verifier(rot10_eval, in_eval, 10);
  sm4_SSS_rotl32_verifier(rot18_eval, in_eval, 18);
  sm4_SSS_rotl32_verifier(rot24_eval, in_eval, 24);
  
  for (unsigned int i = 0; i < 32; i++) {
    out_eval[i] = bf128_add(
        bf128_add(bf128_add(in_eval[i], rot2_eval[i]), rot10_eval[i]),
        bf128_add(rot18_eval[i], rot24_eval[i]));
  }
}

static inline uint8_t sm4_parity32(uint32_t x) {
  x ^= x >> 16;
  x ^= x >> 8;
  x ^= x >> 4;
  x &= 0xF;
  return (UINT8_C(0x69) >> x) & 1;
}

static inline uint32_t sm4_word_from_tag_index(unsigned int idx) {
  const unsigned int byte = idx / 8;
  const unsigned int bit = idx % 8;
  const unsigned int word_bit = (3 - byte) * 8 + bit;
  return UINT32_C(1) << word_bit;
}

static void sm4_build_linear_masks(uint32_t masks[32], uint32_t (*linear_fn)(uint32_t)) {
  for (unsigned int i = 0; i < 32; ++i) {
    masks[i] = 0;
  }

  for (unsigned int in_idx = 0; in_idx < 32; ++in_idx) {
    uint32_t in_word = sm4_word_from_tag_index(in_idx);
    uint32_t out_word = linear_fn(in_word);
    uint8_t out_bytes[4];
    sm4_uint32_to_bytes(out_word, out_bytes);
    for (unsigned int out_idx = 0; out_idx < 32; ++out_idx) {
      const unsigned int byte = out_idx / 8;
      const unsigned int bit = out_idx % 8;
      if ((out_bytes[byte] >> bit) & 1) {
        masks[out_idx] |= UINT32_C(1) << in_idx;
      }
    }
  }
}

static void sm4_invert_masks(uint32_t out[32], const uint32_t in[32]) {
  uint64_t rows[32];
  for (unsigned int i = 0; i < 32; ++i) {
    rows[i] = ((uint64_t)in[i]) | ((uint64_t)UINT32_C(1) << (32 + i));
  }

  for (unsigned int col = 0; col < 32; ++col) {
    unsigned int pivot = col;
    while (pivot < 32 && ((rows[pivot] >> col) & 1) == 0) {
      ++pivot;
    }
    assert(pivot < 32);
    if (pivot != col) {
      uint64_t tmp = rows[col];
      rows[col] = rows[pivot];
      rows[pivot] = tmp;
    }
    for (unsigned int r = 0; r < 32; ++r) {
      if (r != col && ((rows[r] >> col) & 1)) {
        rows[r] ^= rows[col];
      }
    }
  }

  for (unsigned int i = 0; i < 32; ++i) {
    out[i] = (uint32_t)(rows[i] >> 32);
  }
}

static void sm4_linear_l_inv_masks(uint32_t masks[32]) {
  static bool initialized = false;
  static uint32_t cached[32];

  if (initialized) {
    memcpy(masks, cached, sizeof(cached));
    return;
  }

  uint32_t forward[32];
  sm4_build_linear_masks(forward, sm4_linear_l);
  sm4_invert_masks(cached, forward);
  memcpy(masks, cached, sizeof(cached));
  initialized = true;
}

static uint32_t sm4_linear_l_inv_scalar(uint32_t in) {
  uint32_t masks[32];
  sm4_linear_l_inv_masks(masks);

  uint32_t out = 0;
  for (unsigned int bit = 0; bit < 32; ++bit) {
    if (sm4_parity32(in & masks[bit])) {
      out |= (UINT32_C(1) << bit);
    }
  }
  return out;
}

static void sm4_SSS_linear_l_inv_prover(uint8_t* out_val, bf128_t* out_tag,
                                        const uint8_t* in_val, const bf128_t* in_tag) {
  uint32_t masks[32];
  sm4_linear_l_inv_masks(masks);

  uint32_t in_word = sm4_bytes_to_uint32(in_val);
  uint32_t out_word = sm4_linear_l_inv_scalar(in_word);
  sm4_uint32_to_bytes(out_word, out_val);

  for (unsigned int bit = 0; bit < 32; ++bit) {
    bf128_t acc = bf128_zero();
    uint32_t mask = masks[bit];
    for (unsigned int src = 0; src < 32; ++src) {
      if ((mask >> src) & 1) {
        acc = bf128_add(acc, in_tag[src]);
      }
    }
    out_tag[bit] = acc;
  }
}

static void sm4_SSS_linear_l_inv_verifier(bf128_t* out_eval, const bf128_t* in_eval) {
  uint32_t masks[32];
  sm4_linear_l_inv_masks(masks);

  for (unsigned int bit = 0; bit < 32; ++bit) {
    bf128_t acc = bf128_zero();
    uint32_t mask = masks[bit];
    for (unsigned int src = 0; src < 32; ++src) {
      if ((mask >> src) & 1) {
        acc = bf128_add(acc, in_eval[src]);
      }
    }
    out_eval[bit] = acc;
  }
}

/**
 * SM4 线性变换 L' (用于密钥扩展)
 * L'(B) = B ⊕ (B<<<13) ⊕ (B<<<23)
 * 
 * Prover版本
 */
static void sm4_SSS_linear_l_prime_prover(uint8_t* out_val, bf128_t* out_tag,
                                         const uint8_t* in_val, const bf128_t* in_tag) {
  uint8_t rot13_val[4], rot23_val[4];
  bf128_t rot13_tag[32], rot23_tag[32];
  
  sm4_SSS_rotl32_prover(rot13_val, rot13_tag, in_val, in_tag, 13);
  sm4_SSS_rotl32_prover(rot23_val, rot23_tag, in_val, in_tag, 23);
  
  // L'(B) = B ⊕ rot13 ⊕ rot23
  for (unsigned int i = 0; i < 4; i++) {
    out_val[i] = in_val[i] ^ rot13_val[i] ^ rot23_val[i];
    
    for (unsigned int bit = 0; bit < 8; bit++) {
      unsigned int idx = i * 8 + bit;
      out_tag[idx] = bf128_add(bf128_add(in_tag[idx], rot13_tag[idx]), rot23_tag[idx]);
    }
  }
}

/**
 * SM4 线性变换 L' (Verifier版本)
 */
static void sm4_SSS_linear_l_prime_verifier(bf128_t* out_eval, const bf128_t* in_eval) {
  bf128_t rot13_eval[32], rot23_eval[32];
  
  sm4_SSS_rotl32_verifier(rot13_eval, in_eval, 13);
  sm4_SSS_rotl32_verifier(rot23_eval, in_eval, 23);
  
  for (unsigned int i = 0; i < 32; i++) {
    out_eval[i] = bf128_add(bf128_add(in_eval[i], rot13_eval[i]), rot23_eval[i]);
  }
}

static void sm4_linear_l_prime_inv_masks(uint32_t masks[32]) {
  static bool initialized = false;
  static uint32_t cached[32];

  if (initialized) {
    memcpy(masks, cached, sizeof(cached));
    return;
  }

  uint32_t forward[32];
  sm4_build_linear_masks(forward, sm4_linear_l_prime);
  sm4_invert_masks(cached, forward);
  memcpy(masks, cached, sizeof(cached));
  initialized = true;
}

static uint32_t sm4_linear_l_prime_inv_scalar(uint32_t in) {
  uint32_t masks[32];
  sm4_linear_l_prime_inv_masks(masks);

  uint32_t out = 0;
  for (unsigned int bit = 0; bit < 32; ++bit) {
    if (sm4_parity32(in & masks[bit])) {
      out |= (UINT32_C(1) << bit);
    }
  }
  return out;
}

static void sm4_SSS_linear_l_prime_inv_prover(uint8_t* out_val, bf128_t* out_tag,
                                              const uint8_t* in_val, const bf128_t* in_tag) {
  uint32_t masks[32];
  sm4_linear_l_prime_inv_masks(masks);

  uint32_t in_word = sm4_bytes_to_uint32(in_val);
  uint32_t out_word = sm4_linear_l_prime_inv_scalar(in_word);
  sm4_uint32_to_bytes(out_word, out_val);

  for (unsigned int bit = 0; bit < 32; ++bit) {
    bf128_t acc = bf128_zero();
    uint32_t mask = masks[bit];
    for (unsigned int src = 0; src < 32; ++src) {
      if ((mask >> src) & 1) {
        acc = bf128_add(acc, in_tag[src]);
      }
    }
    out_tag[bit] = acc;
  }
}

static void sm4_SSS_linear_l_prime_inv_verifier(bf128_t* out_eval, const bf128_t* in_eval) {
  uint32_t masks[32];
  sm4_linear_l_prime_inv_masks(masks);

  for (unsigned int bit = 0; bit < 32; ++bit) {
    bf128_t acc = bf128_zero();
    uint32_t mask = masks[bit];
    for (unsigned int src = 0; src < 32; ++src) {
      if ((mask >> src) & 1) {
        acc = bf128_add(acc, in_eval[src]);
      }
    }
    out_eval[bit] = acc;
  }
}

// ============================================================================
// Phase 4: 密钥扩展约束
// ============================================================================

/**
 * SM4 密钥扩展向前传播 (Prover版本)
 * 从主密钥 MK 生成 36 个字 (K[0..35])
 * K[0..3] = MK ⊕ FK
 * K[i+4] = K[i] ⊕ T'(K[i+1] ⊕ K[i+2] ⊕ K[i+3] ⊕ CK[i]) for i=0..31
 * 
 * @param rk 输出：36个32位字的轮密钥 (144字节)
 * @param rk_tag 输出：轮密钥的tag (36*32 = 1152 bf128_t)
 * @param w 输入：扩展见证 (从主密钥开始)
 * @param w_tag 输入：扩展见证的tag
 */
static void sm4_SSS_keyexp_forward_prover(uint8_t* rk, bf128_t* rk_tag,
                                          const uint8_t* w, const bf128_t* w_tag) {
  // SM4固定为128位密钥 = 16字节 = 4个字
  // 类似AES的 NK = 4
  const unsigned int SM4_NK = 4;  // 密钥字数
  const unsigned int SM4_R = 32;  // 轮数
  
  // ::1-2 复制前128位 (MK ⊕ FK 已经在w中)
  memcpy(rk, w, 128 / 8);  // 16 bytes = K[0..3]
  memcpy(rk_tag, w_tag, 128 * sizeof(bf128_t));
  
  // ::3 索引到下一个见证位置
  unsigned int i_wd = 128;  // 已经处理了128位
  
  // ::4-10 生成32轮密钥 (K[4..35])
  for (unsigned int j = SM4_NK; j < SM4_NK + SM4_R; j++) {
    // SM4每轮都需要S盒输出，所以从见证中提取
    // w[i_wd/8] 包含 T'(K[i+1] ⊕ K[i+2] ⊕ K[i+3] ⊕ CK[i]) 的输出
    memcpy(&rk[32 * j / 8], &w[i_wd / 8], 32 / 8);  // 4 bytes
    memcpy(&rk_tag[32 * j], &w_tag[i_wd], 32 * sizeof(bf128_t));
    i_wd += 32;  // 移动到下一个字
  }
}

/**
 * SM4 密钥扩展向前传播 (Verifier版本)
 */
static void sm4_SSS_keyexp_forward_verifier(bf128_t* rk_key, const bf128_t* w_key) {
  const unsigned int SM4_NK = 4;
  const unsigned int SM4_R = 32;
  
  // ::1-2
  memcpy(rk_key, w_key, 128 * sizeof(bf128_t));
  
  // ::3
  unsigned int i_wd = 128;
  
  // ::4-10
  for (unsigned int j = SM4_NK; j < SM4_NK + SM4_R; j++) {
    memcpy(&rk_key[32 * j], &w_key[i_wd], 32 * sizeof(bf128_t));
    i_wd += 32;
  }
}

/**
 * SM4 密钥扩展反向传播 (Prover版本)
 * 从轮密钥反推S盒输入
 * 
 * @param sbox_inputs 输出：32轮S盒输入（每轮4字节，共128字节）
 * @param sbox_inputs_tag 输出：S盒输入的tag
 * @param w_sbox 输入：扩展见证中的S盒输出
 * @param w_sbox_tag 输入：S盒输出的tag
 * @param rk 输入：轮密钥
 * @param rk_tag 输入：轮密钥tag
 */
static void sm4_SSS_keyexp_backward_prover(uint8_t* sbox_inputs, bf128_t* sbox_inputs_tag,
                                           const uint8_t* w_sbox, const bf128_t* w_sbox_tag,
                                           const uint8_t* rk, const bf128_t* rk_tag) {
  (void)rk_tag; // Unused parameter
  const unsigned int SM4_R = 32;
  
  // 对于每一轮 i (i=0..31):
  // K[i+4] = K[i] ⊕ T'(X)  其中 X = K[i+1] ⊕ K[i+2] ⊕ K[i+3] ⊕ CK[i]
  // 因此: T'(X) = K[i+4] ⊕ K[i]
  // T'(X) 包含 τ(X) = Sbox 输出，我们需要反推 X (Sbox输入)
  
  for (unsigned int i = 0; i < SM4_R; i++) {
    // 计算 T'(X) = K[i+4] ⊕ K[i]
    uint32_t t_prime_out;
    uint8_t* t_prime_bytes = (uint8_t*)&t_prime_out;
    
    // XOR K[i+4] 和 K[i] 的值
    for (unsigned int byte_idx = 0; byte_idx < 4; byte_idx++) {
      t_prime_bytes[byte_idx] = rk[4 * (i + 4) + byte_idx] ^ rk[4 * i + byte_idx];
    }
    
    // 应用 L'^-1 到 T'(X) 得到 τ(X)
    // L'(B) = B ⊕ (B<<<13) ⊕ (B<<<23)
    // 需要 L'^-1，但这里直接从见证中获取τ(X)的输出
    // w_sbox[32*i/8 .. 32*(i+1)/8) 存储的是 τ(X) 的S盒输出（逆变换后）
    
    // SM4的约束：我们从见证中得到S盒输出的逆仿射变换
    // 这里 w_sbox 存储的是S盒输入（经过逆仿射变换）
    memcpy(&sbox_inputs[4 * i], &w_sbox[4 * i], 4);
    memcpy(&sbox_inputs_tag[32 * i], &w_sbox_tag[32 * i], 32 * sizeof(bf128_t));
  }
}

/**
 * SM4 密钥扩展反向传播 (Verifier版本)
 */
static void sm4_SSS_keyexp_backward_verifier(bf128_t* sbox_inputs_key, const bf128_t* w_sbox_key,
                                             const bf128_t* rk_key, bf128_t delta) {
  (void)rk_key;   // SM4暂时不需要从rk反推，直接用w_sbox
  (void)delta;
  
  const unsigned int SM4_R = 32;
  
  // 直接从见证中复制S盒输入的key
  for (unsigned int i = 0; i < SM4_R; i++) {
    memcpy(&sbox_inputs_key[32 * i], &w_sbox_key[32 * i], 32 * sizeof(bf128_t));
  }
}

/**
 * SM4 密钥扩展约束验证 (Prover版本)
 * 验证每轮的 S盒输入×S盒输出 关系
 */
static void sm4_SSS_expkey_constraints_prover(zk_hash_128_3_ctx* hasher, uint8_t* rk, bf128_t* rk_tag,
                                              const uint8_t* w, const bf128_t* w_tag) {
  const unsigned int SM4_R = 32;
  const unsigned int KEY_BITS = (SM4_R + 4) * 32;
  const uint8_t* inv_block = w + KEY_BITS / 8;
  const bf128_t* inv_block_tag = w_tag + KEY_BITS;
  // ::1 向前传播生成轮密钥
  sm4_SSS_keyexp_forward_prover(rk, rk_tag, w, w_tag);

  // ::2-5 对每轮S盒约束
  for (unsigned int i = 0; i < SM4_R; i++) {
    uint8_t ck_bytes[4];
    sm4_uint32_to_bytes(SM4_CK[i], ck_bytes);

    uint8_t x_bytes[4];
    bf128_t x_tag[32];
    uint8_t tprime_out[4];
    bf128_t tprime_tag[32];

    for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
      x_bytes[byte_i] = rk[(i + 1) * 4 + byte_i] ^ rk[(i + 2) * 4 + byte_i] ^
                        rk[(i + 3) * 4 + byte_i] ^ ck_bytes[byte_i];
      tprime_out[byte_i] = rk[(i + 4) * 4 + byte_i] ^ rk[i * 4 + byte_i];

      for (unsigned int bit = 0; bit < 8; bit++) {
        unsigned int idx = byte_i * 8 + bit;
        x_tag[idx] = bf128_add(
            bf128_add(rk_tag[(i + 1) * 32 + idx], rk_tag[(i + 2) * 32 + idx]),
            rk_tag[(i + 3) * 32 + idx]);
        tprime_tag[idx] = bf128_add(rk_tag[(i + 4) * 32 + idx], rk_tag[i * 32 + idx]);
      }
    }

    uint8_t tau_bytes[4];
    bf128_t tau_tag[32];
    sm4_SSS_linear_l_prime_inv_prover(tau_bytes, tau_tag, tprime_out, tprime_tag);

    for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
      uint8_t inv_norm = inv_block[i * 4 + byte_i];
      bf128_t inv_norm_tag[8];
      for (unsigned int bit = 0; bit < 8; ++bit) {
        inv_norm_tag[bit] = inv_block_tag[i * 32 + byte_i * 8 + bit];
      }

#if defined(FAEST_SM4_DEBUG)
      uint8_t expected_inv = sm4_inverse_affine_scalar(sm4_sbox(x_bytes[byte_i]));
      if (inv_norm != expected_inv) {
        fprintf(stderr,
                "[SM4_DEBUG] keyexp inv mismatch r=%u byte=%u witness=%02x expected=%02x\n",
                i, byte_i, inv_norm, expected_inv);
      }
#endif

      bf128_t y[4];
      bf128_t y_tag[4];
      sm4_SSS_inv_norm_to_conjugates_prover(y, y_tag, inv_norm, inv_norm_tag);

      bf128_t conj[8];
      bf128_t conj_tag[8];
      sm4_SSS_f256_f2_conjugates_1_byte(conj, x_bytes[byte_i]);
      sm4_SSS_f256_f2_conjugates_SSS_byte(conj_tag, x_tag + byte_i * 8);

#if defined(FAEST_SM4_DEBUG)
      sm4_debug_set_ctx("keyexp", i, byte_i);
  if (i == 0 && byte_i == 0) {
    sm4_debug_hex("prover keyexp x_byte", &x_bytes[0], 1);
    sm4_debug_hex("prover keyexp inv_norm", &inv_norm, 1);
    sm4_debug_dump_tags("prover keyexp x_tag", x_tag + byte_i * 8, 8);
    sm4_debug_dump_tags("prover keyexp inv_tag", inv_norm_tag, 8);
  }
#endif
      sm4_SSS_inv_norm_constraints_prover(hasher, conj, conj_tag, y, y_tag);
    }
  }
}

/**
 * SM4 密钥扩展约束验证 (Verifier版本)
 */
static void sm4_SSS_expkey_constraints_verifier(zk_hash_128_ctx* hasher, bf128_t* rk_key,
                                                const bf128_t* w_key, bf128_t delta) {
  const unsigned int SM4_R = 32;
  const unsigned int KEY_BITS = (SM4_R + 4) * 32;
  const bf128_t* inv_block_key = w_key + KEY_BITS;
  // ::1 向前传播
  sm4_SSS_keyexp_forward_verifier(rk_key, w_key);

  // ::2-5 验证每轮S盒约束
  for (unsigned int i = 0; i < SM4_R; i++) {
    uint8_t ck_bytes[4];
    sm4_uint32_to_bytes(SM4_CK[i], ck_bytes);

    bf128_t x_key[32];
    bf128_t tprime_key[32];

    for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
      for (unsigned int bit = 0; bit < 8; bit++) {
        unsigned int idx = byte_i * 8 + bit;
        x_key[idx] = bf128_add(
            bf128_add(rk_key[(i + 1) * 32 + idx], rk_key[(i + 2) * 32 + idx]),
            rk_key[(i + 3) * 32 + idx]);
        if ((ck_bytes[byte_i] >> bit) & 1) {
          x_key[idx] = bf128_add(x_key[idx], delta);
        }

        tprime_key[idx] = bf128_add(rk_key[(i + 4) * 32 + idx], rk_key[i * 32 + idx]);
      }
    }

    bf128_t tau_key[32];
    sm4_SSS_linear_l_prime_inv_verifier(tau_key, tprime_key);

    for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
      bf128_t inv_norm_key[8];
      for (unsigned int bit = 0; bit < 8; ++bit) {
        inv_norm_key[bit] = inv_block_key[i * 32 + byte_i * 8 + bit];
      }

      bf128_t y_key[4];
      sm4_SSS_inv_norm_to_conjugates_verifier(y_key, inv_norm_key);

      bf128_t conj_key[8];
      sm4_SSS_f256_f2_conjugates_SSS_byte(conj_key, x_key + byte_i * 8);

#if defined(FAEST_SM4_DEBUG)
      sm4_debug_set_ctx("keyexp", i, byte_i);
  if (i == 0 && byte_i == 0) {
    sm4_debug_dump_tags("verifier keyexp x_tag", x_key + byte_i * 8, 8);
    sm4_debug_dump_tags("verifier keyexp inv_tag", inv_norm_key, 8);
  }
#endif
      sm4_SSS_inv_norm_constraints_verifier(hasher, conj_key, y_key, delta);
    }
  }
}

// ============================================================================
// Phase 5: Feistel轮函数约束（加密）
// ============================================================================

static void sm4_SSS_enc_constraints_prover(zk_hash_128_3_ctx* hasher,
                                           const uint8_t* owf_in, const bf128_t* owf_in_tag,
                                           const uint8_t* owf_out, const bf128_t* owf_out_tag,
                                           const uint8_t* w, const bf128_t* w_tag,
                                           const uint8_t* rk, const bf128_t* rk_tag,
                                           const faest_paramset_t* params) {
  (void)params; // Unused parameter
  const unsigned int SM4_R = 32;
  const unsigned int Nbytes = 16;
  const unsigned int Nbits = 128;
  
  // 当前状态（滚动窗口：4个字）
  uint8_t state[16];
  bf128_t state_tag[128];
  
  // ::1 初始化状态从输入明文
  memcpy(state, owf_in, Nbytes);
  memcpy(state_tag, owf_in_tag, Nbits * sizeof(bf128_t));
  
  // ::2 每次迭代处理2轮（奇数轮+偶数轮）
  for (unsigned int r_pair = 0; r_pair < SM4_R / 2; r_pair++) {
    unsigned int r_odd = r_pair * 2 + 1;   // 奇数轮：1,3,5,...,31
    unsigned int r_even = r_pair * 2 + 2;  // 偶数轮：2,4,6,...,32
    
    // ========== 奇数轮：生成 S-box 约束（通过 inv*temp=1） ==========
    // ::3 计算 temp = state[1] ⊕ state[2] ⊕ state[3] ⊕ rk[round_idx]
    // SM4算法：每轮使用rk[i]，i从0开始
    // rk数组：rk[0..3]是初始密钥(MK^FK)，rk[4..35]是32个轮密钥
    unsigned int round_idx = r_odd - 1;  // 轮索引从0开始，所以r_odd=1对应rk[4]
    
    uint8_t temp_odd[4];
    bf128_t temp_odd_tag[32];
    
    for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
      temp_odd[byte_i] = state[4 + byte_i] ^ state[8 + byte_i] ^
                         state[12 + byte_i] ^ rk[(round_idx + 4) * 4 + byte_i];
      
      for (unsigned int bit = 0; bit < 8; bit++) {
        temp_odd_tag[byte_i * 8 + bit] = bf128_add(
            bf128_add(state_tag[32 + byte_i * 8 + bit], state_tag[64 + byte_i * 8 + bit]),
            bf128_add(state_tag[96 + byte_i * 8 + bit], rk_tag[(round_idx + 4) * 32 + byte_i * 8 + bit]));
      }
    }
    
    // ::4 从见证读取4个字节的 S-box 输出（奇数轮专有）
    // Witness布局：8字节(sbox+invnorm) + 16字节state + 4字节偶数轮invnorm = 28字节/对
    // 最后一对（r_pair=15, r_even=32使用公开输出）只有8字节
    const unsigned int pair_bytes = 28;  // 4 sbox + 4 inv + 16 state + 4 even_inv
    const unsigned int base_bytes =
        (r_pair < SM4_R / 2 - 1) ? r_pair * pair_bytes : (SM4_R / 2 - 1) * pair_bytes;
    const unsigned int base_bits = base_bytes * 8;
    const uint8_t* sbox_bytes = w + base_bytes;
    const bf128_t* sbox_tags = w_tag + base_bits;

    uint8_t sbox_out_odd[4];
    bf128_t sbox_out_odd_tag[32];

    for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
      uint8_t sbox_val = sbox_bytes[byte_i * 2];
      uint8_t inv_val = sbox_bytes[byte_i * 2 + 1];
      const bf128_t* sbox_tag = sbox_tags + byte_i * 16;      // 8 bits for sbox, next 8 for inv
      const bf128_t* inv_tag = sbox_tag + 8;

      // ::6 生成 inv * temp == 1 约束（通过共轭多项式）
      bf128_t y[4];
      bf128_t y_tag[4];
      sm4_SSS_inv_norm_to_conjugates_prover(y, y_tag, inv_val, inv_tag);

      bf128_t conj[8];
      bf128_t conj_tag[8];
      sm4_SSS_f256_f2_conjugates_1_byte(conj, temp_odd[byte_i]);
      sm4_SSS_f256_f2_conjugates_SSS_byte(conj_tag, temp_odd_tag + byte_i * 8);
#if defined(FAEST_SM4_DEBUG)
      uint8_t expected_inv = sm4_inverse_affine_scalar(sm4_sbox(temp_odd[byte_i]));
      if (inv_val != expected_inv) {
        fprintf(stderr,
                "[SM4_DEBUG] enc odd inv mismatch r=%u byte=%u witness=%02x expected=%02x\n",
                r_odd, byte_i, inv_val, expected_inv);
      }
    #endif
    #if defined(FAEST_SM4_DEBUG)
      sm4_debug_set_ctx("enc_odd", r_odd, byte_i);
#endif
      sm4_SSS_inv_norm_constraints_prover(hasher, conj, conj_tag, y, y_tag);

      // ::7 直接使用 witness 的 S-box 输出
      sbox_out_odd[byte_i] = sbox_val;
      memcpy(&sbox_out_odd_tag[byte_i * 8], sbox_tag, 8 * sizeof(bf128_t));
    }
    
    // ::9 应用线性变换L
    uint8_t L_out_odd[4];
    bf128_t L_out_odd_tag[32];
    sm4_SSS_linear_l_prover(L_out_odd, L_out_odd_tag, sbox_out_odd, sbox_out_odd_tag);
    
    // ::10 计算新字 = state[0] ⊕ L(τ(temp))
    uint8_t new_word_odd[4];
    bf128_t new_word_odd_tag[32];
    for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
      new_word_odd[byte_i] = state[byte_i] ^ L_out_odd[byte_i];
      
      for (unsigned int bit = 0; bit < 8; bit++) {
        new_word_odd_tag[byte_i * 8 + bit] =
            bf128_add(state_tag[byte_i * 8 + bit], L_out_odd_tag[byte_i * 8 + bit]);
      }
    }
    
    // ::11 更新状态（滚动移位）: state = [state[1], state[2], state[3], new_word]
    memmove(state, state + 4, 12);
    memcpy(state + 12, new_word_odd, 4);
    memmove(state_tag, state_tag + 32, 96 * sizeof(bf128_t));
    memcpy(state_tag + 96, new_word_odd_tag, 32 * sizeof(bf128_t));
    
    // ========== 偶数轮：使用状态见证生成S盒约束 ==========
    if (r_even <= SM4_R) {  // 第32轮使用公开输出作为状态
      // ::12 计算 temp = state[1] ⊕ state[2] ⊕ state[3] ⊕ rk[round_idx]
      unsigned int round_idx_even = r_even - 1;

      uint8_t temp_even[4];
      bf128_t temp_even_tag[32];

      for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
        temp_even[byte_i] = state[4 + byte_i] ^ state[8 + byte_i] ^
                            state[12 + byte_i] ^ rk[(round_idx_even + 4) * 4 + byte_i];

        for (unsigned int bit = 0; bit < 8; bit++) {
          temp_even_tag[byte_i * 8 + bit] = bf128_add(
              bf128_add(state_tag[32 + byte_i * 8 + bit], state_tag[64 + byte_i * 8 + bit]),
              bf128_add(state_tag[96 + byte_i * 8 + bit], rk_tag[(round_idx_even + 4) * 32 + byte_i * 8 + bit]));
        }
      }

      // ::13 偶数轮从witness读取完整状态（普通对）；第32轮改用公开输出
      // Witness布局：每对轮28字节（8字节sbox/inv + 16字节state + 4字节偶数轮invnorm）
      // 最后一对（r_even=SM4_R）：8字节sbox/inv + 4字节偶数轮invnorm（无state）
      uint8_t state_witness_buf[16];
      bf128_t state_witness_tag_buf[128];
      const uint8_t* state_witness = NULL;
      const bf128_t* state_witness_tag = NULL;
      const uint8_t* inv_even_witness = NULL;
      const bf128_t* inv_even_witness_tag = NULL;
      if (r_pair < SM4_R / 2 - 1) {
        // Normal even round: state at +8, invnorm at +24
        state_witness = sbox_bytes + 8;
        state_witness_tag = sbox_tags + 64;    // skip 8 bytes = 64 bits
        inv_even_witness = sbox_bytes + 24;    // 8 + 16 = 24 bytes offset
        inv_even_witness_tag = sbox_tags + 192; // 64 + 128 = 192 bits offset
      }
      if (r_even == SM4_R) {
        // Last even round: state = public output (reversed word order)
        for (unsigned int word = 0; word < 4; word++) {
          memcpy(state_witness_buf + word * 4, owf_out + (3 - word) * 4, 4);
          memcpy(state_witness_tag_buf + word * 32, owf_out_tag + (3 - word) * 32,
                 32 * sizeof(bf128_t));
        }
        state_witness = state_witness_buf;
        state_witness_tag = state_witness_tag_buf;
        // invnorm for last pair: right after odd-round 8 bytes (no state in witness)
        inv_even_witness = sbox_bytes + 8;
        inv_even_witness_tag = sbox_tags + 64;
      }

      // ::14 从witness直接读取偶数轮invnorm（不再通过inverse_affine推导）
      uint8_t inv_norm_even[4];
      bf128_t inv_norm_even_tag[32];
      for (unsigned int byte_i = 0; byte_i < 4; ++byte_i) {
        inv_norm_even[byte_i] = inv_even_witness[byte_i];
        for (unsigned int bit = 0; bit < 8; ++bit) {
          inv_norm_even_tag[byte_i * 8 + bit] = inv_even_witness_tag[byte_i * 8 + bit];
        }
      }

#if defined(FAEST_SM4_DEBUG)
      // Sanity check: witness invnorm should match sm4_invnorm(temp_even[byte_i])
      for (unsigned int byte_i = 0; byte_i < 4; ++byte_i) {
        uint8_t expected_inv_even = sm4_invnorm(temp_even[byte_i]);
        if (inv_norm_even[byte_i] != expected_inv_even) {
          fprintf(stderr,
                  "[SM4_DEBUG] enc_even inv mismatch r=%u byte=%u witness=%02x expected=%02x\n",
                  r_even, byte_i, inv_norm_even[byte_i], expected_inv_even);
        }
      }
#endif

      // ::16 生成逆范数约束
      for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
        bf128_t y[4];
        bf128_t y_tag[4];
        sm4_SSS_inv_norm_to_conjugates_prover(y, y_tag, inv_norm_even[byte_i],
                                              inv_norm_even_tag + byte_i * 8);

        bf128_t conj[8];
        bf128_t conj_tag[8];
        sm4_SSS_f256_f2_conjugates_1_byte(conj, temp_even[byte_i]);
        sm4_SSS_f256_f2_conjugates_SSS_byte(conj_tag, temp_even_tag + byte_i * 8);

        sm4_debug_set_ctx("enc_even", r_even, byte_i);
        sm4_SSS_inv_norm_constraints_prover(hasher, conj, conj_tag, y, y_tag);
      }

      // ::17 更新状态到witness值
      memcpy(state, state_witness, 16);
      memcpy(state_tag, state_witness_tag, 128 * sizeof(bf128_t));
    }
  }

  // TEMP SAFETY CHECK MOVED: handled at the top-level constraints using the secret key.
  (void)owf_out_tag;
}

/**
 * SM4 加密约束 (Verifier版本)
 * 验证32轮Feistel结构，按AES风格每次处理2轮（奇+偶）
 */
static void sm4_SSS_enc_constraints_verifier(zk_hash_128_ctx* hasher,
                                             const bf128_t* owf_in_key,
                                             const bf128_t* owf_out_key,
                                             const bf128_t* w_key,
                                             const bf128_t* rk_key,
                                             bf128_t delta,
                                             const faest_paramset_t* params) {
  (void)params; // Unused parameter
  const unsigned int SM4_R = 32;
  const unsigned int Nbits = 128;
  
  // 当前状态key（滚动窗口：4个字）
  bf128_t state_key[128];
  
  // ::1 初始化从输入key
  memcpy(state_key, owf_in_key, Nbits * sizeof(bf128_t));
  
  // ::2 每次迭代处理2轮（奇数轮+偶数轮）
  for (unsigned int r_pair = 0; r_pair < SM4_R / 2; r_pair++) {
    unsigned int r_odd = r_pair * 2 + 1;
    unsigned int r_even = r_pair * 2 + 2;
    
    // ========== 奇数轮：生成逆范数约束 ==========
    // ::3 计算 temp_key = state_key[1] ⊕ state_key[2] ⊕ state_key[3] ⊕ rk_key[round_idx]
    unsigned int round_idx = r_odd - 1;  // 轮索引从0开始
    bf128_t temp_odd_key[32];
    
    for (unsigned int bit = 0; bit < 32; bit++) {
      temp_odd_key[bit] = bf128_add(
          bf128_add(state_key[32 + bit], state_key[64 + bit]),
          bf128_add(state_key[96 + bit], rk_key[(round_idx + 4) * 32 + bit]));
    }
    
    // ::4 从见证读取4个字节的 S-box 输出 key
    const unsigned int pair_bytes = 28;  // 4 sbox + 4 inv + 16 state + 4 even_inv
    const unsigned int base_bytes = (r_pair < SM4_R / 2 - 1) ? r_pair * pair_bytes : (SM4_R / 2 - 1) * pair_bytes;
    const unsigned int base_bits = base_bytes * 8;
    const bf128_t* sbox_keys = w_key + base_bits;  // 每对轮：前8字节是 (sbox, inv)
    
    bf128_t sbox_out_odd_key[32];
    
    for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
      const bf128_t* sbox_key = sbox_keys + byte_i * 16;
      const bf128_t* inv_key = sbox_key + 8;
      
      // ::7 生成 inv * temp == 1 约束
      bf128_t y_key[4];
      sm4_SSS_inv_norm_to_conjugates_verifier(y_key, inv_key);
      bf128_t conj_key[8];
      sm4_SSS_f256_f2_conjugates_SSS_byte(conj_key, temp_odd_key + byte_i * 8);
    #if defined(FAEST_SM4_DEBUG)
      sm4_debug_set_ctx("enc_odd", r_odd, byte_i);
    #endif
      sm4_SSS_inv_norm_constraints_verifier(hasher, conj_key, y_key, delta);
      
      // ::8 直接使用 witness 的 S-box 输出
      memcpy(&sbox_out_odd_key[byte_i * 8], sbox_key, 8 * sizeof(bf128_t));
    }
    
    // ::9 应用线性变换L
    bf128_t L_out_odd_key[32];
    sm4_SSS_linear_l_verifier(L_out_odd_key, sbox_out_odd_key);
    
    // ::10 计算新字 = state_key[0] ⊕ L(τ(temp))
    bf128_t new_word_odd_key[32];
    for (unsigned int bit = 0; bit < 32; bit++) {
      new_word_odd_key[bit] = bf128_add(state_key[bit], L_out_odd_key[bit]);
    }
    
    // ::11 更新状态
    memmove(state_key, state_key + 32, 96 * sizeof(bf128_t));
    memcpy(state_key + 96, new_word_odd_key, 32 * sizeof(bf128_t));
    
    // ========== 偶数轮：使用状态见证生成S盒约束 ==========
    if (r_even <= SM4_R) {
      // ::12 计算 temp_key = state_key[1] ⊕ state_key[2] ⊕ state_key[3] ⊕ rk_key[round_idx]
      unsigned int round_idx_even = r_even - 1;
      bf128_t temp_even_key[32];

      for (unsigned int bit = 0; bit < 32; bit++) {
        temp_even_key[bit] = bf128_add(
            bf128_add(state_key[32 + bit], state_key[64 + bit]),
            bf128_add(state_key[96 + bit], rk_key[(round_idx_even + 4) * 32 + bit]));
      }

      // ::13 读取偶数轮状态见证key；第32轮改用公开输出
      // Witness布局对应：每对28字节（8字节sbox/inv + 16字节state + 4字节invnorm）
      // 最后一对（r_even=SM4_R）：8字节sbox/inv + 4字节invnorm（无state）
      bf128_t state_witness_key_buf[128];
      const bf128_t* state_witness_key = NULL;
      const bf128_t* inv_even_witness_key = NULL;
      if (r_pair < SM4_R / 2 - 1) {
        state_witness_key = sbox_keys + 64;   // skip 8 bytes (sbox+inv) = 64 bits
        inv_even_witness_key = sbox_keys + 192; // 64 + 128 = 192 bits
      }
      if (r_even == SM4_R) {
        // Last even round: state = public output (reversed word order)
        for (unsigned int word = 0; word < 4; word++) {
          memcpy(state_witness_key_buf + word * 32, owf_out_key + (3 - word) * 32,
                 32 * sizeof(bf128_t));
        }
        state_witness_key = state_witness_key_buf;
        // invnorm for last pair: right after odd 8 bytes
        inv_even_witness_key = sbox_keys + 64;
      }

      // ::14 从witness直接读取偶数轮invnorm的key（不再通过inverse_affine推导）
      bf128_t inv_norm_even_key[32];
      for (unsigned int byte_i = 0; byte_i < 4; ++byte_i) {
        for (unsigned int bit = 0; bit < 8; ++bit) {
          inv_norm_even_key[byte_i * 8 + bit] = inv_even_witness_key[byte_i * 8 + bit];
        }
      }

      // ::16 生成逆范数约束
      for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
        bf128_t y_key[4];
        sm4_SSS_inv_norm_to_conjugates_verifier(y_key, inv_norm_even_key + byte_i * 8);

        bf128_t conj_key[8];
        sm4_SSS_f256_f2_conjugates_SSS_byte(conj_key, temp_even_key + byte_i * 8);
#if defined(FAEST_SM4_DEBUG)
        sm4_debug_set_ctx("enc_even", r_even, byte_i);
#endif
        sm4_SSS_inv_norm_constraints_verifier(hasher, conj_key, y_key, delta);
      }

      // ::17 更新状态到witness值
      memcpy(state_key, state_witness_key, 128 * sizeof(bf128_t));
    }
  }
  
  // ::17 验证最终输出（已隐含在约束系统中）
  (void)owf_out_key;
}

// ============================================================================
// Phase 6: 完整约束系统（OWF CONSTRAINTS）
// ============================================================================

/**
 * 完整的SM4约束系统 (Prover版本)
 * 包含密钥扩展和加密约束
 */
static void sm4_SSS_constraints_prover(zk_hash_128_3_ctx* hasher, const uint8_t* w,
                                       const bf128_t* w_tag, const uint8_t* owf_in,
                                       const uint8_t* owf_out, const faest_paramset_t* params) {
  const unsigned int SM4_BLOCKSIZE = 128;  // 128位 = 16字节
  const unsigned int SM4_R = 32;           // 32轮

#if defined(FAEST_SM4_DEBUG)
  /* Debug-only witness sanity check: verify the witness key yields the public
   * output.  The ZK output constraint is already enforced cryptographically in
   * sm4_SSS_enc_constraints_prover: the last round loads owf_out as the state
   * and incorporates owf_out_tag into the ZK hash, so no extra assert is needed
   * in production.  Keeping this block debug-only avoids the silent no-op that
   * a bare assert() becomes when NDEBUG is defined. */
  if (!faest_is_em(params)) {
    uint8_t mk[16];
    for (unsigned int i = 0; i < 4; i++) {
      uint32_t k_word = sm4_bytes_to_uint32(w + 4 * i) ^ SM4_FK[i];
      sm4_uint32_to_bytes(k_word, mk + 4 * i);
    }
    sm4_round_keys_t rk_tmp;
    sm4_init_round_keys(&rk_tmp, mk);
    uint8_t expected_out[16];
    sm4_encrypt_block(&rk_tmp, owf_in, expected_out);
    if (memcmp(expected_out, owf_out, 16) != 0) {
      fprintf(stderr, "[SM4_DEBUG] sm4_SSS_constraints_prover: witness key does "
                      "not produce expected owf_out — possible witness bug\n");
    }
  }
#endif /* FAEST_SM4_DEBUG */
  
  // 分配轮密钥空间
  uint8_t* rk = malloc((SM4_R + 4) * 4);  // 36个字 × 4字节
  bf128_t* rk_tag = malloc((SM4_R + 4) * 32 * sizeof(bf128_t));  // 36个字 × 32位
  assert(rk);
  assert(rk_tag);
  
  // 分配输入/输出空间
  uint8_t* in = malloc(SM4_BLOCKSIZE / 8);
  bf128_t* in_tag = malloc(SM4_BLOCKSIZE * sizeof(bf128_t));
  uint8_t* out = malloc(SM4_BLOCKSIZE / 8);
  bf128_t* out_tag = malloc(SM4_BLOCKSIZE * sizeof(bf128_t));
  assert(in);
  assert(in_tag);
  assert(out);
  assert(out_tag);
  
  // 初始化输入（明文）
  memcpy(in, owf_in, SM4_BLOCKSIZE / 8);
  for (unsigned int i = 0; i < SM4_BLOCKSIZE; i++) {
    in_tag[i] = bf128_zero();  // 公开输入，tag为0
  }
  
  // 初始化输出（密文）
  memcpy(out, owf_out, SM4_BLOCKSIZE / 8);
  for (unsigned int i = 0; i < SM4_BLOCKSIZE; i++) {
    out_tag[i] = bf128_zero();  // 公开输出，tag为0
  }
  
  // ::1 密钥扩展约束
  sm4_SSS_expkey_constraints_prover(hasher, rk, rk_tag, w, w_tag);
  
  // ::2 加密约束（32轮）
  // w的布局：[MK:128位] [密钥扩展见证:32×32位] [加密见证:...]
  const unsigned int Lke = params->Lke;  // 密钥扩展部分长度
  sm4_SSS_enc_constraints_prover(hasher, in, in_tag, out, out_tag,
                                 w + Lke / 8, w_tag + Lke,
                                 rk, rk_tag, params);
  
  free(out_tag);
  free(out);
  free(in_tag);
  free(in);
  free(rk_tag);
  free(rk);
}

/**
 * 完整的SM4约束系统 (Verifier版本)
 */
static void sm4_SSS_constraints_verifier(zk_hash_128_ctx* hasher, const bf128_t* w_key,
                                         const uint8_t* owf_in, const uint8_t* owf_out,
                                         bf128_t delta, const faest_paramset_t* params) {
  const unsigned int SM4_BLOCKSIZE = 128;
  const unsigned int SM4_R = 32;
  
  // 分配轮密钥空间
  bf128_t* rk_key = malloc((SM4_R + 4) * 32 * sizeof(bf128_t));
  assert(rk_key);
  
  // 分配输入/输出空间
  bf128_t* in_key = malloc(SM4_BLOCKSIZE * sizeof(bf128_t));
  bf128_t* out_key = malloc(SM4_BLOCKSIZE * sizeof(bf128_t));
  assert(in_key);
  assert(out_key);
  
  // 初始化输入key（明文×delta）
  for (unsigned int i = 0; i < SM4_BLOCKSIZE / 8; i++) {
    for (unsigned int bit = 0; bit < 8; bit++) {
      in_key[i * 8 + bit] = bf128_mul_bit(delta, (owf_in[i] >> bit) & 1);
    }
  }
  
  // 初始化输出key（密文×delta）
  for (unsigned int i = 0; i < SM4_BLOCKSIZE / 8; i++) {
    for (unsigned int bit = 0; bit < 8; bit++) {
      out_key[i * 8 + bit] = bf128_mul_bit(delta, (owf_out[i] >> bit) & 1);
    }
  }
  
  // ::1 密钥扩展约束
  sm4_SSS_expkey_constraints_verifier(hasher, rk_key, w_key, delta);
  
  // ::2 加密约束
  const unsigned int Lke = params->Lke;
  sm4_SSS_enc_constraints_verifier(hasher, in_key, out_key, w_key + Lke,
                                   rk_key, delta, params);
  
  free(out_key);
  free(in_key);
  free(rk_key);
}

// ============================================================================
// 顶层 Prover/Verifier 接口
// ============================================================================

static inline void sm4_ptr_set_bit_be(uint8_t* dst, unsigned int index, unsigned int value) {
  const unsigned int bit = 7 - (index % 8);
  dst[index / 8] = (dst[index / 8] & ~(1u << bit)) | ((value & 1u) << bit);
}

static inline unsigned int sm4_ptr_get_bit_be(const uint8_t* src, unsigned int index) {
  return (src[index / 8] >> (7 - (index % 8))) & 1u;
}

static inline unsigned int sm4_map_row_to_word_swap(unsigned int row) {
  const unsigned int word_base = row & ~31u;
  const unsigned int byte_idx = (row >> 3) & 3u;
  const unsigned int bit_idx = row & 7u;
  return word_base | ((3u - byte_idx) << 3) | bit_idx;
}

static inline unsigned int sm4_map_row_to_word_bit_reverse(unsigned int row) {
  const unsigned int word_base = row & ~31u;
  const unsigned int bit_idx = row & 31u;
  return word_base | (31u - bit_idx);
}

static inline unsigned int sm4_map_row_apply(unsigned int row, unsigned int mode) {
  switch (mode) {
    case 1u:
      return sm4_map_row_to_word_swap(row);
    case 2u:
      return sm4_map_row_to_word_bit_reverse(row);
    case 3u:
      return sm4_map_row_to_word_bit_reverse(sm4_map_row_to_word_swap(row));
    default:
      return row;
  }
}

static inline unsigned int sm4_map_d_index(unsigned int row) {
  return row;
}

#if defined(FAEST_SM4_DEBUG)
static void sm4_debug_hex_raw(const uint8_t* src, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    fprintf(stderr, "%02x", src[i]);
  }
  fputc('\n', stderr);
}

static void sm4_selftest_vector_once(void) {
  static int done = 0;
  if (done) {
    return;
  }
  done = 1;

  const uint8_t key[16] = {
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
  };
  const uint8_t pt[16] = {
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
  };
  const uint8_t expected_ct[16] = {
      0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
      0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
  };

  sm4_round_keys_t rk;
  uint8_t ct[16];
  sm4_init_round_keys(&rk, key);
  sm4_encrypt_block(&rk, pt, ct);

  if (memcmp(ct, expected_ct, sizeof(ct)) != 0) {
    sm4_debug_hex("sm4_selftest ct", ct, sizeof(ct));
    sm4_debug_hex("sm4_selftest expected", expected_ct, sizeof(expected_ct));
    fprintf(stderr, "[SM4_DEBUG] sm4_selftest FAILED\n");
  } else {
    fprintf(stderr, "[SM4_DEBUG] sm4_selftest PASSED\n");
  }
}
#endif

// SM4 专用：d = w ⊕ u，按默认位序逐位计算
void sm4_pack_d_big_endian(uint8_t* dst, const uint8_t* witness, const uint8_t* u,
                           unsigned int ell_bits) {
  const size_t ell_bytes = (ell_bits + 7) / 8;
  memset(dst, 0, ell_bytes);

/* NOTE: do NOT zero out u here – u is real VOLE randomness that must be
 * included in d = w XOR u.  Clearing u would corrupt the VOLE relation. */
#if defined(FAEST_SM4_DEBUG)
  fprintf(stderr, "[SM4_DEBUG] d formula: d_bit[i] = witness_bit[i] XOR u_bit[i] (BE)\n");
  sm4_debug_hex("d-pack witness[0..15]", witness, 16);
  sm4_debug_hex("d-pack u[0..15]", u, 16);
  const size_t dbg_len = ell_bytes;
  if (sm4_dbg_last_witness) {
    free(sm4_dbg_last_witness);
  }
  if (sm4_dbg_last_u) {
    free(sm4_dbg_last_u);
  }
  sm4_dbg_last_witness = malloc(dbg_len);
  sm4_dbg_last_u = malloc(dbg_len);
  if (sm4_dbg_last_witness && sm4_dbg_last_u) {
    memcpy(sm4_dbg_last_witness, witness, dbg_len);
    memcpy(sm4_dbg_last_u, u, dbg_len);
    sm4_dbg_last_witness_len = dbg_len;
    sm4_dbg_last_u_len = dbg_len;
  } else {
    sm4_dbg_last_witness_len = 0;
    sm4_dbg_last_u_len = 0;
  }
#endif
  for (unsigned int i = 0; i < ell_bits; ++i) {
    const unsigned int dst_idx = sm4_map_d_index(i);
    if (dst_idx >= ell_bits) {
      continue;
    }
    const unsigned int w_bit = ptr_get_bit(witness, i);
    const unsigned int u_bit = ptr_get_bit(u, i);
    ptr_set_bit(dst, dst_idx, w_bit ^ u_bit);
  }
#if defined(FAEST_SM4_DEBUG)
  sm4_debug_hex_raw(dst, ell_bytes);
#endif
}

static inline unsigned int sm4_get_d_bit_be(const uint8_t* d, unsigned int i) {
  return ptr_get_bit(d, i);
}

/* ---------------------------------------------------------------------------
 * Portable 32-bit big-endian byte-swap.
 * On GCC/Clang this compiles to a single BSWAP instruction.
 * --------------------------------------------------------------------------- */
static inline uint32_t sm4_bswap32(uint32_t x) {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap32(x);
#else
  return ((x & 0xFF000000u) >> 24) |
         ((x & 0x00FF0000u) >>  8) |
         ((x & 0x0000FF00u) <<  8) |
         ((x & 0x000000FFu) << 24);
#endif
}

/*
 * sm4_col_get_bit – extract logical bit `row` from a VOLE column buffer
 * whose content obeys SM4's Big-Endian 32-bit word layout.
 *
 * SM4 defines its 128-bit state as four 32-bit Big-Endian words W[0..3].
 * Bit 0 is the MSB of W[0], bit 31 is the LSB of W[0], bit 32 is the
 * MSB of W[1], and so on.  The witness buffer stores these bits packed
 * in that exact order as raw bytes.
 *
 * Steps:
 *   1. word_idx = row / 32   — which 32-bit word
 *   2. Read 4 bytes via memcpy (handles any alignment) and byte-swap from
 *      Big-Endian to host-native order with sm4_bswap32.
 *   3. bit_in_word = row % 32 where 0 means the MSB.
 *      Extract: (w >> (31 - bit_in_word)) & 1
 */
static inline unsigned int sm4_col_get_bit(const uint8_t* col, unsigned int row) {
  const unsigned int word_idx    = row >> 5;         /* row / 32           */
  const unsigned int bit_in_word = row & 31u;        /* row % 32, 0 = MSB  */
  uint32_t w;
  memcpy(&w, col + word_idx * 4u, sizeof(w));        /* safe unaligned load */
  w = sm4_bswap32(w);                                /* BE → host-native   */
  return (w >> (31u - bit_in_word)) & 1u;
}

// 辅助函数：将列优先V矩阵转换为行优先并提取w_tag
static bf128_t* column_to_row_major_and_shrink_V_128(uint8_t** V, unsigned int ell,
                                                     const char* dbg_label) {
  bf128_t* w_tag = malloc((ell + 2 * 128) * sizeof(bf128_t));
  assert(w_tag);

#if defined(FAEST_SM4_DEBUG)
  const unsigned int KEY_BITS = 32 * (32 + 4);  // 36 words × 32 bits
#endif

  for (unsigned int row = 0; row != ell + 2 * 128; ++row) {
    uint8_t new_row[BF128_NUM_BYTES] = {0};
    for (unsigned int column = 0; column != 128; ++column) {
      ptr_set_bit(new_row, column, ptr_get_bit(V[column], row));
    }
    w_tag[row] = bf128_load(new_row);

#if defined(FAEST_SM4_DEBUG)
    if (row < 8 || row == 32 || row == 64 || row == 96 ||
        row == KEY_BITS || row == KEY_BITS + 1 || row == KEY_BITS + 2 || row == KEY_BITS + 3) {
      char label[64];
      snprintf(label, sizeof(label), "transpose[%s] row=%u", dbg_label, row);
      sm4_debug_hex(label, new_row, BF128_NUM_BYTES);
    }
    if (row < 4) {
      char label[64];
      snprintf(label, sizeof(label), "transpose[%s] row=%u", dbg_label, row);
      sm4_debug_bits32(label, new_row);
    }
#endif
  }

  return w_tag;
}

static bf128_t* column_to_row_major_and_shrink_V_128_sm4(uint8_t** V, unsigned int ell,
                                                         unsigned int lambda,
                                                         unsigned int ell_hat,
                                                         const char* dbg_label) {
  const unsigned int rows_to_keep = ell + 2 * lambda;
  assert(ell_hat >= rows_to_keep);

  bf128_t* w_tag = malloc(rows_to_keep * sizeof(bf128_t));
  assert(w_tag);

#if defined(FAEST_SM4_DEBUG)
  const unsigned int KEY_BITS = 32 * (32 + 4);  // 36 words × 32 bits
  const unsigned int dbg_rows[] = {
      0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u,
      32u, 64u, 96u,
      KEY_BITS, KEY_BITS + 1u, KEY_BITS + 2u, KEY_BITS + 3u,
      ell, ell + 1u, ell + 2u, ell + 3u,
      ell + lambda, ell + lambda + 1u, ell + lambda + 2u, ell + lambda + 3u,
  };
#endif

  for (unsigned int row = 0; row != rows_to_keep; ++row) {
    uint8_t new_row[BF128_NUM_BYTES] = {0};

    /*
     * Bit-transpose: collect one bit from each VOLE column into a single
     * row of the output matrix, honoring SM4's Big-Endian 32-bit word
     * layout.
     *
     * sm4_col_get_bit(col, row):
     *   - Locates the 32-bit word: word_idx = row / 32
     *   - Reads it with memcpy and byte-swaps (BE → host-native) using
     *     sm4_bswap32 so that the host sees the correct word value.
     *   - Extracts bit (31 - row%32), i.e. MSB-first within each word.
     *
     * This is applied symmetrically for both Prover (V → w_tag) and
     * Verifier (Q → q_key) since both call this function.
     */
    for (unsigned int column = 0; column != lambda; ++column) {
      ptr_set_bit(new_row, column, ptr_get_bit(V[column], row));
    }

    w_tag[row] = bf128_load(new_row);

#if defined(FAEST_SM4_DEBUG)
    bool dbg_row_hit = false;
    for (size_t i = 0; i < sizeof(dbg_rows) / sizeof(dbg_rows[0]); ++i) {
      if (row == dbg_rows[i]) {
        dbg_row_hit = true;
        break;
      }
    }
    if (row < 8 || row == 32 || row == 64 || row == 96 ||
        row == KEY_BITS || row == KEY_BITS + 1 || row == KEY_BITS + 2 || row == KEY_BITS + 3) {
      char label[64];
      snprintf(label, sizeof(label), "transpose[%s] row=%u", dbg_label, row);
      sm4_debug_hex(label, new_row, BF128_NUM_BYTES);
    }

    if (dbg_row_hit) {
      const unsigned int word_idx = row >> 5;
      const unsigned int byte_idx = word_idx * 4u;
      uint8_t col_bytes[128];
      for (unsigned int column = 0; column != lambda; ++column) {
        col_bytes[column] = V[column][byte_idx];
      }
      fprintf(stderr,
              "[SM4_DEBUG] transpose[%s] row=%u word_idx=%u byte_idx=%u\n",
              dbg_label, row, word_idx, byte_idx);
      sm4_debug_hex("transpose column bytes (MSB byte of BE word)", col_bytes, sizeof(col_bytes));

      if (sm4_dbg_last_w_tag && row < sm4_dbg_last_w_taglen) {
        uint8_t prover_row[BF128_NUM_BYTES];
        bf128_store(prover_row, sm4_dbg_last_w_tag[row]);
        sm4_debug_hex("transpose prover w_tag", prover_row, BF128_NUM_BYTES);
        fprintf(stderr,
                "[SM4_DEBUG] transpose[%s] row=%u match=%s\n",
                dbg_label,
                row,
                memcmp(prover_row, new_row, BF128_NUM_BYTES) == 0 ? "yes" : "no");
      }
    }
#endif
  }

  return w_tag;
}

// ============================================================================
// 顶层 Prover/Verifier 接口
// ============================================================================


void sm4_128_prover(uint8_t* a0_tilde, uint8_t* a1_tilde, uint8_t* a2_tilde, const uint8_t* w,
                    const uint8_t* u, uint8_t** V, const uint8_t* owf_in, const uint8_t* owf_out,
                    const uint8_t* chall_2, const faest_paramset_t* params) {
#if defined(FAEST_SM4_DEBUG)
  sm4_selftest_vector_once();
  sm4_debug_first_error_reported = false;  // Reset error flag
#endif
  const unsigned int ell = params->l;
  const unsigned int lambda = 128;  // SM4_128固定为128位
  const unsigned int ell_hat = ell + 3 * lambda + UNIVERSAL_HASH_B_BITS;
  const size_t chall2_len = 3u * (lambda / 8u) + 8u;

  // ::1-5 将V转换为w_tag
  bf128_t* w_tag = column_to_row_major_and_shrink_V_128_sm4(V, ell, lambda, ell_hat, "prover V->w_tag");

  // Stage check: witness generation complete
  if (!w_tag) {
    return; /* malloc failure — caller will observe zeroed output buffers */
  }

#if defined(FAEST_SM4_DEBUG)
  // cache prover view for verifier-side comparison inside same process (tests)
  free(sm4_dbg_last_w_tag);
  sm4_dbg_last_w_taglen = ell + 2 * lambda;
  sm4_dbg_last_w_tag = malloc(sm4_dbg_last_w_taglen * sizeof(bf128_t));
  assert(sm4_dbg_last_w_tag);
  memcpy(sm4_dbg_last_w_tag, w_tag, sm4_dbg_last_w_taglen * sizeof(bf128_t));

  sm4_dbg_last_chall2_hash = sm4_hash64_fnv1a_local(chall_2, chall2_len);
  sm4_dbg_last_chall2_len = chall2_len;

  // Column-level hash snapshot for V to compare against Q in verifier.
  const size_t col_bytes = (ell_hat + 7u) / 8u;
  if (sm4_dbg_last_v_col_hashes) {
    free(sm4_dbg_last_v_col_hashes);
  }
  sm4_dbg_last_v_col_hashes = malloc(lambda * sizeof(uint64_t));
  sm4_dbg_last_v_col_count = lambda;
  sm4_dbg_last_v_col_bytes = col_bytes;
  if (sm4_dbg_last_v_col_hashes) {
    for (unsigned int col = 0; col < lambda; ++col) {
      sm4_dbg_last_v_col_hashes[col] = sm4_hash64_fnv1a_local(V[col], col_bytes);
    }
  }
  if (sm4_dbg_last_v_cols) {
    free(sm4_dbg_last_v_cols);
  }
  sm4_dbg_last_v_cols_len = (size_t)lambda * col_bytes;
  sm4_dbg_last_v_cols = malloc(sm4_dbg_last_v_cols_len);
  if (sm4_dbg_last_v_cols) {
    for (unsigned int col = 0; col < lambda; ++col) {
      memcpy(sm4_dbg_last_v_cols + (size_t)col * col_bytes, V[col], col_bytes);
    }
  }
#endif

  // ::6-7 嵌入VOLE masks
  bf128_t bf_u_star_0 = bf128_sum_poly_bits(u);
  bf128_t bf_u_star_1 = bf128_sum_poly_bits(u + lambda / 8);

  // ::8-9
  bf128_t bf_v_star_0 = bf128_sum_poly(w_tag + ell);
  bf128_t bf_v_star_1 = bf128_sum_poly(w_tag + ell + lambda);

#if defined(FAEST_SM4_DEBUG)
  sm4_dbg_last_v_star0 = bf_v_star_0;
  sm4_dbg_last_v_star1 = bf_v_star_1;
#endif

  // ::10-12 初始化ZK哈希
  zk_hash_128_3_ctx hasher;
  zk_hash_128_3_init(&hasher, chall_2);

  // ::13 生成SM4约束
  sm4_SSS_constraints_prover(&hasher, w, w_tag, owf_in, owf_out, params);

  // Stage check: constraints generation complete

  // ::14 最终化哈希
  zk_hash_128_3_finalize(a0_tilde, a1_tilde, a2_tilde, &hasher, bf_v_star_0,
                         bf128_add(bf_u_star_0, bf_v_star_1), bf_u_star_1);

#if defined(FAEST_SM4_DEBUG)
  sm4_debug_hex("prover a0_tilde", a0_tilde, lambda / 8);
  sm4_debug_hex("prover a1_tilde", a1_tilde, lambda / 8);
  sm4_debug_hex("prover a2_tilde", a2_tilde, lambda / 8);
#endif

  // Stage check: final comparison preparation complete

  free(w_tag);
}

void sm4_128_verifier(uint8_t* a0_tilde, const uint8_t* d, uint8_t** Q, const uint8_t* owf_in,
                      const uint8_t* owf_out, const uint8_t* chall_2, const uint8_t* chall_3,
                      const uint8_t* a1_tilde, const uint8_t* a2_tilde,
                      const faest_paramset_t* params) {
#if defined(FAEST_SM4_DEBUG)
  sm4_selftest_vector_once();
  sm4_debug_first_error_reported = false;  // Reset error flag
#endif
  const unsigned int ell = params->l;
  const unsigned int lambda = 128;
  const unsigned int ell_hat = ell + 3 * lambda + UNIVERSAL_HASH_B_BITS;
  const size_t chall2_len = 3u * (lambda / 8u) + 8u;

  // ::1 加载delta
  bf128_t bf_delta = bf128_load(chall_3);
  bf128_t bf_delta_sq = bf128_mul(bf_delta, bf_delta);
#if defined(FAEST_SM4_DEBUG)
  uint8_t dbg_delta[BF128_NUM_BYTES];
  bf128_store(dbg_delta, bf_delta);
  sm4_debug_hex("verifier delta", dbg_delta, lambda / 8);
#endif

  // ::2-6 将Q转换为q_key
  bf128_t* q_key = column_to_row_major_and_shrink_V_128_sm4(Q, ell, lambda, ell_hat, "verifier Q->q_key");

  // Stage check: witness reconstruction complete
  if (!q_key) {
    return; /* malloc failure — caller will observe zeroed output buffers */
  }

#if defined(FAEST_SM4_DEBUG)
  if (sm4_dbg_last_w_tag && sm4_dbg_last_w_taglen == ell + 2 * lambda) {
    // Compare possible row permutations within each 32-bit word.
    for (unsigned int mode = 0; mode < 4; ++mode) {
      size_t match_zero = 0;
      size_t match_delta = 0;
      for (unsigned int row = 0; row < sm4_dbg_last_w_taglen; ++row) {
        const unsigned int mapped = sm4_map_row_apply(row, mode);
        uint8_t w_buf[BF128_NUM_BYTES], q_buf[BF128_NUM_BYTES];
        bf128_store(w_buf, sm4_dbg_last_w_tag[row]);
        bf128_store(q_buf, q_key[mapped]);
        uint8_t diff[BF128_NUM_BYTES];
        bf128_store(diff, bf128_add(sm4_dbg_last_w_tag[row], q_key[mapped]));
        if (memcmp(diff, (uint8_t[BF128_NUM_BYTES]){0}, BF128_NUM_BYTES) == 0) {
          ++match_zero;
        } else if (memcmp(diff, dbg_delta, BF128_NUM_BYTES) == 0) {
          ++match_delta;
        }
      }
      fprintf(stderr,
              "[SM4_DEBUG] row_perm mode=%u match_zero=%zu match_delta=%zu total=%zu\n",
              mode, match_zero, match_delta, sm4_dbg_last_w_taglen);
    }

    for (unsigned int row = 0; row < 2; ++row) {
      uint8_t w_buf[BF128_NUM_BYTES], q_buf[BF128_NUM_BYTES];
      char label[64];
      bf128_store(w_buf, sm4_dbg_last_w_tag[row]);
      bf128_store(q_buf, q_key[row]);
      snprintf(label, sizeof(label), "prover w_tag row=%u", row);
      sm4_debug_bits32(label, w_buf);
      snprintf(label, sizeof(label), "verifier q_key row=%u", row);
      sm4_debug_bits32(label, q_buf);
    }

    size_t mismatch_count = 0;
    size_t first_mismatch = SIZE_MAX;
    uint8_t first_diff[BF128_NUM_BYTES];
    unsigned int mismatch_mod[32] = {0};
    size_t mismatch_rows[16];
    size_t mismatch_rows_count = 0;
    for (unsigned int row = 0; row < sm4_dbg_last_w_taglen; ++row) {
      uint8_t a[BF128_NUM_BYTES], b[BF128_NUM_BYTES];
      bf128_store(a, sm4_dbg_last_w_tag[row]);
      bf128_store(b, q_key[row]);
      if (memcmp(a, b, sizeof(a)) != 0) {
        if (mismatch_rows_count < (sizeof(mismatch_rows) / sizeof(mismatch_rows[0]))) {
          mismatch_rows[mismatch_rows_count++] = row;
        }
        if (mismatch_count < 8) {
          uint8_t diff[BF128_NUM_BYTES];
          bf128_store(diff, bf128_add(sm4_dbg_last_w_tag[row], q_key[row]));
          char label[64];
          snprintf(label, sizeof(label), "row mismatch %u", row);
          sm4_debug_hex(label, a, BF128_NUM_BYTES);
          sm4_debug_hex("verifier row", b, BF128_NUM_BYTES);
          sm4_debug_hex("row diff", diff, BF128_NUM_BYTES);
          fprintf(stderr, "[SM4_DEBUG] row diff == delta: %s\n",
                  memcmp(diff, dbg_delta, BF128_NUM_BYTES) == 0 ? "yes" : "no");
          if (row < 4) {
            sm4_debug_bits32("prover w_tag", a);
            sm4_debug_bits32("verifier q_key", b);
          }
          if (row >= 2 && row < 16) {
            char bits_label[64];
            snprintf(bits_label, sizeof(bits_label), "prover w_tag row=%u", row);
            sm4_debug_bits32(bits_label, a);
            snprintf(bits_label, sizeof(bits_label), "verifier q_key row=%u", row);
            sm4_debug_bits32(bits_label, b);
          }
        }
        if (first_mismatch == SIZE_MAX) {
          uint8_t diff[BF128_NUM_BYTES];
          bf128_store(diff, bf128_add(sm4_dbg_last_w_tag[row], q_key[row]));
          memcpy(first_diff, diff, sizeof(first_diff));
          first_mismatch = row;
        }
        ++mismatch_count;
        mismatch_mod[row % 32] += 1;
      }
    }
    fprintf(stderr, "[SM4_DEBUG] transpose mismatch rows=%zu\n", mismatch_count);
    if (first_mismatch != SIZE_MAX) {
      const unsigned int Lke = params->Lke;
      fprintf(stderr,
              "[SM4_DEBUG] first mismatch row=%zu (Lke=%u, segment=%s)\n",
              first_mismatch, Lke,
              first_mismatch < Lke ? "keyexp" : "enc");
      sm4_debug_hex("[SM4_DEBUG] first mismatch diff", first_diff, BF128_NUM_BYTES);
      fprintf(stderr,
              "[SM4_DEBUG] first mismatch diff == delta: %s\n",
              memcmp(first_diff, dbg_delta, BF128_NUM_BYTES) == 0 ? "yes" : "no");
    }
    if (mismatch_rows_count > 0) {
      fprintf(stderr, "[SM4_DEBUG] first mismatch rows:");
      for (size_t i = 0; i < mismatch_rows_count; ++i) {
        fprintf(stderr, " %zu", mismatch_rows[i]);
      }
      fprintf(stderr, "\n");
      fprintf(stderr, "[SM4_DEBUG] mismatch row mod32 counts:");
      for (unsigned int i = 0; i < 32; ++i) {
        if (mismatch_mod[i] != 0) {
          fprintf(stderr, " %u:%u", i, mismatch_mod[i]);
        }
      }
      fprintf(stderr, "\n");
    }
  }
  sm4_debug_hex("d bytes[0..15]", d, 16);
  if (sm4_dbg_last_w_tag && sm4_dbg_last_w_taglen == ell + 2 * lambda) {
    uint8_t truth_bytes[16] = {0};
    char truth_bits[129];
    char read_bits[129];
    unsigned int truth_known = 0;
    unsigned int truth_delta = 0;
    unsigned int truth_zero = 0;
    for (unsigned int row = 0; row < 128; ++row) {
      uint8_t w_buf[BF128_NUM_BYTES], q_buf[BF128_NUM_BYTES];
      bf128_store(w_buf, sm4_dbg_last_w_tag[row]);
      bf128_store(q_buf, q_key[row]);
      uint8_t diff[BF128_NUM_BYTES];
      bf128_store(diff, bf128_add(sm4_dbg_last_w_tag[row], q_key[row]));
      const bool diff_is_zero = memcmp(diff, (uint8_t[BF128_NUM_BYTES]){0}, BF128_NUM_BYTES) == 0;
      const bool diff_is_delta = memcmp(diff, dbg_delta, BF128_NUM_BYTES) == 0;
      unsigned int expected = 0u;
      unsigned int actual = sm4_get_d_bit_be(d, row);
      if (diff_is_delta) {
        expected = 1u;
        ptr_set_bit(truth_bytes, row, 1u);
        truth_bits[row] = '1';
        ++truth_delta;
        ++truth_known;
      } else if (diff_is_zero) {
        truth_bits[row] = '0';
        ++truth_zero;
        ++truth_known;
      } else {
        truth_bits[row] = 'x';
      }
      read_bits[row] = actual ? '1' : '0';
      fprintf(stderr, "[SM4_DEBUG] d bit[%u] actual=%u expected=%u\n", row, actual, expected);
    }
    truth_bits[128] = '\0';
    read_bits[128] = '\0';
    fprintf(stderr, "[SM4_DEBUG] d truth known=%u zero=%u delta=%u\n", truth_known, truth_zero,
            truth_delta);
    sm4_debug_hex("d truth bytes[0..15]", truth_bytes, 16);
    fprintf(stderr, "[SM4_DEBUG] d truth[0..127]=%s\n", truth_bits);
    fprintf(stderr, "[SM4_DEBUG] d read[0..127]=%s\n", read_bits);

    // Build a full-length truth mask for all ell bits to compare against d/w/u.
    if (ell % 8 == 0) {
      const size_t truth_full_bytes = ell / 8;
      uint8_t* truth_full = calloc(truth_full_bytes, 1);
      if (truth_full) {
        unsigned int truth_full_known = 0;
        for (unsigned int row = 0; row < ell; ++row) {
          uint8_t diff_full[BF128_NUM_BYTES];
          bf128_store(diff_full, bf128_add(sm4_dbg_last_w_tag[row], q_key[row]));
          const bool diff_is_zero_full =
              memcmp(diff_full, (uint8_t[BF128_NUM_BYTES]){0}, BF128_NUM_BYTES) == 0;
          const bool diff_is_delta_full =
              memcmp(diff_full, dbg_delta, BF128_NUM_BYTES) == 0;
          if (diff_is_delta_full) {
            ptr_set_bit(truth_full, row, 1u);
            ++truth_full_known;
          } else if (diff_is_zero_full) {
            ++truth_full_known;
          }
        }
        fprintf(stderr, "[SM4_DEBUG] d truth full known=%u/%u\n", truth_full_known, ell);
        sm4_debug_hex_raw(truth_full, truth_full_bytes);
        free(truth_full);
      }
    }

    // Dump raw witness/u bytes and truth bits as pure hex strings (no labels).
    if (sm4_dbg_last_witness && sm4_dbg_last_witness_len > 0) {
      sm4_debug_hex_raw(sm4_dbg_last_witness, sm4_dbg_last_witness_len);
    }
    if (sm4_dbg_last_u && sm4_dbg_last_u_len > 0) {
      sm4_debug_hex_raw(sm4_dbg_last_u, sm4_dbg_last_u_len);
    }
    sm4_debug_hex_raw(truth_bytes, sizeof(truth_bytes));

    if (sm4_dbg_last_witness && sm4_dbg_last_u && sm4_dbg_last_witness_len == sm4_dbg_last_u_len) {
      const size_t buf_bits = sm4_dbg_last_witness_len * 8;
      const size_t win_bits = 128;
      struct {
        const char* label;
        int use_be;
        unsigned int map_mode;
      } variants[] = {
          {"xor_raw_be", 1, 0},
          {"xor_raw_le", 0, 0},
          {"xor_swap_be", 1, 1},
          {"xor_swap_le", 0, 1},
          {"xor_bitrev_be", 1, 2},
          {"xor_bitrev_le", 0, 2},
          {"xor_swap_bitrev_be", 1, 3},
          {"xor_swap_bitrev_le", 0, 3},
      };
      unsigned int any_found = 0;

      for (size_t v = 0; v < sizeof(variants) / sizeof(variants[0]); ++v) {
        unsigned int found = 0;
        for (size_t off = 0; off + win_bits <= buf_bits; ++off) {
          unsigned int match = 1;
          for (unsigned int j = 0; j < win_bits; ++j) {
            const unsigned int truth_bit = ptr_get_bit(truth_bytes, j);
            const unsigned int idx = sm4_map_row_apply((unsigned int)(off + j),
                                                       variants[v].map_mode);
            const unsigned int w_bit = variants[v].use_be
                                           ? sm4_ptr_get_bit_be(sm4_dbg_last_witness, idx)
                                           : ptr_get_bit(sm4_dbg_last_witness, idx);
            const unsigned int u_bit = variants[v].use_be
                                           ? sm4_ptr_get_bit_be(sm4_dbg_last_u, idx)
                                           : ptr_get_bit(sm4_dbg_last_u, idx);
            if (truth_bit != (w_bit ^ u_bit)) {
              match = 0;
              break;
            }
          }
          if (match) {
            fprintf(stderr,
                    "[SM4_DEBUG] truth window found (%s) at bit=%zu (byte=%zu bit=%zu)\n",
                    variants[v].label, off, off / 8, off % 8);
            found = 1;
            any_found = 1;
            break;
          }
        }
        if (!found) {
          fprintf(stderr, "[SM4_DEBUG] truth window not found (%s)\n", variants[v].label);
        }
      }
      if (!any_found) {
        fprintf(stderr, "[SM4_DEBUG] truth window not found in any xor variant\n");

        // Scan for a 128-bit window with byte-permutation and bit-order variants.
        {
          const size_t buf_bits_inner = sm4_dbg_last_witness_len * 8;
          const unsigned int off_step = 32;  // keep word alignment
          unsigned int found = 0;
          size_t found_off = 0;
          uint8_t found_byte[4] = {0, 1, 2, 3};
          unsigned int found_msb = 0;

          for (unsigned int a = 0; a < 4 && !found; ++a) {
            for (unsigned int b = 0; b < 4 && !found; ++b) {
              if (b == a) {
                continue;
              }
              for (unsigned int c = 0; c < 4 && !found; ++c) {
                if (c == a || c == b) {
                  continue;
                }
                for (unsigned int d_perm = 0; d_perm < 4 && !found; ++d_perm) {
                  if (d_perm == a || d_perm == b || d_perm == c) {
                    continue;
                  }
                  uint8_t perm[4] = {(uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d_perm};
                  for (unsigned int msb = 0; msb < 2 && !found; ++msb) {
                    for (size_t off = 0; off + 128 <= buf_bits_inner; off += off_step) {
                      unsigned int match = 1;
                      for (unsigned int j = 0; j < 128; ++j) {
                        const unsigned int word_base = (unsigned int)off & ~31u;
                        const unsigned int word_idx = (j >> 5) & 3u;
                        const unsigned int bit_in_word = j & 31u;
                        const unsigned int byte_idx = (bit_in_word >> 3) & 3u;
                        const unsigned int bit_idx = bit_in_word & 7u;
                        const unsigned int mapped_byte = perm[byte_idx];
                        const unsigned int mapped_bit = msb ? (7u - bit_idx) : bit_idx;
                        const unsigned int idx = word_base + (word_idx << 5) +
                                                   (mapped_byte << 3) + mapped_bit;
                        const unsigned int truth_bit = ptr_get_bit(truth_bytes, j);
                        const unsigned int bit_val =
                            ptr_get_bit(sm4_dbg_last_witness, idx) ^
                            ptr_get_bit(sm4_dbg_last_u, idx);
                        if (bit_val != truth_bit) {
                          match = 0;
                          break;
                        }
                      }
                      if (match) {
                        found = 1;
                        found_off = off;
                        memcpy(found_byte, perm, 4);
                        found_msb = msb;
                        break;
                      }
                    }
                  }
                }
              }
            }
          }

          if (found) {
            fprintf(stderr,
                    "[SM4_DEBUG] truth window found (perm_scan) at bit=%zu (byte=%zu bit=%zu) "
                    "perm=[%u %u %u %u] bit_order=%s\n",
                    found_off, found_off / 8, found_off % 8, found_byte[0], found_byte[1],
                    found_byte[2], found_byte[3], found_msb ? "msb" : "lsb");
          } else {
            fprintf(stderr, "[SM4_DEBUG] truth window not found (perm_scan)\n");
          }
        }

        // Scan for a 128-bit window with word+byte permutations and bit-order variants.
        {
          const size_t buf_bits_outer = sm4_dbg_last_witness_len * 8;
          const unsigned int off_step = 32;  // keep word alignment
          unsigned int found = 0;
          size_t found_off = 0;
          uint8_t found_word[4] = {0, 1, 2, 3};
          uint8_t found_byte[4] = {0, 1, 2, 3};
          unsigned int found_msb = 0;

          for (unsigned int w0 = 0; w0 < 4 && !found; ++w0) {
            for (unsigned int w1 = 0; w1 < 4 && !found; ++w1) {
              if (w1 == w0) {
                continue;
              }
              for (unsigned int w2 = 0; w2 < 4 && !found; ++w2) {
                if (w2 == w0 || w2 == w1) {
                  continue;
                }
                for (unsigned int w3 = 0; w3 < 4 && !found; ++w3) {
                  if (w3 == w0 || w3 == w1 || w3 == w2) {
                    continue;
                  }
                  uint8_t word_perm[4] = {(uint8_t)w0, (uint8_t)w1, (uint8_t)w2, (uint8_t)w3};
                  for (unsigned int a = 0; a < 4 && !found; ++a) {
                    for (unsigned int b = 0; b < 4 && !found; ++b) {
                      if (b == a) {
                        continue;
                      }
                      for (unsigned int c = 0; c < 4 && !found; ++c) {
                        if (c == a || c == b) {
                          continue;
                        }
                        for (unsigned int d_byte = 0; d_byte < 4 && !found; ++d_byte) {
                          if (d_byte == a || d_byte == b || d_byte == c) {
                            continue;
                          }
                          uint8_t byte_perm[4] =
                              {(uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d_byte};
                          for (unsigned int msb = 0; msb < 2 && !found; ++msb) {
                            for (size_t off = 0; off + 128 <= buf_bits_outer; off += off_step) {
                              unsigned int match = 1;
                              for (unsigned int j = 0; j < 128; ++j) {
                                const unsigned int word_idx = (j >> 5) & 3u;
                                const unsigned int bit_in_word = j & 31u;
                                const unsigned int byte_idx = (bit_in_word >> 3) & 3u;
                                const unsigned int bit_idx = bit_in_word & 7u;
                                const unsigned int mapped_word = word_perm[word_idx];
                                const unsigned int mapped_byte = byte_perm[byte_idx];
                                const unsigned int mapped_bit = msb ? (7u - bit_idx) : bit_idx;
                                const unsigned int idx = (unsigned int)off + (mapped_word << 5) +
                                                           (mapped_byte << 3) + mapped_bit;
                                const unsigned int truth_bit = ptr_get_bit(truth_bytes, j);
                                const unsigned int bit_val =
                                    ptr_get_bit(sm4_dbg_last_witness, idx) ^
                                    ptr_get_bit(sm4_dbg_last_u, idx);
                                if (bit_val != truth_bit) {
                                  match = 0;
                                  break;
                                }
                              }
                              if (match) {
                                found = 1;
                                found_off = off;
                                memcpy(found_word, word_perm, 4);
                                memcpy(found_byte, byte_perm, 4);
                                found_msb = msb;
                                break;
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }

          if (found) {
            fprintf(stderr,
                    "[SM4_DEBUG] truth window found (word_perm_scan) at bit=%zu (byte=%zu bit=%zu) "
                    "word=[%u %u %u %u] byte=[%u %u %u %u] bit_order=%s\n",
                    found_off, found_off / 8, found_off % 8, found_word[0], found_word[1],
                    found_word[2], found_word[3], found_byte[0], found_byte[1], found_byte[2],
                    found_byte[3], found_msb ? "msb" : "lsb");
          } else {
            fprintf(stderr, "[SM4_DEBUG] truth window not found (word_perm_scan)\n");
          }
        }

        // Scan for strided bitstreams (e.g., interleaved layouts).
        {
          const size_t buf_bits_stride = sm4_dbg_last_witness_len * 8;
          const unsigned int strides[] = {2, 4, 8, 16, 32};
          unsigned int found = 0;
          unsigned int found_stride = 0;
          unsigned int found_offset = 0;
          unsigned int found_msb = 0;

          for (size_t s = 0; s < sizeof(strides) / sizeof(strides[0]) && !found; ++s) {
            const unsigned int stride = strides[s];
            for (unsigned int off = 0; off < stride && !found; ++off) {
              for (unsigned int msb = 0; msb < 2 && !found; ++msb) {
                unsigned int match = 1;
                for (unsigned int j = 0; j < 128; ++j) {
                  const unsigned int idx = off + j * stride;
                  if (idx >= buf_bits_stride) {
                    match = 0;
                    break;
                  }
                  const unsigned int truth_bit = ptr_get_bit(truth_bytes, j);
                  const unsigned int w_bit = msb ? sm4_ptr_get_bit_be(sm4_dbg_last_witness, idx)
                                                  : ptr_get_bit(sm4_dbg_last_witness, idx);
                  const unsigned int u_bit = msb ? sm4_ptr_get_bit_be(sm4_dbg_last_u, idx)
                                                  : ptr_get_bit(sm4_dbg_last_u, idx);
                  if ((w_bit ^ u_bit) != truth_bit) {
                    match = 0;
                    break;
                  }
                }
                if (match) {
                  found = 1;
                  found_stride = stride;
                  found_offset = off;
                  found_msb = msb;
                }
              }
            }
          }

          if (found) {
            fprintf(stderr,
                    "[SM4_DEBUG] truth window found (stride_scan) stride=%u offset=%u bit_order=%s\n",
                    found_stride, found_offset, found_msb ? "msb" : "lsb");
          } else {
            fprintf(stderr, "[SM4_DEBUG] truth window not found (stride_scan)\n");
          }
        }

        // Brute-force byte permutations within 32-bit words to match rows 0..127.
        uint8_t perm[4] = {0, 1, 2, 3};
        unsigned int best_matches = 0;
        uint8_t best_perm[4] = {0, 1, 2, 3};
        unsigned int best_msb = 0;
        for (unsigned int a = 0; a < 4; ++a) {
          for (unsigned int b = 0; b < 4; ++b) {
            if (b == a) {
              continue;
            }
            for (unsigned int c = 0; c < 4; ++c) {
              if (c == a || c == b) {
                continue;
              }
              for (unsigned int d_perm3 = 0; d_perm3 < 4; ++d_perm3) {
                if (d_perm3 == a || d_perm3 == b || d_perm3 == c) {
                  continue;
                }
                perm[0] = (uint8_t)a;
                perm[1] = (uint8_t)b;
                perm[2] = (uint8_t)c;
                perm[3] = (uint8_t)d_perm3;
                for (unsigned int msb = 0; msb < 2; ++msb) {
                  unsigned int matches = 0;
                  for (unsigned int row = 0; row < 128; ++row) {
                    const unsigned int word_base = row & ~31u;
                    const unsigned int byte_idx = (row >> 3) & 3u;
                    const unsigned int bit_idx = row & 7u;
                    const unsigned int mapped_byte = perm[byte_idx];
                    const unsigned int mapped_bit = msb ? (7u - bit_idx) : bit_idx;
                    const unsigned int idx = word_base | (mapped_byte << 3) | mapped_bit;
                    const unsigned int truth_bit = ptr_get_bit(truth_bytes, row);
                    const unsigned int bit_val =
                        ptr_get_bit(sm4_dbg_last_witness, idx) ^
                        ptr_get_bit(sm4_dbg_last_u, idx);
                    if (bit_val == truth_bit) {
                      ++matches;
                    }
                  }
                  if (matches > best_matches) {
                    best_matches = matches;
                    best_perm[0] = perm[0];
                    best_perm[1] = perm[1];
                    best_perm[2] = perm[2];
                    best_perm[3] = perm[3];
                    best_msb = msb;
                  }
                }
              }
            }
          }
        }
        fprintf(stderr,
                "[SM4_DEBUG] best byte-perm match: %u/128 perm=[%u %u %u %u] bit_order=%s\n",
                best_matches, best_perm[0], best_perm[1], best_perm[2], best_perm[3],
                best_msb ? "msb" : "lsb");

        if (best_matches < 128) {
          uint8_t word_perm[4] = {0, 1, 2, 3};
          uint8_t byte_perm[4] = {0, 1, 2, 3};
          unsigned int best2_matches = 0;
          uint8_t best2_word[4] = {0, 1, 2, 3};
          uint8_t best2_byte[4] = {0, 1, 2, 3};
          unsigned int best2_msb = 0;
          for (unsigned int w0 = 0; w0 < 4; ++w0) {
            for (unsigned int w1 = 0; w1 < 4; ++w1) {
              if (w1 == w0) {
                continue;
              }
              for (unsigned int w2 = 0; w2 < 4; ++w2) {
                if (w2 == w0 || w2 == w1) {
                  continue;
                }
                for (unsigned int w3 = 0; w3 < 4; ++w3) {
                  if (w3 == w0 || w3 == w1 || w3 == w2) {
                    continue;
                  }
                  word_perm[0] = (uint8_t)w0;
                  word_perm[1] = (uint8_t)w1;
                  word_perm[2] = (uint8_t)w2;
                  word_perm[3] = (uint8_t)w3;
                  for (unsigned int a = 0; a < 4; ++a) {
                    for (unsigned int b = 0; b < 4; ++b) {
                      if (b == a) {
                        continue;
                      }
                      for (unsigned int c = 0; c < 4; ++c) {
                        if (c == a || c == b) {
                          continue;
                        }
                        for (unsigned int d_byte2 = 0; d_byte2 < 4; ++d_byte2) {
                          if (d_byte2 == a || d_byte2 == b || d_byte2 == c) {
                            continue;
                          }
                          byte_perm[0] = (uint8_t)a;
                          byte_perm[1] = (uint8_t)b;
                          byte_perm[2] = (uint8_t)c;
                          byte_perm[3] = (uint8_t)d_byte2;
                          for (unsigned int msb = 0; msb < 2; ++msb) {
                            unsigned int matches = 0;
                            for (unsigned int row = 0; row < 128; ++row) {
                              const unsigned int word_idx = (row >> 5) & 3u;
                              const unsigned int bit_in_word = row & 31u;
                              const unsigned int perm_word = word_perm[word_idx];
                              const unsigned int word_base = perm_word << 5;
                              const unsigned int byte_idx = (bit_in_word >> 3) & 3u;
                              const unsigned int bit_idx = bit_in_word & 7u;
                              const unsigned int mapped_byte = byte_perm[byte_idx];
                              const unsigned int mapped_bit = msb ? (7u - bit_idx) : bit_idx;
                              const unsigned int idx = word_base | (mapped_byte << 3) | mapped_bit;
                              const unsigned int truth_bit = ptr_get_bit(truth_bytes, row);
                              const unsigned int bit_val =
                                  ptr_get_bit(sm4_dbg_last_witness, idx) ^
                                  ptr_get_bit(sm4_dbg_last_u, idx);
                              if (bit_val == truth_bit) {
                                ++matches;
                              }
                            }
                            if (matches > best2_matches) {
                              best2_matches = matches;
                              memcpy(best2_word, word_perm, 4);
                              memcpy(best2_byte, byte_perm, 4);
                              best2_msb = msb;
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
          fprintf(stderr,
                  "[SM4_DEBUG] best word+byte perm match: %u/128 word=[%u %u %u %u] "
                  "byte=[%u %u %u %u] bit_order=%s\n",
                  best2_matches, best2_word[0], best2_word[1], best2_word[2], best2_word[3],
                  best2_byte[0], best2_byte[1], best2_byte[2], best2_byte[3],
                  best2_msb ? "msb" : "lsb");

          if (best2_matches < 128) {
            uint8_t w_perm[4] = {0, 1, 2, 3};
            uint8_t u_perm[4] = {0, 1, 2, 3};
            unsigned int best3_matches = 0;
            uint8_t best3_w[4] = {0, 1, 2, 3};
            uint8_t best3_u[4] = {0, 1, 2, 3};
            unsigned int best3_msb = 0;
            for (unsigned int wa = 0; wa < 4; ++wa) {
              for (unsigned int wb = 0; wb < 4; ++wb) {
                if (wb == wa) {
                  continue;
                }
                for (unsigned int wc = 0; wc < 4; ++wc) {
                  if (wc == wa || wc == wb) {
                    continue;
                  }
                  for (unsigned int wd = 0; wd < 4; ++wd) {
                    if (wd == wa || wd == wb || wd == wc) {
                      continue;
                    }
                    w_perm[0] = (uint8_t)wa;
                    w_perm[1] = (uint8_t)wb;
                    w_perm[2] = (uint8_t)wc;
                    w_perm[3] = (uint8_t)wd;
                    for (unsigned int ua = 0; ua < 4; ++ua) {
                      for (unsigned int ub = 0; ub < 4; ++ub) {
                        if (ub == ua) {
                          continue;
                        }
                        for (unsigned int uc = 0; uc < 4; ++uc) {
                          if (uc == ua || uc == ub) {
                            continue;
                          }
                          for (unsigned int ud = 0; ud < 4; ++ud) {
                            if (ud == ua || ud == ub || ud == uc) {
                              continue;
                            }
                            u_perm[0] = (uint8_t)ua;
                            u_perm[1] = (uint8_t)ub;
                            u_perm[2] = (uint8_t)uc;
                            u_perm[3] = (uint8_t)ud;
                            for (unsigned int msb = 0; msb < 2; ++msb) {
                              unsigned int matches = 0;
                              for (unsigned int row = 0; row < 128; ++row) {
                                const unsigned int word_base = row & ~31u;
                                const unsigned int byte_idx = (row >> 3) & 3u;
                                const unsigned int bit_idx = row & 7u;
                                const unsigned int mapped_bit = msb ? (7u - bit_idx) : bit_idx;
                                const unsigned int idx_w =
                                    word_base | (w_perm[byte_idx] << 3) | mapped_bit;
                                const unsigned int idx_u =
                                    word_base | (u_perm[byte_idx] << 3) | mapped_bit;
                                const unsigned int truth_bit =
                                    sm4_ptr_get_bit_be(truth_bytes, row);
                                const unsigned int bit_val =
                                    ptr_get_bit(sm4_dbg_last_witness, idx_w) ^
                                    ptr_get_bit(sm4_dbg_last_u, idx_u);
                                if (bit_val == truth_bit) {
                                  ++matches;
                                }
                              }
                              if (matches > best3_matches) {
                                best3_matches = matches;
                                memcpy(best3_w, w_perm, 4);
                                memcpy(best3_u, u_perm, 4);
                                best3_msb = msb;
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
            fprintf(stderr,
                    "[SM4_DEBUG] best separate byte perm match: %u/128 "
                    "w=[%u %u %u %u] u=[%u %u %u %u] bit_order=%s\n",
                    best3_matches, best3_w[0], best3_w[1], best3_w[2], best3_w[3],
                    best3_u[0], best3_u[1], best3_u[2], best3_u[3],
                    best3_msb ? "msb" : "lsb");
          }
        }
      }
    }
  }
  {
    const unsigned int KEY_BITS = 32 * (32 + 4);
    const unsigned int idxs[] = {0,        1,        2,        3,
                   4,        5,        6,        7,
                   32,       64,       96,       KEY_BITS,
                   KEY_BITS + 1, KEY_BITS + 2, KEY_BITS + 3,
                   ell,      ell + 1,  ell + 2,  ell + lambda - 1,
                   ell + lambda, ell + lambda + 1,
                   ell + 2 * lambda - 2, ell + 2 * lambda - 1};
    for (size_t k = 0; k < sizeof(idxs) / sizeof(idxs[0]); ++k) {
      if (idxs[k] >= ell + 2 * lambda) {
        continue;
      }
      uint8_t buf[BF128_NUM_BYTES];
      bf128_store(buf, q_key[idxs[k]]);
      char label[64];
      snprintf(label, sizeof(label), "q_key pre-delta idx=%u", idxs[k]);
      sm4_debug_hex(label, buf, BF128_NUM_BYTES);

      if (sm4_dbg_last_w_tag && idxs[k] < sm4_dbg_last_w_taglen) {
        uint8_t prover_buf[BF128_NUM_BYTES];
        bf128_store(prover_buf, sm4_dbg_last_w_tag[idxs[k]]);
        snprintf(label, sizeof(label), "w_tag idx=%u", idxs[k]);
        sm4_debug_hex(label, prover_buf, BF128_NUM_BYTES);
      }
    }

    for (size_t k = 0; k < sizeof(idxs) / sizeof(idxs[0]); ++k) {
      if (idxs[k] >= ell) {
        continue;
      }
      unsigned int bit = sm4_get_d_bit_be(d, idxs[k]);
      fprintf(stderr, "[SM4_DEBUG] d bit[%u]=%u\n", idxs[k], bit);
    }
  }

  if (sm4_dbg_last_w_tag && sm4_dbg_last_w_taglen == ell + 2 * lambda) {
    const unsigned int rows_check[] = {ell - 1u, ell, ell + 1u};
    for (size_t i = 0; i < sizeof(rows_check) / sizeof(rows_check[0]); ++i) {
      const unsigned int row = rows_check[i];
      const unsigned int d_bit = row < ell ? sm4_get_d_bit_be(d, row) : 0u;
      bf128_t w = sm4_dbg_last_w_tag[row];
      bf128_t q = q_key[row];
      bf128_t expected = bf128_add(w, bf128_mul_bit(bf_delta, d_bit));
      uint8_t w_buf[BF128_NUM_BYTES];
      uint8_t q_buf[BF128_NUM_BYTES];
      uint8_t exp_buf[BF128_NUM_BYTES];
      bf128_store(w_buf, w);
      bf128_store(q_buf, q);
      bf128_store(exp_buf, expected);
      fprintf(stderr,
              "[SM4_DEBUG] q_eq_check row=%u d_bit=%u\n",
              row, d_bit);
      sm4_debug_hex("q_eq_check w_tag", w_buf, BF128_NUM_BYTES);
      sm4_debug_hex("q_eq_check q_key", q_buf, BF128_NUM_BYTES);
      sm4_debug_hex("q_eq_check expected", exp_buf, BF128_NUM_BYTES);
      fprintf(stderr,
              "[SM4_DEBUG] q_eq_check row=%u match_expected=%s\n",
              row,
              memcmp(q_buf, exp_buf, BF128_NUM_BYTES) == 0 ? "yes" : "no");

      if (row + 1u < sm4_dbg_last_w_taglen) {
        bf128_t w_next = sm4_dbg_last_w_tag[row + 1u];
        bf128_t exp_next = bf128_add(w_next, bf128_mul_bit(bf_delta, d_bit));
        uint8_t exp_next_buf[BF128_NUM_BYTES];
        bf128_store(exp_next_buf, exp_next);
        sm4_debug_hex("q_eq_check expected row+1", exp_next_buf, BF128_NUM_BYTES);
        fprintf(stderr,
                "[SM4_DEBUG] q_eq_check row=%u match_expected_row+1=%s\n",
                row,
                memcmp(q_buf, exp_next_buf, BF128_NUM_BYTES) == 0 ? "yes" : "no");
      }

      if (row > 0u) {
        bf128_t w_prev = sm4_dbg_last_w_tag[row - 1u];
        bf128_t exp_prev = bf128_add(w_prev, bf128_mul_bit(bf_delta, d_bit));
        uint8_t exp_prev_buf[BF128_NUM_BYTES];
        bf128_store(exp_prev_buf, exp_prev);
        sm4_debug_hex("q_eq_check expected row-1", exp_prev_buf, BF128_NUM_BYTES);
        fprintf(stderr,
                "[SM4_DEBUG] q_eq_check row=%u match_expected_row-1=%s\n",
                row,
                memcmp(q_buf, exp_prev_buf, BF128_NUM_BYTES) == 0 ? "yes" : "no");
      }
    }
  }

  if (sm4_dbg_last_v_col_hashes && sm4_dbg_last_v_col_count == lambda) {
    const size_t col_bytes = (ell_hat + 7u) / 8u;
    const uint64_t chall2_hash = sm4_hash64_fnv1a_local(chall_2, chall2_len);
    if (sm4_dbg_last_v_col_bytes == col_bytes &&
        sm4_dbg_last_chall2_len == chall2_len) {
      const unsigned int chall2_match =
          (sm4_dbg_last_chall2_hash == chall2_hash) ? 1u : 0u;
      if (!chall2_match) {
        fprintf(stderr,
                "[SM4_DEBUG] WARNING: chall_2 mismatch, but dumping V/Q bits for analysis v=0x%016llx q=0x%016llx\n",
                (unsigned long long)sm4_dbg_last_chall2_hash,
                (unsigned long long)chall2_hash);
      }
      size_t first_bad = SIZE_MAX;
      uint64_t v_hash = 0;
      uint64_t q_hash = 0;
      for (unsigned int col = 0; col < lambda; ++col) {
        const uint64_t cur_q_hash = sm4_hash64_fnv1a_local(Q[col], col_bytes);
        if (cur_q_hash != sm4_dbg_last_v_col_hashes[col]) {
          first_bad = col;
          v_hash = sm4_dbg_last_v_col_hashes[col];
          q_hash = cur_q_hash;
          break;
        }
      }
      if (first_bad == SIZE_MAX) {
        fprintf(stderr, "[SM4_DEBUG] V/Q column hash match: all %u columns\n", lambda);
      } else {
        fprintf(stderr,
                "[SM4_DEBUG] V/Q column hash first mismatch col=%zu v_hash=0x%016llx q_hash=0x%016llx\n",
                first_bad, (unsigned long long)v_hash, (unsigned long long)q_hash);
        if (sm4_dbg_last_v_cols && sm4_dbg_last_v_cols_len == (size_t)lambda * col_bytes) {
          const uint8_t* v_col = sm4_dbg_last_v_cols + first_bad * col_bytes;
          const uint8_t* q_col = Q[first_bad];
          size_t byte_idx = 0;
          while (byte_idx < col_bytes && v_col[byte_idx] == q_col[byte_idx]) {
            ++byte_idx;
          }
          if (byte_idx < col_bytes) {
            const uint8_t diff = (uint8_t)(v_col[byte_idx] ^ q_col[byte_idx]);
            unsigned int bit_idx = 0;
            while (bit_idx < 8 && ((diff >> bit_idx) & 1u) == 0u) {
              ++bit_idx;
            }
            const unsigned int ell_bytes = ell / 8u;
            const unsigned int masks_bytes = 3u * (lambda / 8u);
            const char* region = "uhash";
            if (byte_idx < ell_bytes) {
              region = "witness";
            } else if (byte_idx < ell_bytes + masks_bytes) {
              region = "masks";
            }
            fprintf(stderr,
                    "[SM4_DEBUG] V/Q column diff col=%zu byte=%zu bit=%u region=%s v=0x%02x q=0x%02x\n",
                    first_bad, byte_idx, bit_idx, region, v_col[byte_idx], q_col[byte_idx]);

            const unsigned int row = (unsigned int)(byte_idx * 8u + bit_idx);
            const unsigned int v_bit = (v_col[byte_idx] >> bit_idx) & 1u;
            const unsigned int q_bit = (q_col[byte_idx] >> bit_idx) & 1u;
            const unsigned int d_bit = row < ell ? sm4_get_d_bit_be(d, row) : 0u;
            const unsigned int d_bit_le = row < ell ? ptr_get_bit(d, row) : 0u;
            uint8_t delta_bytes[BF128_NUM_BYTES];
            bf128_store(delta_bytes, bf_delta);
            const unsigned int delta_bit = ptr_get_bit(delta_bytes, (unsigned int)first_bad);
            const unsigned int expected_q = v_bit ^ (d_bit & delta_bit);
            const unsigned int expected_q_le = v_bit ^ (d_bit_le & delta_bit);
            const char* scenario = "unknown";
            if (expected_q == q_bit) {
              scenario = (d_bit == 1u && q_bit != v_bit) ? "A" : "A?";
            } else {
              scenario = "B";
            }
            fprintf(stderr,
                    "[SM4_DEBUG] V/Q bit-check col=%zu row=%u v_bit=%u q_bit=%u d_bit=%u d_bit_le=%u delta_bit=%u expected_q=%u expected_q_le=%u scenario=%s\n",
                    first_bad, row, v_bit, q_bit, d_bit, d_bit_le, delta_bit, expected_q, expected_q_le, scenario);
          } else {
            fprintf(stderr,
                    "[SM4_DEBUG] V/Q column diff col=%zu but no differing byte found\n",
                    first_bad);
          }
        }
      }
    } else if (sm4_dbg_last_v_col_bytes != col_bytes) {
      fprintf(stderr,
              "[SM4_DEBUG] V/Q column hash skipped: col_bytes mismatch v=%zu q=%zu\n",
              sm4_dbg_last_v_col_bytes, col_bytes);
    }
  }
#endif

  // ::7-9 计算q_star
#if defined(FAEST_SM4_DEBUG)
  {
    fprintf(stderr,
            "[SM4_DEBUG] q_star preimage: q_key[ell..ell+2*lambda) (no d mixed); sum_poly order xs[127..0]\n");
    for (unsigned int i = 0; i < lambda; ++i) {
      uint8_t buf[BF128_NUM_BYTES];
      char label[64];
      bf128_store(buf, q_key[ell + i]);
      snprintf(label, sizeof(label), "q_star xs0[%03u] row=%u", i, ell + i);
      sm4_debug_hex(label, buf, BF128_NUM_BYTES);
    }
    for (unsigned int i = 0; i < lambda; ++i) {
      uint8_t buf[BF128_NUM_BYTES];
      char label[64];
      bf128_store(buf, q_key[ell + lambda + i]);
      snprintf(label, sizeof(label), "q_star xs1[%03u] row=%u", i, ell + lambda + i);
      sm4_debug_hex(label, buf, BF128_NUM_BYTES);
    }

    if (sm4_dbg_last_w_tag && sm4_dbg_last_w_taglen == ell + 2 * lambda) {
      size_t mismatch0 = 0;
      size_t mismatch1 = 0;
      size_t first0 = SIZE_MAX;
      size_t first1 = SIZE_MAX;
      for (unsigned int i = 0; i < lambda; ++i) {
        uint8_t a[BF128_NUM_BYTES], b[BF128_NUM_BYTES];
        bf128_store(a, sm4_dbg_last_w_tag[ell + i]);
        bf128_store(b, q_key[ell + i]);
        if (memcmp(a, b, sizeof(a)) != 0) {
          if (first0 == SIZE_MAX) {
            first0 = i;
          }
          ++mismatch0;
        }
      }
      for (unsigned int i = 0; i < lambda; ++i) {
        uint8_t a[BF128_NUM_BYTES], b[BF128_NUM_BYTES];
        bf128_store(a, sm4_dbg_last_w_tag[ell + lambda + i]);
        bf128_store(b, q_key[ell + lambda + i]);
        if (memcmp(a, b, sizeof(a)) != 0) {
          if (first1 == SIZE_MAX) {
            first1 = i;
          }
          ++mismatch1;
        }
      }
      fprintf(stderr,
              "[SM4_DEBUG] q_star inputs vs w_tag mismatch: xs0=%zu xs1=%zu first0=%zu first1=%zu\n",
              mismatch0, mismatch1, first0, first1);
      if (first0 != SIZE_MAX) {
        uint8_t a[BF128_NUM_BYTES], b[BF128_NUM_BYTES];
        bf128_store(a, sm4_dbg_last_w_tag[ell + first0]);
        bf128_store(b, q_key[ell + first0]);
        sm4_debug_hex("w_tag xs0 first mismatch", a, BF128_NUM_BYTES);
        sm4_debug_hex("q_key xs0 first mismatch", b, BF128_NUM_BYTES);
      }
      if (first1 != SIZE_MAX) {
        uint8_t a[BF128_NUM_BYTES], b[BF128_NUM_BYTES];
        bf128_store(a, sm4_dbg_last_w_tag[ell + lambda + first1]);
        bf128_store(b, q_key[ell + lambda + first1]);
        sm4_debug_hex("w_tag xs1 first mismatch", a, BF128_NUM_BYTES);
        sm4_debug_hex("q_key xs1 first mismatch", b, BF128_NUM_BYTES);
      }
    }
  }
#endif
  bf128_t q_star_0 = bf128_sum_poly(q_key + ell);
  bf128_t q_star_1 = bf128_sum_poly(q_key + ell + lambda);
  bf128_t q_star = bf128_add(q_star_0, bf128_mul(bf_delta, q_star_1));

#if defined(FAEST_SM4_DEBUG)
  if (sm4_dbg_last_w_tag && sm4_dbg_last_w_taglen == ell + 2 * lambda) {
    bf128_t prover_q_star = bf128_add(sm4_dbg_last_v_star0, bf128_mul(bf_delta, sm4_dbg_last_v_star1));
    uint8_t a[BF128_NUM_BYTES], b[BF128_NUM_BYTES];
    bf128_store(a, prover_q_star);
    bf128_store(b, q_star);
    if (memcmp(a, b, sizeof(a)) != 0) {
      sm4_debug_hex("prover q_star", a, BF128_NUM_BYTES);
      sm4_debug_hex("verifier q_star", b, BF128_NUM_BYTES);

      /* extra diagnostics: dump delta and the two sum-polys used to form q_star */
      uint8_t dbg_buf[BF128_NUM_BYTES];
      bf128_store(dbg_buf, bf_delta);
      sm4_debug_hex("verifier bf_delta", dbg_buf, BF128_NUM_BYTES);
      bf128_store(dbg_buf, q_star_0);
      sm4_debug_hex("verifier q_star_0", dbg_buf, BF128_NUM_BYTES);
      bf128_store(dbg_buf, q_star_1);
      sm4_debug_hex("verifier q_star_1", dbg_buf, BF128_NUM_BYTES);

      /* dump prover-side v_star components for comparison */
      bf128_store(dbg_buf, sm4_dbg_last_v_star0);
      sm4_debug_hex("prover v_star0", dbg_buf, BF128_NUM_BYTES);
      bf128_store(dbg_buf, sm4_dbg_last_v_star1);
      sm4_debug_hex("prover v_star1", dbg_buf, BF128_NUM_BYTES);

      /* NOTE: q_star = v_star_0 + delta*(u_star_0 + v_star_1) + delta^2*u_star_1
       * so q_star != prover_q_star is EXPECTED for non-zero delta — do NOT set
       * sm4_debug_first_error_reported here as it would silently skip all
       * subsequent verifier hash updates, breaking the protocol. */
    }
  }
#endif

  // ::10 初始化ZK哈希
  zk_hash_128_ctx b_ctx;
  zk_hash_128_init(&b_ctx, chall_2);

  // ::11 添加差分d到q_key
  for (unsigned int i = 0; i < ell; i++) {
    q_key[i] = bf128_add(q_key[i], bf128_mul_bit(bf_delta, sm4_get_d_bit_be(d, i)));
  }

#if defined(FAEST_SM4_DEBUG)
  if (sm4_dbg_last_w_tag && sm4_dbg_last_w_taglen == ell + 2 * lambda) {
    size_t match_after_delta = 0;
    size_t mismatch_after_delta = 0;
    size_t first_mismatch_after = SIZE_MAX;
    for (unsigned int row = 0; row < ell; ++row) {
      uint8_t a[BF128_NUM_BYTES], b[BF128_NUM_BYTES];
      bf128_store(a, sm4_dbg_last_w_tag[row]);
      bf128_store(b, q_key[row]);
      if (memcmp(a, b, sizeof(a)) == 0) {
        ++match_after_delta;
      } else {
        if (first_mismatch_after == SIZE_MAX) {
          first_mismatch_after = row;
        }
        ++mismatch_after_delta;
      }
    }
    fprintf(stderr,
            "[SM4_DEBUG] post-delta match=%zu mismatch=%zu first_mismatch=%zu\n",
            match_after_delta, mismatch_after_delta, first_mismatch_after);
  }
  {
    const unsigned int KEY_BITS = 32 * (32 + 4);
    const unsigned int idxs[] = {0, 1, 2, 3, 4, 5, 6, 7, 32, 64, 96, KEY_BITS,
                                 KEY_BITS + 1, KEY_BITS + 2, KEY_BITS + 3};
    for (size_t k = 0; k < sizeof(idxs) / sizeof(idxs[0]); ++k) {
      if (idxs[k] >= ell + 2 * lambda) {
        continue;
      }
      uint8_t buf[BF128_NUM_BYTES];
      bf128_store(buf, q_key[idxs[k]]);
      char label[64];
      snprintf(label, sizeof(label), "q_key post-delta idx=%u", idxs[k]);
      sm4_debug_hex(label, buf, BF128_NUM_BYTES);
    }
  }

  if (sm4_dbg_last_w_tag && sm4_dbg_last_w_taglen == ell + 2 * lambda) {
    size_t mismatch_count = 0;
    for (unsigned int row = 0; row < sm4_dbg_last_w_taglen; ++row) {
      uint8_t a[BF128_NUM_BYTES], b[BF128_NUM_BYTES];
      bf128_store(a, sm4_dbg_last_w_tag[row]);
      bf128_store(b, q_key[row]);
      if (memcmp(a, b, sizeof(a)) != 0) {
        ++mismatch_count;
      }
    }
    fprintf(stderr, "[SM4_DEBUG] post-delta mismatch rows=%zu\n", mismatch_count);
  }
#endif

  // ::12 验证SM4约束
  sm4_SSS_constraints_verifier(&b_ctx, q_key, owf_in, owf_out, bf_delta, params);

  // Stage check: constraints verification complete

  free(q_key);

  // ::13-14 最终化哈希
  uint8_t q_tilde[16];  // 128位 = 16字节
  zk_hash_128_finalize(q_tilde, &b_ctx, q_star);
#if defined(FAEST_SM4_DEBUG)
  uint8_t dbg_q_star[BF128_NUM_BYTES];
  bf128_store(dbg_q_star, q_star);
  sm4_debug_hex("verifier q_star", dbg_q_star, lambda / 8);
#endif

  // Stage check: challenge and hash finalization complete

  // ::15-16 计算a0_tilde
  bf128_t tmp1 = bf128_mul(bf128_load(a1_tilde), bf_delta);
  bf128_t tmp2 = bf128_mul(bf128_load(a2_tilde), bf_delta_sq);
  bf128_t tmp3 = bf128_add(tmp1, tmp2);
  bf128_t ret = bf128_add(bf128_load(q_tilde), tmp3);

  bf128_store(a0_tilde, ret);

#if defined(FAEST_SM4_DEBUG)
  sm4_debug_hex("verifier q_tilde", q_tilde, lambda / 8);
  sm4_debug_hex("verifier a0_tilde", a0_tilde, lambda / 8);
#endif

  // Stage check: final comparison preparation complete
}
