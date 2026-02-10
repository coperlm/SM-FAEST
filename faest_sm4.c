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

// 宏定义：循环左移 8 位
#define SM4_ROTL8(x, n) (((x) << (n)) | ((x) >> (8 - (n))))

#if defined(FAEST_SM4_DEBUG)
static void sm4_debug_hex(const char* label, const uint8_t* buf, size_t len) {
  fprintf(stderr, "[SM4_DEBUG] %s:", label);
  for (size_t i = 0; i < len; ++i) {
    fprintf(stderr, "%s%02x", (i % 16 == 0) ? " " : "", buf[i]);
  }
  fprintf(stderr, "\n");
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
 * 其中 C = 0xD3, L^-1: z[i] = y[(i+1)%8] ^ y[(i+3)%8] ^ y[(i+7)%8]
 */
static inline uint8_t sm4_inverse_affine_scalar(uint8_t sbox_out) {
  // 1. 去除仿射常数
  uint8_t y = sbox_out ^ SM4_AFFINE_C;
  
  // 2. 应用逆线性变换 L^-1
  // 公式等价于: z = (y <<< 7) ^ (y <<< 5) ^ (y <<< 1)
  uint8_t z = (SM4_ROTL8(y, 7) ^ SM4_ROTL8(y, 5) ^ SM4_ROTL8(y, 1)) & 0xFF;
  
  return z;
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
 * 1. 标量计算: y = L^-1(x ^ 0xD3)
 *    L^-1: z = (y<<<7) ^ (y<<<5) ^ (y<<<1)
 * 2. Tag 计算（线性操作）:
 *    应用相同的线性变换
 */
static void sm4_SSS_inverse_affine_byte_prover(uint8_t* y_bits, bf128_t* y_bits_tag,
                                                const uint8_t x_bits, const bf128_t* x_bits_tag) {
  // 1. 标量计算: y = L^-1(x ^ C)
  // C = 0xD3, L^-1 使用循环左移: (y<<<7) ^ (y<<<5) ^ (y<<<1)
  uint8_t y_temp = x_bits ^ SM4_AFFINE_C;
  *y_bits = (SM4_ROTL8(y_temp, 7) ^ SM4_ROTL8(y_temp, 5) ^ SM4_ROTL8(y_temp, 1)) & 0xFF;
  
  // 2. Tag 计算（线性部分）
  // 首先处理常数 0xD3 的 XOR（在 prover 侧，delta=0，所以 tag 不变）
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
 * 对于常数 C = 0xD3 = 11010011（二进制），在位 0,1,4,6,7 上为 1
 * Verifier 需要在这些位上加上 delta
 */
static void sm4_SSS_inverse_affine_byte_verifier(bf128_t* y_bits_key, const bf128_t* x_bits_key,
                                                 bf128_t delta) {
  // 应用线性变换L^-1: z[i] = y[(i+1)%8] ^ y[(i+3)%8] ^ y[(i+7)%8]
  for (unsigned int bit_i = 0; bit_i < 8; bit_i++) {
    y_bits_key[bit_i] = bf128_add(
        bf128_add(x_bits_key[(bit_i + 1) % 8], x_bits_key[(bit_i + 3) % 8]),
        x_bits_key[(bit_i + 7) % 8]);
  }
  
  // 处理常数 L^-1(0xD3) = 0x34 = 00110100 的贡献
  // 在位 2, 4, 5 上为 1，需要加上 delta
  y_bits_key[2] = bf128_add(y_bits_key[2], delta);  // bit 2
  y_bits_key[4] = bf128_add(y_bits_key[4], delta);  // bit 4
  y_bits_key[5] = bf128_add(y_bits_key[5], delta);  // bit 5
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
// Phase 2: Inverse Norm to Conjugates
// ============================================================================

// SM4 域的 beta 值（GF(2^8) with polynomial 0x1F5）
// β = 0x02 是本原元
// 这些值在 GF(2^8) 层面，需要提升到 bf128_t
// beta_squares[i] = β^(2i), i = 0,1,2,3,4
static const uint8_t sm4_beta_squares_gf8[5] = {
    0x01,  // β^0 = 1
    0x04,  // β^2
    0x10,  // β^4
    0x40,  // β^6
    0xF5,  // β^8
};

// beta_cubes[i] = β^(3*(i+1)), i = 0,1,2,3
static const uint8_t sm4_beta_cubes_gf8[4] = {
    0x08,  // β^3
    0x40,  // β^6
    0x1F,  // β^9
    0xF8,  // β^12
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
 * 将 uint8_t 提升到 bf128_t（将 GF(2^8) 嵌入到 GF(2^128)）
 * 简单地将 uint8_t 值放在 bf128_t 的最低字节
 */
static inline bf128_t sm4_lift_uint8_to_bf128(uint8_t val) {
  return bf128_from_bf8(val);
}

// 预计算提升后的 beta 值到 bf128_t
static bf128_t sm4_beta_squares_bf128[5];
static bf128_t sm4_beta_cubes_bf128[4];
static bool sm4_beta_initialized = false;

/**
 * 初始化 SM4 的 beta 常量（提升到 bf128_t 域）
 */
static void sm4_init_beta_values(void) {
  if (sm4_beta_initialized) {
    return;
  }
  
  for (unsigned int i = 0; i < 5; i++) {
    sm4_beta_squares_bf128[i] = sm4_lift_uint8_to_bf128(sm4_beta_squares_gf8[i]);
  }
  
  for (unsigned int i = 0; i < 4; i++) {
    sm4_beta_cubes_bf128[i] = sm4_lift_uint8_to_bf128(sm4_beta_cubes_gf8[i]);
  }
  
  sm4_beta_initialized = true;
}

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
  sm4_init_beta_values();
  
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
  sm4_init_beta_values();
  
  for (unsigned int i = 0; i < 4; ++i) {
    y_eval[i] = bf128_add(
        bf128_add(x_eval[0], bf128_mul(sm4_beta_squares_bf128[i], x_eval[1])),
        bf128_add(bf128_mul(sm4_beta_squares_bf128[i + 1], x_eval[2]),
                  bf128_mul(sm4_beta_cubes_bf128[i], x_eval[3])));
  }
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
  zk_hash_128_3_update(hasher, deg3, deg2, deg1);
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
  
  zk_hash_128_update(hasher, term);
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
  // n是移位的位数，需要转换为字节和位的组合
  unsigned int byte_shift = n / 8;      // 完整字节的移位
  unsigned int bit_shift = n % 8;       // 剩余位的移位
  unsigned int right_bits = 8 - bit_shift;  // 需要从下一字节借的位数
  
  if (bit_shift == 0) {
    // 简单的字节循环移位
    for (unsigned int i = 0; i < 4; i++) {
      out_val[i] = in_val[(i + byte_shift) % 4];
      for (unsigned int bit = 0; bit < 8; bit++) {
        out_tag[i * 8 + bit] = in_tag[((i + byte_shift) % 4) * 8 + bit];
      }
    }
  } else {
    // 需要跨字节边界的位移位
    for (unsigned int i = 0; i < 4; i++) {
      unsigned int src_byte = (i + byte_shift) % 4;
      unsigned int next_byte = (src_byte + 1) % 4;
      
      // 值的计算
      out_val[i] = (in_val[src_byte] << bit_shift) | (in_val[next_byte] >> right_bits);
      
      // Tag的计算（逐位处理）
      for (unsigned int bit = 0; bit < 8; bit++) {
        unsigned int total_shift = (byte_shift * 8 + bit_shift + bit) % 32;
        unsigned int src_bit_idx = (i * 8 + bit + (32 - total_shift)) % 32;
        out_tag[i * 8 + bit] = in_tag[src_bit_idx];
      }
    }
  }
}

/**
 * 循环左移32位字（Verifier版本）
 */
static void sm4_SSS_rotl32_verifier(bf128_t* out_eval, const bf128_t* in_eval, unsigned int n) {
  // 临时数组存储结果
  bf128_t temp[32];
  
  for (unsigned int i = 0; i < 32; i++) {
    temp[i] = in_eval[(i + (32 - n)) % 32];
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
      uint8_t inv_norm;
      bf128_t inv_norm_tag[8];
      sm4_SSS_inverse_affine_byte_prover(&inv_norm, inv_norm_tag, tau_bytes[byte_i],
                                         &tau_tag[byte_i * 8]);

      bf128_t y[4];
      bf128_t y_tag[4];
      sm4_SSS_inv_norm_to_conjugates_prover(y, y_tag, inv_norm, inv_norm_tag);

      bf128_t temp_bits[8];
      bf128_t temp_bits_tag[8];
      for (unsigned int bit = 0; bit < 8; bit++) {
        temp_bits[bit] = bf128_from_bit((x_bytes[byte_i] >> bit) & 1);
        temp_bits_tag[bit] = x_tag[byte_i * 8 + bit];
      }

      sm4_SSS_inv_norm_constraints_prover(hasher, temp_bits, temp_bits_tag, y, y_tag);
    }
  }
}

/**
 * SM4 密钥扩展约束验证 (Verifier版本)
 */
static void sm4_SSS_expkey_constraints_verifier(zk_hash_128_ctx* hasher, bf128_t* rk_key,
                                                const bf128_t* w_key, bf128_t delta) {
  const unsigned int SM4_R = 32;
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
      sm4_SSS_inverse_affine_byte_verifier(inv_norm_key, &tau_key[byte_i * 8], delta);

      bf128_t y_key[4];
      sm4_SSS_inv_norm_to_conjugates_verifier(y_key, inv_norm_key);

      bf128_t temp_bits_key[8];
      for (unsigned int bit = 0; bit < 8; bit++) {
        temp_bits_key[bit] = x_key[byte_i * 8 + bit];
      }

      sm4_SSS_inv_norm_constraints_verifier(hasher, temp_bits_key, y_key, delta);
    }
  }
}

// ============================================================================
// Phase 5: Feistel轮函数约束（加密）
// ============================================================================

/**
 * SM4 加密约束 (Prover版本)
 * 验证32轮Feistel结构，按AES风格每次处理2轮（奇+偶）
 * 
 * 见证格式（每2轮为一对）：
 * - 奇数轮（1,3,5,...,31）：记录S盒输出的逆范数（4字节）
 * - 偶数轮（2,4,6,...,30）：记录完整状态（16字节）
 * - 第32轮不记录（未提交）
 * 
 * @param hasher ZK哈希上下文
 * @param owf_in 输入明文（16字节）
 * @param owf_in_tag 明文tag
 * @param owf_out 输出密文（16字节）
 * @param owf_out_tag 密文tag
 * @param w 扩展见证（加密部分）
 * @param w_tag 见证tag
 * @param rk 轮密钥（36个字）
 * @param rk_tag 轮密钥tag
 */
static void sm4_SSS_enc_constraints_prover(zk_hash_128_3_ctx* hasher,
                                           const uint8_t* owf_in, const bf128_t* owf_in_tag,
                                           const uint8_t* owf_out, const bf128_t* owf_out_tag,
                                           const uint8_t* w, const bf128_t* w_tag,
                                           const uint8_t* rk, const bf128_t* rk_tag,
                                           const faest_paramset_t* params) {
  const unsigned int SM4_R = 32;
  const unsigned int Nwords = 4;   // SM4状态：4个字
  const unsigned int Nbytes = 16;  // 4个字 × 4字节
  const unsigned int Nbits = 128;  // 4个字 × 32位
  
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
    
    // ========== 奇数轮：生成逆范数约束 ==========
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
    
    // ::4 从见证读取4个字节的逆范数（奇数轮专有）
    const uint8_t* inv_norm_bytes = w + r_pair * 20;  // 每对轮：20字节（4+16）
    const bf128_t* inv_norm_tags = w_tag + r_pair * 160;  // 每对轮：160位（32+128）
    
    uint8_t sbox_out_odd[4];
    bf128_t sbox_out_odd_tag[32];
    
    for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
      uint8_t inv_norm = inv_norm_bytes[byte_i];
      const bf128_t* inv_norm_tag = inv_norm_tags + byte_i * 8;
      
      // ::5 转换逆范数为共轭
      bf128_t y[4];
      bf128_t y_tag[4];
      sm4_SSS_inv_norm_to_conjugates_prover(y, y_tag, inv_norm, inv_norm_tag);
      
      // ::6 从temp提取位表示
      bf128_t temp_bits[8];
      bf128_t temp_bits_tag[8];
      for (unsigned int bit = 0; bit < 8; bit++) {
        temp_bits[bit] = bf128_from_bit((temp_odd[byte_i] >> bit) & 1);
        temp_bits_tag[bit] = temp_odd_tag[byte_i * 8 + bit];
      }
      
      // ::7 生成逆范数约束
      sm4_SSS_inv_norm_constraints_prover(hasher, temp_bits, temp_bits_tag, y, y_tag);
      
      // ::8 应用逆仿射变换（字节版本）
      sm4_SSS_inverse_affine_prover(&sbox_out_odd[byte_i], &sbox_out_odd_tag[byte_i * 8],
                                    &temp_odd[byte_i], &temp_odd_tag[byte_i * 8],
                                    params);
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

      // ::13 偶数轮从witness读取完整状态；第32轮改用公开输出
      // Witness布局：每对轮20字节（4字节inv_norm + 16字节state）
      uint8_t state_witness_buf[16];
      bf128_t state_witness_tag_buf[128];
      const uint8_t* state_witness = w + r_pair * 20 + 4;
      const bf128_t* state_witness_tag = w_tag + r_pair * 160 + 32;
      if (r_even == SM4_R) {
        for (unsigned int word = 0; word < 4; word++) {
          memcpy(state_witness_buf + word * 4, owf_out + (3 - word) * 4, 4);
          memcpy(state_witness_tag_buf + word * 32, owf_out_tag + (3 - word) * 32,
                 32 * sizeof(bf128_t));
        }
        state_witness = state_witness_buf;
        state_witness_tag = state_witness_tag_buf;
      }

      // ::14 从witness状态推导S盒输出：L_out = new_word ^ state[0]
      uint8_t L_out_even[4];
      bf128_t L_out_even_tag[32];
      for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
        L_out_even[byte_i] = state_witness[12 + byte_i] ^ state[byte_i];
        for (unsigned int bit = 0; bit < 8; bit++) {
          unsigned int idx = byte_i * 8 + bit;
          L_out_even_tag[idx] = bf128_add(state_witness_tag[96 + idx], state_tag[idx]);
        }
      }

      uint8_t sbox_out_even[4];
      bf128_t sbox_out_even_tag[32];
      sm4_SSS_linear_l_inv_prover(sbox_out_even, sbox_out_even_tag, L_out_even, L_out_even_tag);

      // ::15 应用逆仿射变换得到逆元
      uint8_t inv_norm_even[4];
      bf128_t inv_norm_even_tag[32];
      sm4_SSS_inverse_affine_prover(inv_norm_even, inv_norm_even_tag, sbox_out_even,
                                    sbox_out_even_tag, params);

      // ::16 生成逆范数约束
      for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
        bf128_t y[4];
        bf128_t y_tag[4];
        sm4_SSS_inv_norm_to_conjugates_prover(y, y_tag, inv_norm_even[byte_i],
                                              inv_norm_even_tag + byte_i * 8);

        bf128_t temp_bits[8];
        bf128_t temp_bits_tag[8];
        for (unsigned int bit = 0; bit < 8; bit++) {
          temp_bits[bit] = bf128_from_bit((temp_even[byte_i] >> bit) & 1);
          temp_bits_tag[bit] = temp_even_tag[byte_i * 8 + bit];
        }

        sm4_SSS_inv_norm_constraints_prover(hasher, temp_bits, temp_bits_tag, y, y_tag);
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
  const unsigned int SM4_R = 32;
  const unsigned int Nbytes = 16;
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
    
    // ::4 从见证读取4个字节的逆范数key
    const bf128_t* inv_norm_keys = w_key + r_pair * 160;  // 每对轮：160位（32+128）
    
    bf128_t sbox_out_odd_key[32];
    
    for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
      const bf128_t* inv_norm_key = inv_norm_keys + byte_i * 8;
      
      // ::5 转换逆范数为共轭
      bf128_t y_key[4];
      sm4_SSS_inv_norm_to_conjugates_verifier(y_key, inv_norm_key);
      
      // ::6 从temp_key提取8位
      bf128_t temp_bits_key[8];
      for (unsigned int bit = 0; bit < 8; bit++) {
        temp_bits_key[bit] = temp_odd_key[byte_i * 8 + bit];
      }
      
      // ::7 生成逆范数约束
      sm4_SSS_inv_norm_constraints_verifier(hasher, temp_bits_key, y_key, delta);
      
      // ::8 应用逆仿射变换（直接使用8位版本）
      sm4_SSS_inverse_affine_verifier(&sbox_out_odd_key[byte_i * 8], temp_bits_key, delta, params);
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

      // ::13 读取偶数轮状态见证tag；第32轮改用公开输出
      bf128_t state_witness_key_buf[128];
      const bf128_t* state_witness_key = w_key + r_pair * 160 + 32;
      if (r_even == SM4_R) {
        for (unsigned int word = 0; word < 4; word++) {
          memcpy(state_witness_key_buf + word * 32, owf_out_key + (3 - word) * 32,
                 32 * sizeof(bf128_t));
        }
        state_witness_key = state_witness_key_buf;
      }

      // ::14 从见证状态推导S盒输出：L_out = new_word ^ state[0]
      bf128_t L_out_even_key[32];
      for (unsigned int bit = 0; bit < 32; bit++) {
        L_out_even_key[bit] = bf128_add(state_witness_key[96 + bit], state_key[bit]);
      }

      bf128_t sbox_out_even_key[32];
      sm4_SSS_linear_l_inv_verifier(sbox_out_even_key, L_out_even_key);

      // ::15 应用逆仿射变换得到逆元
      bf128_t inv_norm_even_key[32];
      for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
        bf128_t temp_bits_key[8];
        for (unsigned int bit = 0; bit < 8; bit++) {
          temp_bits_key[bit] = sbox_out_even_key[byte_i * 8 + bit];
        }
        sm4_SSS_inverse_affine_verifier(&inv_norm_even_key[byte_i * 8], temp_bits_key, delta, params);
      }

      // ::16 生成逆范数约束
      for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
        bf128_t y_key[4];
        sm4_SSS_inv_norm_to_conjugates_verifier(y_key, inv_norm_even_key + byte_i * 8);

        bf128_t temp_bits_key[8];
        for (unsigned int bit = 0; bit < 8; bit++) {
          temp_bits_key[bit] = temp_even_key[byte_i * 8 + bit];
        }
        sm4_SSS_inv_norm_constraints_verifier(hasher, temp_bits_key, y_key, delta);
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

  // TEMP SAFETY CHECK: ensure key-based encryption matches public output.
  // This is a fast guard and MUST be replaced by a ZK constraint later.
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
    assert(memcmp(expected_out, owf_out, 16) == 0);
  }
  
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

// 辅助函数：将列优先V矩阵转换为行优先并提取w_tag
static bf128_t* column_to_row_major_and_shrink_V_128(uint8_t** V, unsigned int ell) {
  bf128_t* w_tag = malloc((ell + 2 * 128) * sizeof(bf128_t));
  assert(w_tag);

  for (unsigned int row = 0; row != ell + 2 * 128; ++row) {
    uint8_t new_row[BF128_NUM_BYTES] = {0};
    for (unsigned int column = 0; column != 128; ++column) {
      ptr_set_bit(new_row, column, ptr_get_bit(V[column], row));
    }
    w_tag[row] = bf128_load(new_row);
  }

  return w_tag;
}

// ============================================================================
// 顶层 Prover/Verifier 接口
// ============================================================================


void sm4_128_prover(uint8_t* a0_tilde, uint8_t* a1_tilde, uint8_t* a2_tilde, const uint8_t* w,
                    const uint8_t* u, uint8_t** V, const uint8_t* owf_in, const uint8_t* owf_out,
                    const uint8_t* chall_2, const faest_paramset_t* params) {
  const unsigned int ell = params->l;
  const unsigned int lambda = 128;  // SM4_128固定为128位

  // ::1-5 将V转换为w_tag
  bf128_t* w_tag = column_to_row_major_and_shrink_V_128(V, ell);

  // ::6-7 嵌入VOLE masks
  bf128_t bf_u_star_0 = bf128_sum_poly_bits(u);
  bf128_t bf_u_star_1 = bf128_sum_poly_bits(u + lambda / 8);

  // ::8-9
  bf128_t bf_v_star_0 = bf128_sum_poly(w_tag + ell);
  bf128_t bf_v_star_1 = bf128_sum_poly(w_tag + ell + lambda);

  // ::10-12 初始化ZK哈希
  zk_hash_128_3_ctx hasher;
  zk_hash_128_3_init(&hasher, chall_2);

  // ::13 生成SM4约束
  sm4_SSS_constraints_prover(&hasher, w, w_tag, owf_in, owf_out, params);

  // ::14 最终化哈希
  zk_hash_128_3_finalize(a0_tilde, a1_tilde, a2_tilde, &hasher, bf_v_star_0,
                         bf128_add(bf_u_star_0, bf_v_star_1), bf_u_star_1);

#if defined(FAEST_SM4_DEBUG)
  sm4_debug_hex("prover a0_tilde", a0_tilde, lambda / 8);
  sm4_debug_hex("prover a1_tilde", a1_tilde, lambda / 8);
  sm4_debug_hex("prover a2_tilde", a2_tilde, lambda / 8);
#endif

  free(w_tag);
}

void sm4_128_verifier(uint8_t* a0_tilde, const uint8_t* d, uint8_t** Q, const uint8_t* owf_in,
                      const uint8_t* owf_out, const uint8_t* chall_2, const uint8_t* chall_3,
                      const uint8_t* a1_tilde, const uint8_t* a2_tilde,
                      const faest_paramset_t* params) {
  const unsigned int ell = params->l;
  const unsigned int lambda = 128;

  // ::1 加载delta
  bf128_t bf_delta = bf128_load(chall_3);
  bf128_t bf_delta_sq = bf128_mul(bf_delta, bf_delta);

  // ::2-6 将Q转换为q_key
  bf128_t* q_key = column_to_row_major_and_shrink_V_128(Q, ell);

  // ::7-9 计算q_star
  bf128_t q_star_0 = bf128_sum_poly(q_key + ell);
  bf128_t q_star_1 = bf128_sum_poly(q_key + ell + lambda);
  bf128_t q_star = bf128_add(q_star_0, bf128_mul(bf_delta, q_star_1));

  // ::10 初始化ZK哈希
  zk_hash_128_ctx b_ctx;
  zk_hash_128_init(&b_ctx, chall_2);

  // ::11 添加差分d到q_key
  for (unsigned int i = 0; i < ell; i++) {
    q_key[i] = bf128_add(q_key[i], bf128_mul_bit(bf_delta, (d[i / 8] >> (i % 8)) & 1));
  }

  // ::12 验证SM4约束
  sm4_SSS_constraints_verifier(&b_ctx, q_key, owf_in, owf_out, bf_delta, params);

  free(q_key);

  // ::13-14 最终化哈希
  uint8_t q_tilde[16];  // 128位 = 16字节
  zk_hash_128_finalize(q_tilde, &b_ctx, q_star);

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
}
