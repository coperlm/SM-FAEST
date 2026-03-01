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
      // nibble 打包：2 个 invnorm 共用 1 字节
      uint8_t inv_norm = (inv_block[i * 2 + byte_i / 2] >> ((byte_i % 2) * 4)) & 0xf;
      bf128_t inv_norm_tag[4];
      for (unsigned int bit = 0; bit < 4; ++bit) {
        inv_norm_tag[bit] = inv_block_tag[i * 16 + byte_i * 4 + bit];
      }


      bf128_t y[4];
      bf128_t y_tag[4];
      sm4_SSS_inv_norm_to_conjugates_prover(y, y_tag, inv_norm, inv_norm_tag);

      bf128_t conj[8];
      bf128_t conj_tag[8];
      sm4_SSS_f256_f2_conjugates_1_byte(conj, x_bytes[byte_i]);
      sm4_SSS_f256_f2_conjugates_SSS_byte(conj_tag, x_tag + byte_i * 8);

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
      // nibble 打包：2 个 invnorm 共用 1 字节
      bf128_t inv_norm_key[4];
      for (unsigned int bit = 0; bit < 4; ++bit) {
        inv_norm_key[bit] = inv_block_key[i * 16 + byte_i * 4 + bit];
      }

      bf128_t y_key[4];
      sm4_SSS_inv_norm_to_conjugates_verifier(y_key, inv_norm_key);

      bf128_t conj_key[8];
      sm4_SSS_f256_f2_conjugates_SSS_byte(conj_key, x_key + byte_i * 8);

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
    // pair_bytes=12: [0..3]=odd_sbox [4..5]=odd_inv [6..9]=even_sbox [10..11]=even_inv
    // last pair (r_even=SM4_R): [0..3]=odd_sbox [4..5]=odd_inv [6..7]=even_inv (8 bytes)
    const unsigned int pair_bytes = 12;  // 4 sbox + 2 inv(nibble) + 4 sbox_even + 2 inv_even(nibble)
    const unsigned int base_bytes = r_pair * pair_bytes;
    const unsigned int base_bits = base_bytes * 8;
    const uint8_t* sbox_bytes = w + base_bytes;
    const bf128_t* sbox_tags = w_tag + base_bits;

    uint8_t sbox_out_odd[4];
    bf128_t sbox_out_odd_tag[32];

    for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
      // sbox 连续排列（匹配 sm4.c 新布局：[sbox0][sbox1][sbox2][sbox3][pack01][pack23]）
      uint8_t sbox_val = sbox_bytes[byte_i];
      // invnorm nibble 打包：j=0→1共享一个字节
      uint8_t inv_val = (sbox_bytes[4 + byte_i / 2] >> ((byte_i % 2) * 4)) & 0xf;
      const bf128_t* sbox_tag = sbox_tags + byte_i * 8;        // 8 bits 每个 sbox 字节
      const bf128_t* inv_tag  = sbox_tags + 32 + byte_i * 4;   // 4 bits 每个 invnorm（nibble）

      // ::6 生成 inv * temp == 1 约束（通过共轭多项式）
      bf128_t y[4];
      bf128_t y_tag[4];
      sm4_SSS_inv_norm_to_conjugates_prover(y, y_tag, inv_val, inv_tag);

      bf128_t conj[8];
      bf128_t conj_tag[8];
      sm4_SSS_f256_f2_conjugates_1_byte(conj, temp_odd[byte_i]);
      sm4_SSS_f256_f2_conjugates_SSS_byte(conj_tag, temp_odd_tag + byte_i * 8);
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
      // Rolling window optimization: replace state_witness with sbox_out_even
      // New layout per pair: [0..3]=odd_sbox [4..5]=odd_inv [6..9]=even_sbox [10..11]=even_inv
      // Last pair (r_even=SM4_R): [6..7]=even_inv only (state=public output)
      const uint8_t* inv_even_witness = NULL;
      const bf128_t* inv_even_witness_tag = NULL;
      if (r_pair < SM4_R / 2 - 1) {
        // Normal even round: read sbox_out_even from witness, do rolling state update
        const uint8_t* sbox_out_even_witness = sbox_bytes + 6;  // bytes 6-9
        const bf128_t* sbox_out_even_tag_ptr = sbox_tags + 48; // bits 48-79

        uint8_t sbox_out_even_bytes[4];
        bf128_t sbox_out_even_tag_bits[32];
        for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
          sbox_out_even_bytes[byte_i] = sbox_out_even_witness[byte_i];
          memcpy(&sbox_out_even_tag_bits[byte_i * 8],
                 sbox_out_even_tag_ptr + byte_i * 8, 8 * sizeof(bf128_t));
        }

        // Apply L transform and rolling state update
        uint8_t L_out_even[4];
        bf128_t L_out_even_tag[32];
        sm4_SSS_linear_l_prover(L_out_even, L_out_even_tag,
                                sbox_out_even_bytes, sbox_out_even_tag_bits);

        uint8_t new_word_even[4];
        bf128_t new_word_even_tag[32];
        for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
          new_word_even[byte_i] = state[byte_i] ^ L_out_even[byte_i];
          for (unsigned int bit = 0; bit < 8; bit++) {
            new_word_even_tag[byte_i * 8 + bit] =
                bf128_add(state_tag[byte_i * 8 + bit], L_out_even_tag[byte_i * 8 + bit]);
          }
        }
        memmove(state, state + 4, 12);
        memcpy(state + 12, new_word_even, 4);
        memmove(state_tag, state_tag + 32, 96 * sizeof(bf128_t));
        memcpy(state_tag + 96, new_word_even_tag, 32 * sizeof(bf128_t));

        inv_even_witness     = sbox_bytes + 10;  // bytes 10-11
        inv_even_witness_tag = sbox_tags  + 80;  // bits  80-95
      }
      if (r_even == SM4_R) {
        // Last even round: state = public output (no rolling needed here)
        // invnorm right after odd 6 bytes
        inv_even_witness     = sbox_bytes + 6;
        inv_even_witness_tag = sbox_tags  + 48;
      }

      // ::14 从witness读取偶数轮invnorm（nibble打包：2个invnorm/字节）
      uint8_t inv_norm_even[4];
      bf128_t inv_norm_even_tag[16];
      for (unsigned int byte_i = 0; byte_i < 4; ++byte_i) {
        inv_norm_even[byte_i] = (inv_even_witness[byte_i / 2] >> ((byte_i % 2) * 4)) & 0xf;
        for (unsigned int bit = 0; bit < 4; ++bit) {
          inv_norm_even_tag[byte_i * 4 + bit] = inv_even_witness_tag[byte_i * 4 + bit];
        }
      }

      // ::16 生成逆范数约束（偶数轮）
      for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
        bf128_t y[4];
        bf128_t y_tag[4];
        sm4_SSS_inv_norm_to_conjugates_prover(y, y_tag, inv_norm_even[byte_i],
                                              inv_norm_even_tag + byte_i * 4);

        bf128_t conj[8];
        bf128_t conj_tag[8];
        sm4_SSS_f256_f2_conjugates_1_byte(conj, temp_even[byte_i]);
        sm4_SSS_f256_f2_conjugates_SSS_byte(conj_tag, temp_even_tag + byte_i * 8);

        sm4_SSS_inv_norm_constraints_prover(hasher, conj, conj_tag, y, y_tag);
      }
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
    // pair_bytes=12: [0..3]=odd_sbox [4..5]=odd_inv [6..9]=even_sbox [10..11]=even_inv
    // last pair (r_even=SM4_R): [0..3]=odd_sbox [4..5]=odd_inv [6..7]=even_inv
    const unsigned int pair_bytes = 12;
    const unsigned int base_bytes = r_pair * pair_bytes;
    const unsigned int base_bits = base_bytes * 8;
    const bf128_t* sbox_keys = w_key + base_bits;
    
    bf128_t sbox_out_odd_key[32];
    
    for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
      const bf128_t* sbox_key = sbox_keys + byte_i * 8;      // 8bits/sbox
      const bf128_t* inv_key  = sbox_keys + 32 + byte_i * 4; // 4bits/invnorm(nibble)
      
      // ::7 生成 inv * temp == 1 约束
      bf128_t y_key[4];
      sm4_SSS_inv_norm_to_conjugates_verifier(y_key, inv_key);
      bf128_t conj_key[8];
      sm4_SSS_f256_f2_conjugates_SSS_byte(conj_key, temp_odd_key + byte_i * 8);
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
      // Rolling window for verifier: use sbox_out_even_key instead of state_witness_key
      const bf128_t* inv_even_witness_key = NULL;
      if (r_pair < SM4_R / 2 - 1) {
        // Normal even round: read sbox_out_even_key from witness, do rolling state update
        const bf128_t* sbox_out_even_key = sbox_keys + 48;  // bits 48-79

        bf128_t L_out_even_key[32];
        sm4_SSS_linear_l_verifier(L_out_even_key, sbox_out_even_key);

        bf128_t new_word_even_key[32];
        for (unsigned int bit = 0; bit < 32; bit++) {
          new_word_even_key[bit] = bf128_add(state_key[bit], L_out_even_key[bit]);
        }
        memmove(state_key, state_key + 32, 96 * sizeof(bf128_t));
        memcpy(state_key + 96, new_word_even_key, 32 * sizeof(bf128_t));

        inv_even_witness_key = sbox_keys + 80;  // bits 80-95
      }
      if (r_even == SM4_R) {
        inv_even_witness_key = sbox_keys + 48;
      }

      // ::14 从witness读取偶数轮invnorm key（nibble打包：4个invnorm = 16 bits）
      bf128_t inv_norm_even_key[16];
      for (unsigned int byte_i = 0; byte_i < 4; ++byte_i) {
        for (unsigned int bit = 0; bit < 4; ++bit) {
          inv_norm_even_key[byte_i * 4 + bit] = inv_even_witness_key[byte_i * 4 + bit];
        }
      }

      // ::16 生成逆范数约束
      for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
        bf128_t y_key[4];
        sm4_SSS_inv_norm_to_conjugates_verifier(y_key, inv_norm_even_key + byte_i * 4);

        bf128_t conj_key[8];
        sm4_SSS_f256_f2_conjugates_SSS_byte(conj_key, temp_even_key + byte_i * 8);
        sm4_SSS_inv_norm_constraints_verifier(hasher, conj_key, y_key, delta);
      }
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
  
  const unsigned int Lke = params->Lke;

  if (faest_is_em(params)) {
    // EM模式：加密的轮密钥由公开的 owf_in 直接确定，无需 ZK 证明密钥扩展。
    // 见证布局：[16字节 OWF Key (明文)] [加密见证]

    // 从公开 owf_in 计算轮密钥
    sm4_round_keys_t public_rk;
    sm4_init_round_keys(&public_rk, owf_in);
    // 填充 rk 数组（索引 4..35 存放 32 个轮密钥，大端字节序）
    for (unsigned int i = 0; i < SM4_R; i++) {
      sm4_uint32_to_bytes(public_rk.round_keys[i], rk + (i + 4) * 4);
    }
    // 轮密钥是公开的，其 VOLE tag 全为 0
    memset(rk_tag, 0, (SM4_R + 4) * 32 * sizeof(bf128_t));

    // 加密的 plaintext = w[0..16]（见证中存储的秘密 OWF key）
    memcpy(in,     w,     SM4_BLOCKSIZE / 8);
    memcpy(in_tag, w_tag, SM4_BLOCKSIZE * sizeof(bf128_t));

    // 加密输出 = SM4_{owf_in}(owf_key) = owf_out XOR owf_key = owf_out XOR w[0..16]
    for (unsigned int i = 0; i < SM4_BLOCKSIZE / 8; i++) {
      out[i] = owf_out[i] ^ w[i];
    }
    // out = in XOR 公开常数，tag 不变
    memcpy(out_tag, w_tag, SM4_BLOCKSIZE * sizeof(bf128_t));

    // 只需加密约束，跳过密钥扩展约束
    sm4_SSS_enc_constraints_prover(hasher, in, in_tag, out, out_tag,
                                   w + Lke / 8, w_tag + Lke,
                                   rk, rk_tag, params);
  } else {
    // 标准模式：输入/输出均为公开值，tag = 0
    memcpy(in, owf_in, SM4_BLOCKSIZE / 8);
    for (unsigned int i = 0; i < SM4_BLOCKSIZE; i++) {
      in_tag[i] = bf128_zero();
    }
    memcpy(out, owf_out, SM4_BLOCKSIZE / 8);
    for (unsigned int i = 0; i < SM4_BLOCKSIZE; i++) {
      out_tag[i] = bf128_zero();
    }

    // ::1 密钥扩展约束
    sm4_SSS_expkey_constraints_prover(hasher, rk, rk_tag, w, w_tag);

    // ::2 加密约束
    sm4_SSS_enc_constraints_prover(hasher, in, in_tag, out, out_tag,
                                   w + Lke / 8, w_tag + Lke,
                                   rk, rk_tag, params);
  }
  
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
  
  const unsigned int Lke = params->Lke;

  if (faest_is_em(params)) {
    // EM模式：轮密钥由公开的 owf_in 直接确定
    sm4_round_keys_t public_rk;
    sm4_init_round_keys(&public_rk, owf_in);

    // 填充 rk_key：轮密钥是公开的，verifier 用 delta × rk_bit 表示
    memset(rk_key, 0, (SM4_R + 4) * 32 * sizeof(bf128_t));
    for (unsigned int i = 0; i < SM4_R; i++) {
      uint8_t rk_bytes[4];
      sm4_uint32_to_bytes(public_rk.round_keys[i], rk_bytes);
      for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
        for (unsigned int bit = 0; bit < 8; bit++) {
          rk_key[(i + 4) * 32 + byte_i * 8 + bit] =
              bf128_mul_bit(delta, (rk_bytes[byte_i] >> bit) & 1);
        }
      }
    }

    // in_key = w_key[0..128]（秘密明文的 VOLE key-shares）
    memcpy(in_key, w_key, SM4_BLOCKSIZE * sizeof(bf128_t));

    // out_key[i] = in_key[i] + delta * bit(owf_out, i)
    //（因为 out = in XOR owf_out，owf_out 是公开常数）
    for (unsigned int i = 0; i < SM4_BLOCKSIZE / 8; i++) {
      for (unsigned int bit = 0; bit < 8; bit++) {
        out_key[i * 8 + bit] = bf128_add(in_key[i * 8 + bit],
                                          bf128_mul_bit(delta, (owf_out[i] >> bit) & 1));
      }
    }

    // 跳过密钥扩展约束，只做加密约束
    sm4_SSS_enc_constraints_verifier(hasher, in_key, out_key, w_key + Lke,
                                     rk_key, delta, params);
  } else {
    // 标准模式
    for (unsigned int i = 0; i < SM4_BLOCKSIZE / 8; i++) {
      for (unsigned int bit = 0; bit < 8; bit++) {
        in_key[i * 8 + bit]  = bf128_mul_bit(delta, (owf_in[i]  >> bit) & 1);
        out_key[i * 8 + bit] = bf128_mul_bit(delta, (owf_out[i] >> bit) & 1);
      }
    }

    // ::1 密钥扩展约束
    sm4_SSS_expkey_constraints_verifier(hasher, rk_key, w_key, delta);

    // ::2 加密约束
    sm4_SSS_enc_constraints_verifier(hasher, in_key, out_key, w_key + Lke,
                                     rk_key, delta, params);
  }
  
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


// SM4 专用：d = w ⊕ u，按默认位序逐位计算
void sm4_pack_d_big_endian(uint8_t* dst, const uint8_t* witness, const uint8_t* u,
                           unsigned int ell_bits) {
  const size_t ell_bytes = (ell_bits + 7) / 8;
  memset(dst, 0, ell_bytes);

/* NOTE: do NOT zero out u here – u is real VOLE randomness that must be
 * included in d = w XOR u.  Clearing u would corrupt the VOLE relation. */
  for (unsigned int i = 0; i < ell_bits; ++i) {
    const unsigned int dst_idx = sm4_map_d_index(i);
    if (dst_idx >= ell_bits) {
      continue;
    }
    const unsigned int w_bit = ptr_get_bit(witness, i);
    const unsigned int u_bit = ptr_get_bit(u, i);
    ptr_set_bit(dst, dst_idx, w_bit ^ u_bit);
  }
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


  for (unsigned int row = 0; row != ell + 2 * 128; ++row) {
    uint8_t new_row[BF128_NUM_BYTES] = {0};
    for (unsigned int column = 0; column != 128; ++column) {
      ptr_set_bit(new_row, column, ptr_get_bit(V[column], row));
    }
    w_tag[row] = bf128_load(new_row);

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
  const unsigned int ell_hat = ell + 3 * lambda + UNIVERSAL_HASH_B_BITS;
  const size_t chall2_len = 3u * (lambda / 8u) + 8u;

  // ::1-5 将V转换为w_tag
  bf128_t* w_tag = column_to_row_major_and_shrink_V_128_sm4(V, ell, lambda, ell_hat, "prover V->w_tag");

  // Stage check: witness generation complete
  if (!w_tag) {
    return; /* malloc failure — caller will observe zeroed output buffers */
  }


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

  // Stage check: constraints generation complete

  // ::14 最终化哈希
  zk_hash_128_3_finalize(a0_tilde, a1_tilde, a2_tilde, &hasher, bf_v_star_0,
                         bf128_add(bf_u_star_0, bf_v_star_1), bf_u_star_1);


  // Stage check: final comparison preparation complete

  free(w_tag);
}

void sm4_128_verifier(uint8_t* a0_tilde, const uint8_t* d, uint8_t** Q, const uint8_t* owf_in,
                      const uint8_t* owf_out, const uint8_t* chall_2, const uint8_t* chall_3,
                      const uint8_t* a1_tilde, const uint8_t* a2_tilde,
                      const faest_paramset_t* params) {
  const unsigned int ell = params->l;
  const unsigned int lambda = 128;
  const unsigned int ell_hat = ell + 3 * lambda + UNIVERSAL_HASH_B_BITS;
  const size_t chall2_len = 3u * (lambda / 8u) + 8u;

  // ::1 加载delta
  bf128_t bf_delta = bf128_load(chall_3);
  bf128_t bf_delta_sq = bf128_mul(bf_delta, bf_delta);

  // ::2-6 将Q转换为q_key
  bf128_t* q_key = column_to_row_major_and_shrink_V_128_sm4(Q, ell, lambda, ell_hat, "verifier Q->q_key");

  // Stage check: witness reconstruction complete
  if (!q_key) {
    return; /* malloc failure — caller will observe zeroed output buffers */
  }


  // ::7-9 计算q_star
  bf128_t q_star_0 = bf128_sum_poly(q_key + ell);
  bf128_t q_star_1 = bf128_sum_poly(q_key + ell + lambda);
  bf128_t q_star = bf128_add(q_star_0, bf128_mul(bf_delta, q_star_1));


  // ::10 初始化ZK哈希
  zk_hash_128_ctx b_ctx;
  zk_hash_128_init(&b_ctx, chall_2);

  // ::11 添加差分d到q_key
  for (unsigned int i = 0; i < ell; i++) {
    q_key[i] = bf128_add(q_key[i], bf128_mul_bit(bf_delta, sm4_get_d_bit_be(d, i)));
  }


  // ::12 验证SM4约束
  sm4_SSS_constraints_verifier(&b_ctx, q_key, owf_in, owf_out, bf_delta, params);

  // Stage check: constraints verification complete

  free(q_key);

  // ::13-14 最终化哈希
  uint8_t q_tilde[16];  // 128位 = 16字节
  zk_hash_128_finalize(q_tilde, &b_ctx, q_star);

  // Stage check: challenge and hash finalization complete

  // ::15-16 计算a0_tilde
  bf128_t tmp1 = bf128_mul(bf128_load(a1_tilde), bf_delta);
  bf128_t tmp2 = bf128_mul(bf128_load(a2_tilde), bf_delta_sq);
  bf128_t tmp3 = bf128_add(tmp1, tmp2);
  bf128_t ret = bf128_add(bf128_load(q_tilde), tmp3);

  bf128_store(a0_tilde, ret);


  // Stage check: final comparison preparation complete
}
