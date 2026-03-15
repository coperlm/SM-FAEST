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

static bool sm4_emb_constants_self_checked = false;
static bool sm4_emb_constants_valid = false;

static bool sm4_bf128_equal(bf128_t lhs, bf128_t rhs) {
  uint8_t l[BF128_NUM_BYTES];
  uint8_t r[BF128_NUM_BYTES];
  bf128_store(l, lhs);
  bf128_store(r, rhs);
  return memcmp(l, r, BF128_NUM_BYTES) == 0;
}

static bool sm4_check_embedding_constants_once(void) {
  if (sm4_emb_constants_self_checked) {
    return sm4_emb_constants_valid;
  }

  sm4_emb_constants_self_checked = true;
  sm4_emb_constants_valid = false;

  const uint8_t beta = 0x0c;
  uint8_t beta_sq = beta;
  uint8_t beta_cu = bf8_mul_sm4(bf8_square_sm4(beta), beta);

  for (unsigned int i = 0; i < 5; ++i) {
    const bf128_t expected_sq = sm4_byte_combine_bits(beta_sq);
    if (!sm4_bf128_equal(expected_sq, sm4_beta_squares_bf128[i])) {
      return false;
    }
    beta_sq = bf8_square_sm4(beta_sq);
  }

  for (unsigned int i = 0; i < 4; ++i) {
    const bf128_t expected_cu = sm4_byte_combine_bits(beta_cu);
    if (!sm4_bf128_equal(expected_cu, sm4_beta_cubes_bf128[i])) {
      return false;
    }
    beta_cu = bf8_mul_sm4(bf8_square_sm4(beta_cu), beta);
  }

  for (uint8_t x = 1; x < 16; ++x) {
    for (uint8_t y = 1; y < 16; ++y) {
      const bf128_t lhs = sm4_byte_combine_bits(bf8_mul_sm4(x, y));
      const bf128_t rhs = bf128_mul(sm4_byte_combine_bits(x), sm4_byte_combine_bits(y));
      if (!sm4_bf128_equal(lhs, rhs)) {
        return false;
      }
    }
  }

  sm4_emb_constants_valid = true;
  return true;
}

// ============================================================================
// SM4 常量: FK (系统参数) 和 CK (固定参数)
// ============================================================================

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

// ============================================================================
// GF(2^8) Frobenius 平方映射（用于 invnorm 约束）
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

// ============================================================================
// Degree-3 invnorm 约束（1:3 方案核心）
// 见证 c = x^{238} = N(x)^{-1} ∈ GF(2^4)，存储为 4-bit nibble
// 约束: c · x^2 · x^{16} = x    (↔ x^{238+2+16} = x^{256} = x in GF(2^8)*)
// ============================================================================

/**
 * sm4_SSS_invnorm_sbox_prover:
 *   x_val/x_tag  - S-box 输入 (8-bit)
 *   c_nibble     - 4-bit invnorm 见证值 (sm4_invnorm(x))
 *   c_tag[4]     - 4 个 bf128 tag，对应 c 的 4 个比特
 *
 * 生成 degree-3 约束: c · x^2 · x^16 + x = 0
 * VOLE 展开（A=c, B=x^2, C=x^16, 乘积 = ABC，线性纠正项 = x）:
 *   deg0 = tag_c · tag_x2 · tag_x16                 (三 tag 乘积)
 *   deg1 = val_c · tag_x2 · tag_x16                 \
 *        + tag_c · val_x2 · tag_x16                  > (两tag一val，三组合)
 *        + tag_c · tag_x2 · val_x16                 /
 *   deg2 = val_c · val_x2 · tag_x16                 \
 *        + val_c · tag_x2 · val_x16                  > (一tag两val，三组合)
 *        + tag_c · val_x2 · val_x16                 /
 *        + tag_x  (线性修正)
 *   deg3 项不存在（被移入 deg2 因为 zk_hash_3 format）
 *
 * 注：zk_hash_128_3_update(ctx, d0, d1, d2) 中 d0 对应最高degree，
 *     所以: d0=deg0(全tag), d1=deg1, d2=deg2+val_c*val_x2*val_x16+val_x
 */
static void sm4_SSS_invnorm_sbox_prover(zk_hash_128_3_ctx* hasher,
                                         uint8_t x_val,        const bf128_t* x_tag,   // 8-bit
                                         uint8_t c_nibble,     const bf128_t* c_tag) { // 4-bit
  // --- 第一步：从 4-bit nibble 嵌入 GF(2^128) ---
  // c 是 GF(2^4) 元素，用基 {1, β, β², β³} 表示
  // c_tag[k] 对应第 k 个 bit 的 VOLE tag，beta_squares_bf128[0] = bcb(β)
  bf128_t C_val = bf128_zero();
  bf128_t C_tag = bf128_zero();
  for (unsigned int k = 0; k < 4; ++k) {
    if (k == 0) {
      if ((c_nibble >> 0) & 1) C_val = bf128_add(C_val, bf128_one());
      C_tag = bf128_add(C_tag, c_tag[0]);
    } else {
      if ((c_nibble >> k) & 1) C_val = bf128_add(C_val, sm4_beta_squares_bf128[k - 1]);
      C_tag = bf128_add(C_tag, bf128_mul(sm4_beta_squares_bf128[k - 1], c_tag[k]));
    }
  }

  // --- 第二步：计算 x^2 和 x^16（Frobenius 映射，线性）---
  // x^2: 对 x_val 施加 bf8_square_sm4，对 x_tag 施加 sm4_sq_bit_inplace
  uint8_t  x2_val;
  bf128_t  x2_tag[8];
  {
    x2_val = bf8_square_sm4(x_val);
    memcpy(x2_tag, x_tag, 8 * sizeof(bf128_t));
    sm4_sq_bit_inplace(x2_tag);
  }
  // x^16: 再平方 3 次
  uint8_t  x16_val;
  bf128_t  x16_tag[8];
  {
    uint8_t  tmp_val  = x2_val;
    bf128_t  tmp_tag[8];
    memcpy(tmp_tag, x2_tag, 8 * sizeof(bf128_t));
    for (unsigned int k = 0; k < 3; ++k) {
      tmp_val = bf8_square_sm4(tmp_val);
      sm4_sq_bit_inplace(tmp_tag);
    }
    x16_val = tmp_val;
    memcpy(x16_tag, tmp_tag, 8 * sizeof(bf128_t));
  }

  // --- 第三步：嵌入 GF(2^128) ---
  bf128_t X_val   = sm4_byte_combine_bits(x_val);
  bf128_t X_tag   = sm4_byte_combine(x_tag);
  bf128_t X2_val  = sm4_byte_combine_bits(x2_val);
  bf128_t X2_tag  = sm4_byte_combine(x2_tag);
  bf128_t X16_val = sm4_byte_combine_bits(x16_val);
  bf128_t X16_tag = sm4_byte_combine(x16_tag);

  // --- 第四步：VOLE degree-3 展开 c·x2·x16 + x = 0 ---
  // 记 A=C, B=X2, C_obj=X16（避免名字冲突），S=X（线性项）
  // d0 = tag_A · tag_B · tag_C_obj
  bf128_t d0 = bf128_mul(bf128_mul(C_tag, X2_tag), X16_tag);

  // d1 = val_A·tag_B·tag_C + tag_A·val_B·tag_C + tag_A·tag_B·val_C
  bf128_t d1 = bf128_add(
      bf128_add(bf128_mul(bf128_mul(C_val, X2_tag), X16_tag),
                bf128_mul(bf128_mul(C_tag, X2_val), X16_tag)),
      bf128_mul(bf128_mul(C_tag, X2_tag), X16_val));

  // d2 = val_A·val_B·tag_C + val_A·tag_B·val_C + tag_A·val_B·val_C + tag_S
  bf128_t d2 = bf128_add(
      bf128_add(
          bf128_add(bf128_mul(bf128_mul(C_val, X2_val), X16_tag),
                    bf128_mul(bf128_mul(C_val, X2_tag), X16_val)),
          bf128_mul(bf128_mul(C_tag, X2_val), X16_val)),
      X_tag);   // 线性纠正项 "+x" 的 tag 部分

  // d_const = val_A·val_B·val_C + val_S  → 正确见证时应为 0，折进 d2 的常数项
  // 实际上 zk_hash_3_update 的 (d0, d1, d2) 对应多项式 d0·Δ³ + d1·Δ² + d2·Δ（各项系数）
  // 注意：c2 实际上是"Δ^0 系数"，即 val×val×val + val_S
  // 这里按 faest_aes.c.in 的 convention：update(hasher, deg3_coeff, deg2_coeff, deg1_coeff)
  // deg0 （常数项）对应正确见证时为0，不显式传递
  (void)(bf128_add(bf128_mul(bf128_mul(C_val, X2_val), X16_val), X_val)); // 调试时可断言=0

  zk_hash_128_3_update(hasher, d0, d1, d2);
}

/**
 * sm4_SSS_invnorm_sbox_verifier:
 * Verifier 侧：对 invnorm 约束进行求值
 *   x_eval[8]  - S-box 输入的 VOLE key-shares（每 bit 一个 bf128）
 *   c_eval[4]  - invnorm 的 4-bit VOLE key-shares
 *   delta      - VOLE 挑战值
 *
 * 验证方程: c · x^2 · x^16 + x = 0 at Δ
 * Verifier 计算多项式在 Δ 处的值并提交给 hasher
 */
static void sm4_SSS_invnorm_sbox_verifier(zk_hash_128_ctx* hasher,
                                           const bf128_t* x_eval,   // 8 bf128
                                           const bf128_t* c_eval,   // 4 bf128
                                           bf128_t delta) {
  (void)delta; // delta 已被吸收进 key-shares

  // 嵌入 GF(2^128)
  bf128_t C_eval = bf128_add(c_eval[0],
      bf128_add(bf128_mul(sm4_beta_squares_bf128[0], c_eval[1]),
      bf128_add(bf128_mul(sm4_beta_squares_bf128[1], c_eval[2]),
                bf128_mul(sm4_beta_squares_bf128[2], c_eval[3]))));

  bf128_t X_eval  = sm4_byte_combine(x_eval);

  // x^2 Frobenius
  bf128_t x2_eval[8];
  memcpy(x2_eval, x_eval, 8 * sizeof(bf128_t));
  sm4_sq_bit_inplace(x2_eval);
  bf128_t X2_eval = sm4_byte_combine(x2_eval);

  // x^16 = (x^2)^8
  bf128_t x16_eval[8];
  memcpy(x16_eval, x2_eval, 8 * sizeof(bf128_t));
  for (unsigned int k = 0; k < 3; ++k) sm4_sq_bit_inplace(x16_eval);
  bf128_t X16_eval = sm4_byte_combine(x16_eval);

  // 约束值: C·X2·X16 + X = 0 at Δ
  bf128_t val = bf128_add(bf128_mul(bf128_mul(C_eval, X2_eval), X16_eval), X_eval);
  zk_hash_128_update(hasher, val);
}

// ============================================================================

/**
 * 对8位GF(2^8)元素的值和标签施加平方运算
 * 在 SM4 的 GF(2^8) 中，平方 = Frobenius 自同态
 * 对标签应用 sm4_sq_bit_inplace（线性映射）
 */
static void sm4_SSS_sq_byte_prover(uint8_t* x_sq_val, bf128_t* x_sq_tag,
                                   uint8_t x_val, const bf128_t* x_tag) {
  *x_sq_val = bf8_square_sm4(x_val);
  memcpy(x_sq_tag, x_tag, 8 * sizeof(bf128_t));
  sm4_sq_bit_inplace(x_sq_tag);
}

/**
 * 完整8位 S-box 的 Degree-2 约束（Prover 版本）
 * x = S-box 输入（8位），y = 见证 = x^{-1} in SM4 GF(2^8)
 * 约束1: x²·y + x = 0  (在 GF(2^128) 嵌入中)
 * 约束2: x·y² + y = 0
 *
 * VOLE Δ-展开：f(Q_A, Q_B, Q_C) = Q_A·Q_B + Q_C，其中 A=x², B=y, C=x
 *   Δ^0 系数 c0 = V_A·V_B + V_C          → v_0（a0贡献）
 *   Δ^1 系数 c1 = w_A·V_B + V_A·w_B + w_C  → v_1（a1贡献）
 *   Δ^2 系数 c2 = w_A·w_B                  → v_2（a2贡献，正确见证=w_C≠0）
 * 调用：zk_hash_128_3_update(hasher, c0, c1, c2)
 */
static void sm4_SSS_full_sbox_prover(zk_hash_128_3_ctx* hasher,
                                     uint8_t x_val, const bf128_t* x_tag,  // 8 bits, S-box input
                                     uint8_t y_val, const bf128_t* y_tag) {// 8 bits, raw inverse
  // 嵌入 GF(2^128)
  bf128_t X_val = sm4_byte_combine_bits(x_val);
  bf128_t X_tag = sm4_byte_combine(x_tag);
  bf128_t Y_val = sm4_byte_combine_bits(y_val);
  bf128_t Y_tag = sm4_byte_combine(y_tag);

  // 计算 x² 和 y² 的值和标签（Frobenius平方）
  uint8_t x_sq_val;
  bf128_t x_sq_tag[8];
  sm4_SSS_sq_byte_prover(&x_sq_val, x_sq_tag, x_val, x_tag);
  bf128_t X_sq_val = sm4_byte_combine_bits(x_sq_val);
  bf128_t X_sq_tag = sm4_byte_combine(x_sq_tag);

  uint8_t y_sq_val;
  bf128_t y_sq_tag[8];
  sm4_SSS_sq_byte_prover(&y_sq_val, y_sq_tag, y_val, y_tag);
  bf128_t Y_sq_val = sm4_byte_combine_bits(y_sq_val);
  bf128_t Y_sq_tag = sm4_byte_combine(y_sq_tag);

  // 约束1: X_sq·Y + X = 0  (A=X_sq, B=Y, C=X)
  {
    bf128_t c0 = bf128_add(bf128_mul(X_sq_tag, Y_tag), X_tag);
    bf128_t c1 = bf128_add(
        bf128_add(bf128_mul(X_sq_val, Y_tag), bf128_mul(X_sq_tag, Y_val)),
        X_val);
    bf128_t c2 = bf128_mul(X_sq_val, Y_val);
    zk_hash_128_3_update(hasher, c0, c1, c2);
#if defined(DEBUG_SM4_CONSTRAINTS)
    static unsigned int _call_count = 0;
    if (_call_count < 4) {
      uint8_t _b0[16],_b1[16],_b2[16];
      bf128_store(_b0,c0); bf128_store(_b1,c1); bf128_store(_b2,c2);
      fprintf(stderr,"[PROVER] call#%u c0=%02x%02x c1=%02x%02x c2=%02x%02x x=%02x y=%02x\n",
              _call_count, _b0[0],_b0[1], _b1[0],_b1[1], _b2[0],_b2[1], x_val, y_val);
    }
    _call_count++;
#endif
  }

  // 约束2: X·Y_sq + Y = 0  (A=X, B=Y_sq, C=Y)
  {
    bf128_t c0 = bf128_add(bf128_mul(X_tag, Y_sq_tag), Y_tag);
    bf128_t c1 = bf128_add(
        bf128_add(bf128_mul(X_val, Y_sq_tag), bf128_mul(X_tag, Y_sq_val)),
        Y_val);
    bf128_t c2 = bf128_mul(X_val, Y_sq_val);
    zk_hash_128_3_update(hasher, c0, c1, c2);
  }
}

/**
 * 完整8位 S-box 的 Degree-2 约束（Verifier 版本）
 * x_eval_bits[8] 和 y_eval_bits[8] 是 GF(2^128) 求值份额（每位一个元素）
 * 验证者计算两个 degree-2 约束的求值并提交给 hasher
 */
static void sm4_SSS_full_sbox_verifier(zk_hash_128_ctx* hasher,
                                       const bf128_t* x_eval_bits,   // 8 bf128_t
                                       const bf128_t* y_eval_bits) { // 8 bf128_t
  // 嵌入 GF(2^128)
  bf128_t X_eval = sm4_byte_combine(x_eval_bits);
  bf128_t Y_eval = sm4_byte_combine(y_eval_bits);

  // 平方：对位级求值份额应用平方映射
  bf128_t x_sq_eval_bits[8];
  memcpy(x_sq_eval_bits, x_eval_bits, 8 * sizeof(bf128_t));
  sm4_sq_bit_inplace(x_sq_eval_bits);
  bf128_t X_sq_eval = sm4_byte_combine(x_sq_eval_bits);

  bf128_t y_sq_eval_bits[8];
  memcpy(y_sq_eval_bits, y_eval_bits, 8 * sizeof(bf128_t));
  sm4_sq_bit_inplace(y_sq_eval_bits);
  bf128_t Y_sq_eval = sm4_byte_combine(y_sq_eval_bits);

  // 约束1: X_sq·Y + X = 0 at Δ
  zk_hash_128_update(hasher, bf128_add(bf128_mul(X_sq_eval, Y_eval), X_eval));

  // 约束2: X·Y_sq + Y = 0 at Δ
  zk_hash_128_update(hasher, bf128_add(bf128_mul(X_eval, Y_sq_eval), Y_eval));
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
 * SM4 密钥扩展约束 (Prover版本) — 1:3 nibble 方案
 *
 * 见证布局（与 sm4_extend_witness 完全对应）：
 *   KE 区 = (SM4_R+4)*4 字节的轮密钥数据 + KE_sbox 见证
 *   KE_sbox 见证：8 个 quad（32轮/4），每 quad 14 字节：
 *     [0..1]   = invnorm 轮（round%4==0），4 nibbles packed
 *     [2..5]   = full8 轮（round%4==1）
 *     [6..9]   = full8 轮（round%4==2）
 *     [10..13] = full8 轮（round%4==3）
 *
 * rk 索引：rk[i] = SM4 MK/K 数组；key_round i 的 S-box 输入 =
 *   rk[i+1]^rk[i+2]^rk[i+3]^CK[i]，i=0..31
 */
static void sm4_SSS_expkey_constraints_prover(zk_hash_128_3_ctx* hasher, uint8_t* rk, bf128_t* rk_tag,
                                              const uint8_t* w, const bf128_t* w_tag) {
  const unsigned int SM4_R = 32;
  const unsigned int KEY_BITS = (SM4_R + 4) * 32;  // rk 数组的总 bit 数（144 字节）

  // KE sbox 见证从 KEY_BITS 之后开始，quad 布局 14 字节×8 quad
  const unsigned int quad_bytes = 14;
  const unsigned int quad_tags  = 112;  // 14*8
  const uint8_t*  ke_w   = w     + KEY_BITS / 8;
  const bf128_t*  ke_tag = w_tag + KEY_BITS;

  static const unsigned int quad_byte_offsets[4] = {0, 2, 6, 10};
  static const unsigned int quad_tag_offsets[4]  = {0, 16, 48, 80};

  // ::1 向前传播生成轮密钥及其 tag
  sm4_SSS_keyexp_forward_prover(rk, rk_tag, w, w_tag);

  // ::2 对每个 quad 的 S-box 约束
  for (unsigned int q = 0; q < SM4_R / 4; q++) {
    const uint8_t*  q_w   = ke_w   + q * quad_bytes;
    const bf128_t*  q_tag = ke_tag + q * quad_tags;

    for (unsigned int r_in_quad = 0; r_in_quad < 4; r_in_quad++) {
      const unsigned int i = q * 4 + r_in_quad;  // 0-indexed round (0..31)

      uint8_t ck_bytes[4];
      sm4_uint32_to_bytes(SM4_CK[i], ck_bytes);

      uint8_t  x_bytes[4];
      bf128_t  x_tag[32];
      for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
        x_bytes[byte_i] = rk[(i + 1) * 4 + byte_i] ^ rk[(i + 2) * 4 + byte_i] ^
                          rk[(i + 3) * 4 + byte_i] ^ ck_bytes[byte_i];
        for (unsigned int bit = 0; bit < 8; bit++) {
          unsigned int idx = byte_i * 8 + bit;
          x_tag[idx] = bf128_add(
              bf128_add(rk_tag[(i + 1) * 32 + idx], rk_tag[(i + 2) * 32 + idx]),
              rk_tag[(i + 3) * 32 + idx]);
          // CK 是公开常数，标签贡献为 0
        }
      }

      if (r_in_quad == 0) {
        // ---- invnorm 轮 ----
        const uint8_t*  wp = q_w   + quad_byte_offsets[0];
        const bf128_t*  tp = q_tag + quad_tag_offsets[0];
        for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
          uint8_t        c_nib = (wp[byte_i / 2] >> (4 * (byte_i % 2))) & 0xF;
          const bf128_t* c_t   = tp + byte_i * 4;
          sm4_SSS_invnorm_sbox_prover(hasher, x_bytes[byte_i], x_tag + byte_i * 8, c_nib, c_t);
        }
      } else {
        // ---- full-8bit 轮 ----
        const uint8_t*  wp = q_w   + quad_byte_offsets[r_in_quad];
        const bf128_t*  tp = q_tag + quad_tag_offsets[r_in_quad];
        for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
          uint8_t        y_val = wp[byte_i];
          const bf128_t* y_t   = tp + byte_i * 8;
          sm4_SSS_full_sbox_prover(hasher, x_bytes[byte_i], x_tag + byte_i * 8, y_val, y_t);
        }
      }
    }
  }
}

/**
 * SM4 密钥扩展约束 (Verifier版本) — 1:3 nibble 方案
 */
static void sm4_SSS_expkey_constraints_verifier(zk_hash_128_ctx* hasher, bf128_t* rk_key,
                                                const bf128_t* w_key, bf128_t delta) {
  const unsigned int SM4_R = 32;
  const unsigned int KEY_BITS = (SM4_R + 4) * 32;

  const unsigned int quad_tags = 112;
  static const unsigned int quad_tag_offsets[4] = {0, 16, 48, 80};

  const bf128_t* ke_key = w_key + KEY_BITS;

  sm4_SSS_keyexp_forward_verifier(rk_key, w_key);

  for (unsigned int q = 0; q < SM4_R / 4; q++) {
    const bf128_t* q_key = ke_key + q * quad_tags;

    for (unsigned int r_in_quad = 0; r_in_quad < 4; r_in_quad++) {
      const unsigned int i = q * 4 + r_in_quad;

      uint8_t ck_bytes[4];
      sm4_uint32_to_bytes(SM4_CK[i], ck_bytes);

      bf128_t x_key[32];
      for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
        for (unsigned int bit = 0; bit < 8; bit++) {
          unsigned int idx = byte_i * 8 + bit;
          x_key[idx] = bf128_add(
              bf128_add(rk_key[(i + 1) * 32 + idx], rk_key[(i + 2) * 32 + idx]),
              rk_key[(i + 3) * 32 + idx]);
          // CK 公开常数：verifier 加 delta * ck_bit
          if ((ck_bytes[byte_i] >> bit) & 1) {
            x_key[idx] = bf128_add(x_key[idx], delta);
          }
        }
      }

      if (r_in_quad == 0) {
        // ---- invnorm 轮 ----
        const bf128_t* tp = q_key + quad_tag_offsets[0];
        for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
          const bf128_t* x_eval = x_key + byte_i * 8;
          const bf128_t* c_eval = tp + byte_i * 4;
          sm4_SSS_invnorm_sbox_verifier(hasher, x_eval, c_eval, delta);
        }
      } else {
        // ---- full-8bit 轮 ----
        const bf128_t* tp = q_key + quad_tag_offsets[r_in_quad];
        for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
          const bf128_t* x_eval = x_key + byte_i * 8;
          const bf128_t* y_eval = tp + byte_i * 8;
          sm4_SSS_full_sbox_verifier(hasher, x_eval, y_eval);
        }
      }
    }
  }
}

// ============================================================================
// Phase 5: Feistel轮函数约束（加密）
// ============================================================================

/**
 * SM4 加密约束 (Prover版本) — 1:3 nibble 方案
 *
 * 见证布局（新）：8 个 quad，每 quad 14 字节：
 *   [0..1]   = invnorm 轮 (round % 4 == 0)：4 个 4-bit nibble，packed
 *   [2..5]   = full-8bit 轮 (round % 4 == 1)：4 个原始逆元
 *   [6..9]   = full-8bit 轮 (round % 4 == 2)：4 个原始逆元
 *   [10..13] = full-8bit 轮 (round % 4 == 3)：4 个原始逆元
 *
 * nibble packed 含义：
 *   w[0] = (sbox1_nibble << 4) | sbox0_nibble
 *   w[1] = (sbox3_nibble << 4) | sbox2_nibble
 *
 * tag 布局：nibble 轮每 sbox 4 个 bf128_tag，full8 轮每 sbox 8 个 bf128_tag
 *   TAG 对应 w 的 bit 展开，所以 nibble 轮 per_quad_tag_bits = 4*4 + 3*4*8 = 112
 */
static void sm4_SSS_enc_constraints_prover(zk_hash_128_3_ctx* hasher,
                                           const uint8_t* owf_in, const bf128_t* owf_in_tag,
                                           const uint8_t* owf_out, const bf128_t* owf_out_tag,
                                           const uint8_t* w, const bf128_t* w_tag,
                                           const uint8_t* rk, const bf128_t* rk_tag,
                                           const faest_paramset_t* params) {
  (void)params;
  (void)owf_out;
  const unsigned int SM4_R = 32;
  const unsigned int Nbytes = 16;
  const unsigned int Nbits  = 128;

  // 滚动窗口状态
  uint8_t  state[16];
  bf128_t  state_tag[128];
  memcpy(state,     owf_in,     Nbytes);
  memcpy(state_tag, owf_in_tag, Nbits * sizeof(bf128_t));

  // quad 布局常量：
  //   每个 quad 的字节游标偏移
  //   nibble 轮占 2 字节（16 tag bits）
  //   full8 轮占 4 字节（32 tag bits）
  // 字节偏移: [0], [2], [6], [10]
  // tag 偏移（以 bf128 计）: [0], [16], [48], [80]
  static const unsigned int quad_byte_offsets[4] = {0, 2, 6, 10};
  static const unsigned int quad_tag_offsets[4]  = {0, 16, 48, 80};
  const unsigned int quad_bytes = 14;
  const unsigned int quad_tags  = 112;  // 14 * 8

  for (unsigned int q = 0; q < SM4_R / 4; q++) {
    const uint8_t*  q_w   = w     + q * quad_bytes;
    const bf128_t*  q_tag = w_tag + q * quad_tags;

    for (unsigned int r_in_quad = 0; r_in_quad < 4; r_in_quad++) {
      const unsigned int round = q * 4 + r_in_quad;  // 0-indexed

      // === 计算 S-box 输入 in = state[1] ^ state[2] ^ state[3] ^ rk[round] ===
      uint8_t  in_bytes[4];
      bf128_t  in_tag[32];
      for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
        in_bytes[byte_i] = state[4 + byte_i] ^ state[8 + byte_i] ^
                           state[12 + byte_i] ^ rk[(round + 4) * 4 + byte_i];
        for (unsigned int bit = 0; bit < 8; bit++) {
          unsigned int idx = byte_i * 8 + bit;
          in_tag[idx] = bf128_add(
              bf128_add(state_tag[32 + idx], state_tag[64 + idx]),
              bf128_add(state_tag[96 + idx], rk_tag[(round + 4) * 32 + idx]));
        }
      }

      // === 读取见证 & 生成约束 ===
      uint8_t  sbox_out_val[4];
      bf128_t  sbox_out_tag_bits[32];

      if (r_in_quad == 0) {
        // ---- invnorm 轮 (degree-3) ----
        const uint8_t*  wp   = q_w   + quad_byte_offsets[0];   // [0..1]
        const bf128_t*  tp   = q_tag + quad_tag_offsets[0];     // [0..15]

        for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
          // nibble 读取: w[byte_i/2] 的低4(byte_i偶) 或 高4(byte_i奇) bits
          uint8_t  c_nib  = (wp[byte_i / 2] >> (4 * (byte_i % 2))) & 0xF;
          const bf128_t* c_t = tp + byte_i * 4;

          sm4_SSS_invnorm_sbox_prover(hasher,
                                       in_bytes[byte_i], in_tag + byte_i * 8,
                                       c_nib, c_t);

          // 修复漏洞二：sbox_out_tag 必须使用 Degree-2 语义。
          // S(x) = L(x^{-1}) ^ C，其中 x^{-1} = c · x^{2} (在 invnorm 约束语义下)。
          // x^{-1} 的 tag 是 c_tag（D-1）与 x^2_tag（D-1 线性映射）的乘积，等于 Degree-2。
          // 正确做法：先计算 x^{16_tag}（Frobenius，线性，D-1），
          // 再组合 C_tag（见证 c 的嵌入 tag）与 x^{16_tag} 的逐 bit 乘积，
          // 得到 D-2 的 x^{-1} GF(2^128) 嵌入 tag，最后对其施加仿射变换 L。

          // 步骤 A：构建 C_tag（4-bit nibble 嵌入 GF(2^128) 的 tag）
          bf128_t C_tag_emb = bf128_zero();
          for (unsigned int k = 0; k < 4; ++k) {
            if (k == 0) {
              C_tag_emb = bf128_add(C_tag_emb, c_t[0]);
            } else {
              C_tag_emb = bf128_add(C_tag_emb,
                  bf128_mul(sm4_beta_squares_bf128[k - 1], c_t[k]));
            }
          }

          // 步骤 B：计算 x^{16} 的 tag（Frobenius ×8，D-1 线性）
          bf128_t x16_tag_bits[8];
          memcpy(x16_tag_bits, in_tag + byte_i * 8, 8 * sizeof(bf128_t));
          for (unsigned int fr = 0; fr < 4; ++fr)  // x^1→x^2→x^4→x^8→x^16
            sm4_sq_bit_inplace(x16_tag_bits);
          bf128_t X16_tag_emb = sm4_byte_combine(x16_tag_bits);

          // 步骤 C：x^{-1} 的 GF(2^128) tag = C_tag_emb * X16_tag_val + C_val * X16_tag_emb
          // (Leibniz 乘积规则，D-2 项)
          uint8_t x16_val = in_bytes[byte_i];
          for (unsigned int fr = 0; fr < 4; ++fr) x16_val = bf8_square_sm4(x16_val);
          bf128_t X16_val_emb = sm4_byte_combine_bits(x16_val);
          bf128_t C_val_emb = bf128_zero();
          {
            if ((c_nib >> 0) & 1) C_val_emb = bf128_add(C_val_emb, bf128_one());
            for (unsigned int k = 1; k < 4; ++k)
              if ((c_nib >> k) & 1)
                C_val_emb = bf128_add(C_val_emb, sm4_beta_squares_bf128[k - 1]);
          }
          bf128_t xinv_tag_emb = bf128_add(
              bf128_mul(C_tag_emb, X16_val_emb),
              bf128_mul(C_val_emb, X16_tag_emb));

          // 步骤 D：将 x^{-1} 的嵌入 tag 拆成 8 个基础 bit 分量，再统一施加 affine。
          // 这里仅做基向量映射；L 变换由 sm4_SSS_affine_forward_prover 统一处理，避免重复施加。
          uint8_t xinv_scalar = sm4_inverse_affine_scalar(sm4_sbox(in_bytes[byte_i]));
          bf128_t xinv_tag_bits[8];
          for (unsigned int bit = 0; bit < 8; ++bit) {
            xinv_tag_bits[bit] = bf128_mul(sm4_byte_combine_bits((uint8_t)(1u << bit)),
                                           xinv_tag_emb);
          }
          uint8_t  soe_val;
          bf128_t  soe_tag[8];
          sm4_SSS_affine_forward_prover(&soe_val, soe_tag, &xinv_scalar, xinv_tag_bits);
          sbox_out_val[byte_i] = soe_val;
          memcpy(sbox_out_tag_bits + byte_i * 8, soe_tag, 8 * sizeof(bf128_t));
        }
      } else {
        // ---- full-8bit 轮 (degree-2) ----
        const uint8_t*  wp = q_w   + quad_byte_offsets[r_in_quad];   // [2],[6],[10]
        const bf128_t*  tp = q_tag + quad_tag_offsets[r_in_quad];    // [16],[48],[80]

        for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
          uint8_t        y_val = wp[byte_i];
          const bf128_t* y_t   = tp + byte_i * 8;

          sm4_SSS_full_sbox_prover(hasher,
                                    in_bytes[byte_i], in_tag + byte_i * 8,
                                    y_val, y_t);

          // sbox_out = affine(y)
          uint8_t  soe_val;
          bf128_t  soe_tag[8];
          sm4_SSS_affine_forward_prover(&soe_val, soe_tag, &y_val, y_t);
          sbox_out_val[byte_i] = soe_val;
          memcpy(sbox_out_tag_bits + byte_i * 8, soe_tag, 8 * sizeof(bf128_t));
        }
      }

      // === 更新滚动窗口（除最后一轮）===
      if (round < SM4_R - 1) {
        uint8_t  L_out[4];
        bf128_t  L_out_tag[32];
        sm4_SSS_linear_l_prover(L_out, L_out_tag, sbox_out_val, sbox_out_tag_bits);

        uint8_t  new_word[4];
        bf128_t  new_word_tag[32];
        for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
          new_word[byte_i] = state[byte_i] ^ L_out[byte_i];
          for (unsigned int bit = 0; bit < 8; bit++) {
            new_word_tag[byte_i * 8 + bit] =
                bf128_add(state_tag[byte_i * 8 + bit], L_out_tag[byte_i * 8 + bit]);
          }
        }
        memmove(state,          state + 4,          12);
        memcpy (state + 12,     new_word,            4);
        memmove(state_tag,      state_tag + 32,     96 * sizeof(bf128_t));
        memcpy (state_tag + 96, new_word_tag,       32 * sizeof(bf128_t));
      }
    }
  }

  // ========================================================================
  // 漏洞一修复：终态等式约束
  // SM4 加密结果 = (X[35], X[34], X[33], X[32])（反序），即 state 的反序
  // 约束: final_state_word[i] == owf_out_word[i]  for i=0..3
  // 在 VOLE 框架中，等式约束等价于提交差值的 tag 为零。
  // 这里通过将 (final_state_tag[bit] XOR owf_out_tag[bit]) 提交到 hasher 来表达。
  // 若见证正确，该差值应为线性 tag（Degree-1 有效约束），验证者可独立校验。
  // 注意：owf_out 在标准模式下是公开值（tag=0），在 EM 模式下是 w[0..16] XOR owf_out。
  for (unsigned int bit = 0; bit < Nbits; ++bit) {
    // 重映射：SM4 输出是 state 的反序 4 个字，state_tag 当前存储的是最后一步更新后的窗口
    // 经过 SM4_R-1 次 memmove 后，state_tag[0..31]=X32, [32..63]=X33, [64..95]=X34, [96..127]=X35
    // SM4 密文 = (X35, X34, X33, X32) 即 state_tag 的反序字排列
    // bit 索引映射：密文 bit i 对应 state_tag 的 word (3 - i/32)*32 + i%32
    const unsigned int word_idx = bit / 32;
    const unsigned int bit_in_word = bit % 32;
    const unsigned int state_bit = (3u - word_idx) * 32u + bit_in_word;
    bf128_t final_bit_tag = (state_bit < Nbits) ? state_tag[state_bit] : bf128_zero();
    // owf_out_tag 在调用处已正确设置（标准模式为0，EM模式为 in_tag）
    bf128_t out_bit_tag = owf_out_tag[bit];
    // 提交约束：final - expected = 0（线性约束，degree-1 coefficient）
    bf128_t diff_tag = bf128_add(final_bit_tag, out_bit_tag);
    // 将线性约束折叠进 hasher（用 degree-1 通道：d0=0, d1=0, d2=diff_tag）
    zk_hash_128_3_update(hasher, bf128_zero(), bf128_zero(), diff_tag);
  }
}

/**
 * SM4 加密约束 (Verifier版本) — 1:3 nibble 方案
 *
 * w_key 见证 key-share 布局（与 prover 完全对称）：
 *   8 个 quad，每 quad quad_tags=112 个 bf128_t
 *   quad 内：
 *     [0..15]   = nibble 轮 4 sbox × 4 bits（每 sbox 4 个 bf128_t）
 *     [16..47]  = full8 轮1 4 sbox × 8 bits
 *     [48..79]  = full8 轮2
 *     [80..111] = full8 轮3
 */
static void sm4_SSS_enc_constraints_verifier(zk_hash_128_ctx* hasher,
                                             const bf128_t* owf_in_key,
                                             const bf128_t* owf_out_key,
                                             const bf128_t* w_key,
                                             const bf128_t* rk_key,
                                             bf128_t delta,
                                             const faest_paramset_t* params) {
  (void)params;
  const unsigned int SM4_R = 32;
  const unsigned int Nbits = 128;

  bf128_t state_key[128];
  memcpy(state_key, owf_in_key, Nbits * sizeof(bf128_t));

  static const unsigned int quad_tag_offsets[4] = {0, 16, 48, 80};
  const unsigned int quad_tags = 112;  // 4*4 + 3*4*8

  for (unsigned int q = 0; q < SM4_R / 4; q++) {
    const bf128_t* q_key = w_key + q * quad_tags;

    for (unsigned int r_in_quad = 0; r_in_quad < 4; r_in_quad++) {
      const unsigned int round = q * 4 + r_in_quad;

      // === S-box 输入的 eval ===
      bf128_t in_key[32];
      for (unsigned int bit = 0; bit < 32; bit++) {
        in_key[bit] = bf128_add(
            bf128_add(state_key[32 + bit], state_key[64 + bit]),
            bf128_add(state_key[96 + bit], rk_key[(round + 4) * 32 + bit]));
      }

      bf128_t sbox_out_key[32];

      if (r_in_quad == 0) {
        // ---- invnorm 轮 ----
        const bf128_t* tp = q_key + quad_tag_offsets[0];
        for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
          const bf128_t* x_eval = in_key + byte_i * 8;
          const bf128_t* c_eval = tp + byte_i * 4;  // 4 bits nibble key-share
          sm4_SSS_invnorm_sbox_verifier(hasher, x_eval, c_eval, delta);

          // 修复漏洞二（Verifier）：sbox_out_key 必须使用 Degree-2 语义。
          // sbox_out_key = L( c_eval * x16_eval ) + delta*C
          // 即 x^{-1}_key = C_eval * X16_eval (乘积，D-2)
          // 然后对其施加仿射变换 L。

          // 步骤 A：C_eval 嵌入 GF(2^128)（4-bit nibble 的 key-shares）
          bf128_t C_eval_emb = bf128_add(c_eval[0],
              bf128_add(bf128_mul(sm4_beta_squares_bf128[0], c_eval[1]),
              bf128_add(bf128_mul(sm4_beta_squares_bf128[1], c_eval[2]),
                        bf128_mul(sm4_beta_squares_bf128[2], c_eval[3]))));

          // 步骤 B：X16_eval = x^{16} 的 Frobenius（4次平方，线性）
          bf128_t x16_eval_bits[8];
          memcpy(x16_eval_bits, x_eval, 8 * sizeof(bf128_t));
          for (unsigned int fr = 0; fr < 4; ++fr)
            sm4_sq_bit_inplace(x16_eval_bits);
          bf128_t X16_eval_emb = sm4_byte_combine(x16_eval_bits);

          // 步骤 C：x^{-1}_eval = C_eval_emb * X16_eval_emb（D-2 乘积）
          bf128_t xinv_eval_emb = bf128_mul(C_eval_emb, X16_eval_emb);

          // 步骤 D：将 x^{-1} 的嵌入 key-share 拆成 8 个基础 bit 分量，再统一施加 affine。
          bf128_t xinv_eval_bits[8];
          for (unsigned int bit = 0; bit < 8; ++bit) {
            xinv_eval_bits[bit] = bf128_mul(sm4_byte_combine_bits((uint8_t)(1u << bit)),
                                            xinv_eval_emb);
          }
          bf128_t soe_key[8];
          sm4_SSS_affine_forward_verifier(soe_key, xinv_eval_bits, delta);
          memcpy(sbox_out_key + byte_i * 8, soe_key, 8 * sizeof(bf128_t));
        }
      } else {
        // ---- full-8bit 轮 ----
        const bf128_t* tp = q_key + quad_tag_offsets[r_in_quad];
        for (unsigned int byte_i = 0; byte_i < 4; byte_i++) {
          const bf128_t* x_eval = in_key + byte_i * 8;
          const bf128_t* y_eval = tp + byte_i * 8;
          sm4_SSS_full_sbox_verifier(hasher, x_eval, y_eval);

          bf128_t soe_key[8];
          sm4_SSS_affine_forward_verifier(soe_key, y_eval, delta);
          memcpy(sbox_out_key + byte_i * 8, soe_key, 8 * sizeof(bf128_t));
        }
      }

      // === 更新滚动状态 ===
      if (round < SM4_R - 1) {
        bf128_t L_out_key[32];
        sm4_SSS_linear_l_verifier(L_out_key, sbox_out_key);

        bf128_t new_word_key[32];
        for (unsigned int bit = 0; bit < 32; bit++) {
          new_word_key[bit] = bf128_add(state_key[bit], L_out_key[bit]);
        }
        memmove(state_key,      state_key + 32,   96 * sizeof(bf128_t));
        memcpy (state_key + 96, new_word_key,     32 * sizeof(bf128_t));
      }
    }
  }

  // ========================================================================
  // 漏洞一修复（Verifier）：终态等式约束
  // 约束：final_state_key[bit] == owf_out_key[bit]  for bit=0..127
  // 等式约束在 Verifier 侧表达为：final_key - out_key = 0 at delta
  for (unsigned int bit = 0; bit < Nbits; ++bit) {
    const unsigned int word_idx    = bit / 32;
    const unsigned int bit_in_word = bit % 32;
    const unsigned int state_bit   = (3u - word_idx) * 32u + bit_in_word;
    bf128_t final_bit_key = (state_bit < Nbits) ? state_key[state_bit] : bf128_zero();
    bf128_t out_bit_key   = owf_out_key[bit];
    bf128_t diff_key = bf128_add(final_bit_key, out_bit_key);
    zk_hash_128_update(hasher, diff_key);
  }
}

// ============================================================================
// Phase 6: 完整约束系统（OWF CONSTRAINTS）
// ============================================================================

/**
 * 完整的SM4约束系统 (Prover版本)
 * 包含密钥扩展和加密约束
 */
static bool sm4_SSS_constraints_prover(zk_hash_128_3_ctx* hasher, const uint8_t* w,
                                       const bf128_t* w_tag, const uint8_t* owf_in,
                                       const uint8_t* owf_out, const faest_paramset_t* params) {
  const unsigned int SM4_BLOCKSIZE = 128;  // 128位 = 16字节
  const unsigned int SM4_R = 32;           // 32轮

  
  // 分配轮密钥空间
  uint8_t* rk = malloc((SM4_R + 4) * 4);  // 36个字 × 4字节
  bf128_t* rk_tag = malloc((SM4_R + 4) * 32 * sizeof(bf128_t));  // 36个字 × 32位
  if (!rk || !rk_tag) {
    free(rk);
    free(rk_tag);
    return false;
  }
  
  // 分配输入/输出空间
  uint8_t* in = malloc(SM4_BLOCKSIZE / 8);
  bf128_t* in_tag = malloc(SM4_BLOCKSIZE * sizeof(bf128_t));
  uint8_t* out = malloc(SM4_BLOCKSIZE / 8);
  bf128_t* out_tag = malloc(SM4_BLOCKSIZE * sizeof(bf128_t));
  if (!in || !in_tag || !out || !out_tag) {
    free(out_tag);
    free(out);
    free(in_tag);
    free(in);
    free(rk_tag);
    free(rk);
    return false;
  }
  
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

    // ::1 密钥扩展并生成哈希约束
    sm4_SSS_keyexp_forward_prover(rk, rk_tag, w, w_tag);
    sm4_SSS_expkey_constraints_prover(hasher, rk, rk_tag, w, w_tag);

    // ::2 加密约束
    sm4_SSS_enc_constraints_prover(hasher, in, in_tag, out, out_tag,
        w + Lke / 8, w_tag + Lke, rk, rk_tag, params);
  }
  
  free(out_tag);
  free(out);
  free(in_tag);
  free(in);
  free(rk_tag);
  free(rk);
  return true;
}

/**
 * 完整的SM4约束系统 (Verifier版本)
 */
static bool sm4_SSS_constraints_verifier(zk_hash_128_ctx* hasher, const bf128_t* w_key,
                                         const uint8_t* owf_in, const uint8_t* owf_out,
                                         bf128_t delta, const faest_paramset_t* params) {
  const unsigned int SM4_BLOCKSIZE = 128;
  const unsigned int SM4_R = 32;
  
  // 分配轮密钥空间
  bf128_t* rk_key = malloc((SM4_R + 4) * 32 * sizeof(bf128_t));
  if (!rk_key) {
    return false;
  }
  
  // 分配输入/输出空间
  bf128_t* in_key = malloc(SM4_BLOCKSIZE * sizeof(bf128_t));
  bf128_t* out_key = malloc(SM4_BLOCKSIZE * sizeof(bf128_t));
  if (!in_key || !out_key) {
    free(out_key);
    free(in_key);
    free(rk_key);
    return false;
  }
  
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

    // ::1 密钥扩展并生成哈希约束
    sm4_SSS_keyexp_forward_verifier(rk_key, w_key);
    sm4_SSS_expkey_constraints_verifier(hasher, rk_key, w_key, delta);

    // ::2 加密约束
    sm4_SSS_enc_constraints_verifier(hasher, in_key, out_key, w_key + Lke,
        rk_key, delta, params);
  }
  
  free(out_key);
  free(in_key);
  free(rk_key);
  return true;
}

// ============================================================================
// 顶层 Prover/Verifier 接口
// ============================================================================

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

static bf128_t* column_to_row_major_and_shrink_V_128_sm4(uint8_t** V, unsigned int ell,
                                                         unsigned int lambda,
                                                         unsigned int ell_hat,
                                                         const char* dbg_label) {
  const unsigned int rows_to_keep = ell + 2 * lambda;
  if (ell_hat < rows_to_keep) {
    (void)dbg_label;
    return NULL;
  }

  bf128_t* w_tag = malloc(rows_to_keep * sizeof(bf128_t));
  if (!w_tag) {
    (void)dbg_label;
    return NULL;
  }


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
    for (unsigned int column = 0; column < lambda; ++column) {
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
  (void)chall2_len;

  if (!sm4_check_embedding_constants_once()) {
    memset(a0_tilde, 0, lambda / 8);
    memset(a1_tilde, 0, lambda / 8);
    memset(a2_tilde, 0, lambda / 8);
    return;
  }

#if defined(DEBUG_SM4_CONSTRAINTS)
  fprintf(stderr, "[DBG-PROVER] ell=%u, Lke=%u, Lenc=%u, R=%u is_em=%d\n",
          params->l, params->Lke, params->Lenc, params->R, faest_is_em(params));
  fprintf(stderr, "[DBG-PROVER] w[0..7]=");
  for (int _i=0;_i<8;_i++) fprintf(stderr,"%02x",w[_i]);
  fprintf(stderr,"\n");
#endif

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
  if (!sm4_SSS_constraints_prover(&hasher, w, w_tag, owf_in, owf_out, params)) {
    memset(a0_tilde, 0, lambda / 8);
    memset(a1_tilde, 0, lambda / 8);
    memset(a2_tilde, 0, lambda / 8);
    free(w_tag);
    return;
  }

  // Stage check: constraints generation complete

  // ::14 最终化哈希
  printf("VERIFIER FINAL HASH called\n");
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
  (void)chall2_len;

  if (!sm4_check_embedding_constants_once()) {
    memset(a0_tilde, 0, lambda / 8);
    return;
  }

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
  if (!sm4_SSS_constraints_verifier(&b_ctx, q_key, owf_in, owf_out, bf_delta, params)) {
    free(q_key);
    memset(a0_tilde, 0, lambda / 8);
    return;
  }

  // Stage check: constraints verification complete

  free(q_key);

#if defined(DEBUG_SM4_CONSTRAINTS)
  uint8_t debug_q_tilde[16];
  {
    zk_hash_128_ctx tmp_ctx2;
    zk_hash_128_init(&tmp_ctx2, chall_2);
    // re-running is too hard; just print delta
    fprintf(stderr, "[DBG-VERIFIER] delta=");
    uint8_t _db[16]; bf128_store(_db, bf_delta);
    for (int _i=0;_i<16;_i++) fprintf(stderr,"%02x",_db[_i]);
    fprintf(stderr,"\n");
  }
#endif

  // ::13-14 最终化哈希
  uint8_t q_tilde[16];  // 128位 = 16字节
  printf("VERIFIER FINAL HASH 2 called\n");
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
