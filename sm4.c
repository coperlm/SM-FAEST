/*
 *  SPDX-License-Identifier: MIT
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include "sm4.h"
#include "fields.h"
#include "compat.h"
#include "utils.h"

#include <string.h>
#include <stdio.h>

#ifndef FAEST_SM4_DEBUG
#define FAEST_SM4_DEBUG 1
#endif

// ============ SM4 S-box (国密标准 GM/T 0002-2012) ============
static const uint8_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// ============ 系统参数 FK ============
static const uint32_t FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

// ============ 固定参数 CK ============
static const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// ============ S-box 查找 ============
uint8_t sm4_sbox(uint8_t in) {
  return SM4_SBOX[in];
}

// ============ 合成置换 τ: τ(A) = (Sbox(a0), Sbox(a1), Sbox(a2), Sbox(a3)) ============
uint32_t sm4_tau(uint32_t a) {
  uint8_t bytes[4];
  sm4_uint32_to_bytes(a, bytes);
  
  bytes[0] = sm4_sbox(bytes[0]);
  bytes[1] = sm4_sbox(bytes[1]);
  bytes[2] = sm4_sbox(bytes[2]);
  bytes[3] = sm4_sbox(bytes[3]);
  
  return sm4_bytes_to_uint32(bytes);
}

// ============ 循环左移 ============
static inline uint32_t sm4_rotl32(uint32_t x, unsigned int n) {
  return (x << n) | (x >> (32 - n));
}

// ============ 线性变换 L (用于加密): L(B) = B ⊕ (B<<<2) ⊕ (B<<<10) ⊕ (B<<<18) ⊕ (B<<<24) ============
uint32_t sm4_linear_l(uint32_t b) {
  return b ^ sm4_rotl32(b, 2) ^ sm4_rotl32(b, 10) ^ sm4_rotl32(b, 18) ^ sm4_rotl32(b, 24);
}

// ============ 线性变换 L' (用于密钥扩展): L'(B) = B ⊕ (B<<<13) ⊕ (B<<<23) ============
uint32_t sm4_linear_l_prime(uint32_t b) {
  return b ^ sm4_rotl32(b, 13) ^ sm4_rotl32(b, 23);
}

// ============ T 变换 (加密用): T(X) = L(τ(X)) ============
static inline uint32_t sm4_t(uint32_t x) {
  return sm4_linear_l(sm4_tau(x));
}

// ============ T' 变换 (密钥扩展用): T'(X) = L'(τ(X)) ============
static inline uint32_t sm4_t_prime(uint32_t x) {
  return sm4_linear_l_prime(sm4_tau(x));
}

// ============ 密钥扩展算法 ============
void sm4_init_round_keys(sm4_round_keys_t* rk, const uint8_t* key) {
  uint32_t K[36]; // K[0..3] 中间密钥, K[4..35] = rk[0..31]
  
  // MK 转换为 K[0..3]
  for (int i = 0; i < 4; i++) {
    K[i] = sm4_bytes_to_uint32(key + 4 * i) ^ FK[i];
  }
  
  // 生成32轮轮密钥
  for (int i = 0; i < 32; i++) {
    K[i + 4] = K[i] ^ sm4_t_prime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
    rk->round_keys[i] = K[i + 4];
  }
}

// ============ SM4 加密算法 ============
void sm4_encrypt_block(const sm4_round_keys_t* rk, const uint8_t* plaintext,
                       uint8_t* ciphertext) {
  uint32_t X[36]; // X[0..3] 输入, X[4..35] 中间状态
  
  // 加载明文
  for (int i = 0; i < 4; i++) {
    X[i] = sm4_bytes_to_uint32(plaintext + 4 * i);
  }
  
  // 32轮迭代: X[i+4] = X[i] ⊕ T(X[i+1] ⊕ X[i+2] ⊕ X[i+3] ⊕ rk[i])
  for (int i = 0; i < 32; i++) {
    X[i + 4] = X[i] ^ sm4_t(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk->round_keys[i]);
  }
  
  // 反序变换输出: (X[35], X[34], X[33], X[32])
  for (int i = 0; i < 4; i++) {
    sm4_uint32_to_bytes(X[35 - i], ciphertext + 4 * i);
  }
}

// ============ IV 递增（用于 CTR 模式）============
#if defined(FAEST_TESTS)
void sm4_increment_iv(uint8_t* iv)
#else
static inline void sm4_increment_iv(uint8_t* iv)
#endif
{
  uint32_t iv0;
  memcpy(&iv0, iv, sizeof(uint32_t));
  iv0 = htole32(le32toh(iv0) + 1);
  memcpy(iv, &iv0, sizeof(uint32_t));
}

// ============ PRG 实现（SM4-CTR 模式）============

// 辅助函数：将 tweak 加到 IV 的高位字上
static inline void add_to_upper_word(uint8_t* iv, uint32_t tweak) {
  uint32_t iv0;
  memcpy(&iv0, iv + 12, sizeof(uint32_t));
  iv0 = htole32(le32toh(iv0) + tweak);
  memcpy(iv + 12, &iv0, sizeof(uint32_t));
}

// SM4-CTR 模式的 PRG 实现
void sm4_prg(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
             unsigned int bits, size_t outlen) {
  (void)bits; // bits 参数在 SM4-128 中未使用，保持接口一致性
  
  // 初始化轮密钥
  sm4_round_keys_t rk;
  sm4_init_round_keys(&rk, key);
  
  // 准备内部 IV（加上 tweak）
  uint8_t internal_iv[SM4_BLOCK_SIZE];
  memcpy(internal_iv, iv, SM4_BLOCK_SIZE);
  add_to_upper_word(internal_iv, tweak);
  
  // CTR 模式：生成所需数量的块
  for (size_t idx = 0; idx < outlen / SM4_BLOCK_SIZE; idx++, out += SM4_BLOCK_SIZE) {
    sm4_encrypt_block(&rk, internal_iv, out);
    sm4_increment_iv(internal_iv);
  }
  
  // 处理不完整的最后一块
  if (outlen % SM4_BLOCK_SIZE) {
    uint8_t last_block[SM4_BLOCK_SIZE];
    sm4_encrypt_block(&rk, internal_iv, last_block);
    memcpy(out, last_block, outlen % SM4_BLOCK_SIZE);
  }
}

void sm4_prg_2_lambda(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
                      unsigned int bits) {
  const unsigned int lambda_bytes = bits / 8;
  sm4_prg(key, iv, tweak, out, bits, 2 * lambda_bytes);
}

void sm4_prg_4_lambda(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
                      unsigned int bits) {
  const unsigned int lambda_bytes = bits / 8;
  sm4_prg(key, iv, tweak, out, bits, 4 * lambda_bytes);
}

// ============ 辅助函数：逆仿射（用于见证）============
static inline uint8_t sm4_rotl8(uint8_t v, unsigned int n) {
  return (uint8_t)((v << n) | (v >> (8 - n)));
}

static inline uint8_t sm4_inverse_affine(uint8_t sbox_out) {
  uint8_t y = sbox_out ^ 0xD6;  // 0xD6 是 SM4 仿射常数 C
  return (uint8_t)(sm4_rotl8(y, 7) ^ sm4_rotl8(y, 5) ^ sm4_rotl8(y, 1));
}

// ============ 扩展见证（ZK 证明用）============
void sm4_extend_witness(uint8_t* w, const uint8_t* key, const uint8_t* in,
                        const faest_paramset_t* params) {
  const bool is_em = (params->Ske == 0); // 检查是否为 EM 模式
  
#if !defined(NDEBUG)
  uint8_t* const w_out = w;
#endif

  const uint8_t* actual_key = key;
  const uint8_t* actual_in  = in;

#if defined(FAEST_SM4_DEBUG)
  fprintf(stderr,
          "[SM4_DEBUG] witness_layout base=%p Lke_bytes=%u l_bytes=%u is_em=%u\n",
          (void*)w_out, params->Lke / 8, params->l / 8, is_em ? 1u : 0u);
  fprintf(stderr,
          "[SM4_DEBUG] witness_layout enc_rounds=1..%u odd_round_bytes=8 even_round_bytes=16\n",
          params->R - 1);
#endif
  
  // EM 模式：交换 key 和 input
  if (is_em) {
    const uint8_t* tmp = actual_key;
    actual_key         = actual_in;
    actual_in          = tmp;
  }
  
  // 步骤 1: 生成轮密钥
  sm4_round_keys_t rk;
  sm4_init_round_keys(&rk, actual_key);

  // 维护 K[0..35]（用于生成 τ(X) 以写入正确的 inv_norm）
  uint32_t K[SM4_ROUNDS + 4];
  for (unsigned int i = 0; i < 4; ++i) {
    K[i] = sm4_bytes_to_uint32(actual_key + 4 * i) ^ FK[i];
  }
  for (unsigned int round = 0; round < SM4_ROUNDS; ++round) {
    K[round + 4] = rk.round_keys[round];
  }
  
  // 步骤 2: 记录密钥扩展见证（标准模式需要，EM 模式跳过）
  if (!is_em) {
    const unsigned int nk = params->lambda / 32; // SM4-128: nk = 4
#if defined(FAEST_SM4_DEBUG)
    size_t seg_start = (size_t)(w - w_out);
#endif
    // 记录初始密钥（nk 个字），使用 K[0..3] = MK ^ FK
    for (unsigned int i = 0; i != nk; ++i) {
      sm4_uint32_to_bytes(K[i], w);
      w += 4;
    }
#if defined(FAEST_SM4_DEBUG)
    fprintf(stderr,
            "[SM4_DEBUG] witness_layout keyexp_mk range=[%zu..%zu]\n",
            seg_start, (size_t)(w - w_out - 1));
    seg_start = (size_t)(w - w_out);
#endif
    
    // 记录全部 32 轮密钥 K[4..35]
    for (unsigned int round = 0; round < SM4_ROUNDS; ++round) {
      sm4_uint32_to_bytes(rk.round_keys[round], w);
      w += 4;
    }
#if defined(FAEST_SM4_DEBUG)
    fprintf(stderr,
            "[SM4_DEBUG] witness_layout keyexp_rk range=[%zu..%zu]\n",
            seg_start, (size_t)(w - w_out - 1));
    seg_start = (size_t)(w - w_out);
#endif

    // 记录每轮 τ(X) 的逆范数（4 字节），总计 32*4 = 128 字节
    for (unsigned int round = 0; round < SM4_ROUNDS; ++round) {
      // X = K[i+1] ⊕ K[i+2] ⊕ K[i+3] ⊕ CK[i]
      uint32_t x = K[round + 1] ^ K[round + 2] ^ K[round + 3] ^ CK[round];
      uint32_t tau_x = sm4_tau(x);  // τ(X) = S-box 应用后的结果

      uint8_t tau_bytes[4];
      sm4_uint32_to_bytes(tau_x, tau_bytes);
      for (unsigned int j = 0; j < 4; ++j) {
        *w++ = sm4_inverse_affine(tau_bytes[j]);
      }
    }
#if defined(FAEST_SM4_DEBUG)
    fprintf(stderr,
            "[SM4_DEBUG] witness_layout keyexp_inv_norm range=[%zu..%zu]\n",
            seg_start, (size_t)(w - w_out - 1));
#endif
  } else {
    const unsigned int lambda_bytes = params->lambda / 8;
    
    // EM 模式：保存 OWF key 到扩展见证
    memcpy(w, actual_in, lambda_bytes);
    w += lambda_bytes;
  }
  
  assert(w - w_out == params->Lke / 8);
  
  // 步骤 3: 记录加密过程的中间状态
#if defined(FAEST_SM4_DEBUG)
  fprintf(stderr,
          "[SM4_DEBUG] witness_layout enc_start offset=%zu\n",
          (size_t)(w - w_out));
#endif
  uint32_t state[4]; // 当前状态 X[i..i+3]
  
  // 加载明文/输入
  for (int i = 0; i < 4; i++) {
    state[i] = sm4_bytes_to_uint32(actual_in + 4 * i);
  }
  
  // 32 轮迭代，记录中间状态（从 round=1 开始，类似 AES）
  for (unsigned int round = 1; round < params->R; round++) {
    if (round % 2 == 1) {
      // 奇数轮：记录 S-box 输出（4 字节）以及逆元（4 字节）
      uint32_t temp = state[1] ^ state[2] ^ state[3] ^ rk.round_keys[round - 1];
      uint8_t temp_bytes[4];
      sm4_uint32_to_bytes(temp, temp_bytes);
      for (int j = 0; j < 4; j++) {
        uint8_t sbox_out = sm4_sbox(temp_bytes[j]);
        *w++ = sbox_out;
        *w++ = sm4_inverse_affine(sbox_out);
      }
    }
    
    // 执行 SM4 轮函数：X[i+4] = X[i] ⊕ T(X[i+1] ⊕ X[i+2] ⊕ X[i+3] ⊕ rk[i])
    uint32_t temp = state[1] ^ state[2] ^ state[3] ^ rk.round_keys[round - 1];
    uint32_t new_word = state[0] ^ sm4_t(temp);
    
    // 更新状态（循环移位）
    state[0] = state[1];
    state[1] = state[2];
    state[2] = state[3];
    state[3] = new_word;
    
    if (round % 2 == 0) {
      // 偶数轮：记录完整状态
      for (int j = 0; j < 4; j++) {
        sm4_uint32_to_bytes(state[j], w);
        w += 4;
      }
    }
  }
  
  // 最后一轮不提交，因此不记录
  
  assert(w - w_out == params->l / 8);
}
