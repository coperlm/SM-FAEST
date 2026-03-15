/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef FAEST_SM4_H
#define FAEST_SM4_H

#include "macros.h"
#include "instances.h"

#include <stdint.h>
#include <stdlib.h>

FAEST_BEGIN_C_DECL

#define SM4_ROUNDS 32
#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16

// SM4 轮密钥结构
typedef struct {
  uint32_t round_keys[SM4_ROUNDS];
} sm4_round_keys_t;

// ============ 基础 SM4 函数 ============

// 密钥初始化
void sm4_init_round_keys(sm4_round_keys_t* round_key, const uint8_t* key);

// 单块加密
void sm4_encrypt_block(const sm4_round_keys_t* key, const uint8_t* plaintext,
                       uint8_t* ciphertext);

// ============ S-box 和变换函数 ============

// SM4 S-box 查找
uint8_t sm4_sbox(uint8_t in);

// 合成置换 τ
uint32_t sm4_tau(uint32_t a);

// 线性变换 L (用于加密)
uint32_t sm4_linear_l(uint32_t b);

// 线性变换 L' (用于密钥扩展)
uint32_t sm4_linear_l_prime(uint32_t b);

// ============ ZK 证明辅助函数 ============

// invnorm: x^{-17} in SM4 GF(2^8), returns 4-bit value
uint8_t sm4_invnorm_old(uint8_t x);
uint8_t sm4_invnorm(uint8_t x);
uint8_t sm4_galois_decompose(unsigned int round_idx, uint8_t a, uint8_t round_key);

// 扩展见证（用于 FAEST 证明系统）
void sm4_extend_witness(uint8_t* w, const uint8_t* key, const uint8_t* in,
                        const faest_paramset_t* params);

// ============ PRG 函数（SM4-CTR 模式）============

// 基础 PRG
void sm4_prg(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
             unsigned int bits, size_t outlen);

// PRG 输出 2λ 位
void sm4_prg_2_lambda(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
                      unsigned int bits);

// PRG 输出 4λ 位
void sm4_prg_4_lambda(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
                      unsigned int bits);

// ============ 辅助函数 ============

#if defined(FAEST_TESTS)
void sm4_increment_iv(uint8_t* iv);
#endif

// 字节序转换
static inline uint32_t sm4_bytes_to_uint32(const uint8_t* bytes) {
  return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
         ((uint32_t)bytes[2] << 8) | ((uint32_t)bytes[3]);
}

static inline void sm4_uint32_to_bytes(uint32_t val, uint8_t* bytes) {
  bytes[0] = (val >> 24) & 0xFF;
  bytes[1] = (val >> 16) & 0xFF;
  bytes[2] = (val >> 8) & 0xFF;
  bytes[3] = val & 0xFF;
}

FAEST_END_C_DECL

#endif
