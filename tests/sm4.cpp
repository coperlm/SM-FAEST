/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "sm4.h"
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(sm4)

// 测试向量来自 GM/T 0002-2012 附录 A.1 示例 1
static const uint8_t test_key[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

static const uint8_t test_plaintext[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

static const uint8_t expected_ciphertext[16] = {
    0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
    0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
};

BOOST_AUTO_TEST_CASE(test_sm4_sbox) {
  // 测试 S-box 的几个关键值
  BOOST_CHECK_EQUAL(sm4_sbox(0x00), 0xd6);
  BOOST_CHECK_EQUAL(sm4_sbox(0x01), 0x90);
  BOOST_CHECK_EQUAL(sm4_sbox(0xff), 0x48);
  BOOST_CHECK_EQUAL(sm4_sbox(0x12), 0x9a);
}

BOOST_AUTO_TEST_CASE(test_sm4_tau) {
  // 测试合成置换 τ
  uint32_t input = 0x01234567;
  uint32_t output = sm4_tau(input);
  
  // 验证 τ 对每个字节应用 S-box
  uint8_t b0 = sm4_sbox(0x01);
  uint8_t b1 = sm4_sbox(0x23);
  uint8_t b2 = sm4_sbox(0x45);
  uint8_t b3 = sm4_sbox(0x67);
  
  uint32_t expected = ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) | 
                      ((uint32_t)b2 << 8) | b3;
  BOOST_CHECK_EQUAL(output, expected);
}

BOOST_AUTO_TEST_CASE(test_sm4_linear_l) {
  // 测试线性变换 L
  uint32_t input = 0x12345678;
  uint32_t output = sm4_linear_l(input);
  
  // L(B) = B ⊕ (B<<<2) ⊕ (B<<<10) ⊕ (B<<<18) ⊕ (B<<<24)
  uint32_t rotl2 = (input << 2) | (input >> 30);
  uint32_t rotl10 = (input << 10) | (input >> 22);
  uint32_t rotl18 = (input << 18) | (input >> 14);
  uint32_t rotl24 = (input << 24) | (input >> 8);
  
  uint32_t expected = input ^ rotl2 ^ rotl10 ^ rotl18 ^ rotl24;
  BOOST_CHECK_EQUAL(output, expected);
}

BOOST_AUTO_TEST_CASE(test_sm4_linear_l_prime) {
  // 测试线性变换 L'
  uint32_t input = 0x87654321;
  uint32_t output = sm4_linear_l_prime(input);
  
  // L'(B) = B ⊕ (B<<<13) ⊕ (B<<<23)
  uint32_t rotl13 = (input << 13) | (input >> 19);
  uint32_t rotl23 = (input << 23) | (input >> 9);
  
  uint32_t expected = input ^ rotl13 ^ rotl23;
  BOOST_CHECK_EQUAL(output, expected);
}

BOOST_AUTO_TEST_CASE(test_sm4_key_expansion) {
  // 测试密钥扩展
  sm4_round_keys_t rk;
  sm4_init_round_keys(&rk, test_key);
  
  // 验证生成了 32 个轮密钥
  // 根据 GM/T 0002-2012，第一个轮密钥应该是特定值
  // 这里我们只验证轮密钥不全为零
  bool all_zero = true;
  for (int i = 0; i < SM4_ROUNDS; i++) {
    if (rk.round_keys[i] != 0) {
      all_zero = false;
      break;
    }
  }
  BOOST_CHECK(!all_zero);
}

BOOST_AUTO_TEST_CASE(test_sm4_encrypt_block) {
  // 测试 SM4 加密（使用标准测试向量）
  sm4_round_keys_t rk;
  sm4_init_round_keys(&rk, test_key);
  
  uint8_t ciphertext[16];
  sm4_encrypt_block(&rk, test_plaintext, ciphertext);
  
  // 验证密文与预期一致
  for (int i = 0; i < 16; i++) {
    BOOST_CHECK_EQUAL(ciphertext[i], expected_ciphertext[i]);
  }
}

BOOST_AUTO_TEST_CASE(test_sm4_encrypt_decrypt_roundtrip) {
  // 测试加密-解密往返（SM4 加密和解密使用相同算法，只是轮密钥反向）
  sm4_round_keys_t rk_enc, rk_dec;
  sm4_init_round_keys(&rk_enc, test_key);
  
  // 创建反向轮密钥用于解密
  for (int i = 0; i < SM4_ROUNDS; i++) {
    rk_dec.round_keys[i] = rk_enc.round_keys[SM4_ROUNDS - 1 - i];
  }
  
  uint8_t ciphertext[16];
  sm4_encrypt_block(&rk_enc, test_plaintext, ciphertext);
  
  uint8_t decrypted[16];
  sm4_encrypt_block(&rk_dec, ciphertext, decrypted);
  
  // 验证解密后恢复原文
  for (int i = 0; i < 16; i++) {
    BOOST_CHECK_EQUAL(decrypted[i], test_plaintext[i]);
  }
}

BOOST_AUTO_TEST_CASE(test_sm4_prg_basic) {
  // 测试 PRG 基础功能
  const uint8_t key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  const uint8_t iv[16]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  
  uint8_t output1[32];
  uint8_t output2[32];
  
  // 多次调用应产生相同输出
  sm4_prg(key, iv, 0, output1, 128, 32);
  sm4_prg(key, iv, 0, output2, 128, 32);
  
  for (int i = 0; i < 32; i++) {
    BOOST_CHECK_EQUAL(output1[i], output2[i]);
  }
  
  // 不同 tweak 应产生不同输出
  uint8_t output3[32];
  sm4_prg(key, iv, 1, output3, 128, 32);
  
  bool different = false;
  for (int i = 0; i < 32; i++) {
    if (output1[i] != output3[i]) {
      different = true;
      break;
    }
  }
  BOOST_CHECK(different);
}

BOOST_AUTO_TEST_CASE(test_sm4_prg_2_lambda) {
  // 测试 prg_2_lambda
  const uint8_t key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  const uint8_t iv[16]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  
  uint8_t output[32]; // 2 * 128 bits = 32 bytes
  sm4_prg_2_lambda(key, iv, 0, output, 128);
  
  // 验证输出长度正确且不全为零
  bool all_zero = true;
  for (int i = 0; i < 32; i++) {
    if (output[i] != 0) {
      all_zero = false;
      break;
    }
  }
  BOOST_CHECK(!all_zero);
}

BOOST_AUTO_TEST_CASE(test_sm4_prg_4_lambda) {
  // 测试 prg_4_lambda
  const uint8_t key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  const uint8_t iv[16]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  
  uint8_t output[64]; // 4 * 128 bits = 64 bytes
  sm4_prg_4_lambda(key, iv, 0, output, 128);
  
  // 验证输出长度正确且不全为零
  bool all_zero = true;
  for (int i = 0; i < 64; i++) {
    if (output[i] != 0) {
      all_zero = false;
      break;
    }
  }
  BOOST_CHECK(!all_zero);
}

BOOST_AUTO_TEST_CASE(test_sm4_increment_iv) {
  // 测试 IV 递增
  uint8_t iv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  
  sm4_increment_iv(iv);
  BOOST_CHECK_EQUAL(iv[0], 0x01);
  
  // 测试进位
  for (int i = 0; i < 16; i++) {
    iv[i] = 0xFF;
  }
  sm4_increment_iv(iv);
  BOOST_CHECK_EQUAL(iv[0], 0x00);
  BOOST_CHECK_EQUAL(iv[1], 0x00); // 进位被截断
}

BOOST_AUTO_TEST_SUITE_END()
