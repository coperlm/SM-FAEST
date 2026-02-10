/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "owf_sm4.h"
#include "sm4.h"
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(owf_sm4)

static const uint8_t test_key[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

static const uint8_t test_input[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

static const uint8_t expected_output[16] = {
    0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
    0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
};

BOOST_AUTO_TEST_CASE(test_owf_sm4_128_basic) {
  // 测试标准 OWF
  uint8_t output[16];
  owf_sm4_128(test_key, test_input, output);
  
  // 验证输出
  for (int i = 0; i < 16; i++) {
    BOOST_CHECK_EQUAL(output[i], expected_output[i]);
  }
}

BOOST_AUTO_TEST_CASE(test_owf_sm4_128_deterministic) {
  // 测试确定性：相同输入应产生相同输出
  uint8_t output1[16];
  uint8_t output2[16];
  
  owf_sm4_128(test_key, test_input, output1);
  owf_sm4_128(test_key, test_input, output2);
  
  for (int i = 0; i < 16; i++) {
    BOOST_CHECK_EQUAL(output1[i], output2[i]);
  }
}

BOOST_AUTO_TEST_CASE(test_owf_sm4_128_different_keys) {
  // 测试不同密钥产生不同输出
  const uint8_t key2[16] = {
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
      0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
  };
  
  uint8_t output1[16];
  uint8_t output2[16];
  
  owf_sm4_128(test_key, test_input, output1);
  owf_sm4_128(key2, test_input, output2);
  
  bool different = false;
  for (int i = 0; i < 16; i++) {
    if (output1[i] != output2[i]) {
      different = true;
      break;
    }
  }
  BOOST_CHECK(different);
}

BOOST_AUTO_TEST_CASE(test_owf_sm4_128_different_inputs) {
  // 测试不同输入产生不同输出
  const uint8_t input2[16] = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };
  
  uint8_t output1[16];
  uint8_t output2[16];
  
  owf_sm4_128(test_key, test_input, output1);
  owf_sm4_128(test_key, input2, output2);
  
  bool different = false;
  for (int i = 0; i < 16; i++) {
    if (output1[i] != output2[i]) {
      different = true;
      break;
    }
  }
  BOOST_CHECK(different);
}

BOOST_AUTO_TEST_CASE(test_owf_em_sm4_128_basic) {
  // 测试 EM 模式 OWF
  uint8_t output[16];
  owf_em_sm4_128(test_key, test_input, output);
  
  // EM 模式输出不应全为零
  bool all_zero = true;
  for (int i = 0; i < 16; i++) {
    if (output[i] != 0) {
      all_zero = false;
      break;
    }
  }
  BOOST_CHECK(!all_zero);
}

BOOST_AUTO_TEST_CASE(test_owf_em_sm4_128_deterministic) {
  // 测试 EM 模式确定性
  uint8_t output1[16];
  uint8_t output2[16];
  
  owf_em_sm4_128(test_key, test_input, output1);
  owf_em_sm4_128(test_key, test_input, output2);
  
  for (int i = 0; i < 16; i++) {
    BOOST_CHECK_EQUAL(output1[i], output2[i]);
  }
}

BOOST_AUTO_TEST_CASE(test_owf_em_sm4_128_key_input_swap) {
  // 测试 EM 模式的 key 和 input 交换效应
  const uint8_t key1[16] = {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
  };
  const uint8_t input1[16] = {
      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
      0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
  };
  
  uint8_t output1[16];
  uint8_t output2[16];
  
  // EM 模式应该交换 key 和 input 的角色
  owf_em_sm4_128(key1, input1, output1);
  owf_em_sm4_128(input1, key1, output2);
  
  // 由于有额外的 XOR key 操作，输出不会完全相同
  // 但我们可以验证它们不全为零且有差异
  bool output1_not_zero = false;
  bool output2_not_zero = false;
  bool outputs_differ = false;
  
  for (int i = 0; i < 16; i++) {
    if (output1[i] != 0) output1_not_zero = true;
    if (output2[i] != 0) output2_not_zero = true;
    if (output1[i] != output2[i]) outputs_differ = true;
  }
  
  BOOST_CHECK(output1_not_zero);
  BOOST_CHECK(output2_not_zero);
  BOOST_CHECK(outputs_differ);
}

BOOST_AUTO_TEST_CASE(test_owf_em_sm4_128_vs_standard) {
  // 测试 EM 模式与标准模式的区别
  uint8_t output_standard[16];
  uint8_t output_em[16];
  
  owf_sm4_128(test_key, test_input, output_standard);
  owf_em_sm4_128(test_key, test_input, output_em);
  
  // 两种模式应产生不同输出
  bool different = false;
  for (int i = 0; i < 16; i++) {
    if (output_standard[i] != output_em[i]) {
      different = true;
      break;
    }
  }
  BOOST_CHECK(different);
}

BOOST_AUTO_TEST_CASE(test_owf_em_sm4_128_manual_verification) {
  // 手动验证 EM 模式的逻辑：output = SM4(input, key) ⊕ key
  uint8_t output_em[16];
  uint8_t output_manual[16];
  
  // EM 模式
  owf_em_sm4_128(test_key, test_input, output_em);
  
  // 手动计算：SM4(input 作为密钥, key 作为数据) ⊕ key
  sm4_round_keys_t rk;
  sm4_init_round_keys(&rk, test_input); // 用 input 作为密钥
  sm4_encrypt_block(&rk, test_key, output_manual); // 加密 key
  
  // XOR key
  for (int i = 0; i < 16; i++) {
    output_manual[i] ^= test_key[i];
  }
  
  // 验证一致性
  for (int i = 0; i < 16; i++) {
    BOOST_CHECK_EQUAL(output_em[i], output_manual[i]);
  }
}

BOOST_AUTO_TEST_SUITE_END()
