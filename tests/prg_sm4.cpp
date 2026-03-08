/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "sm4.h"
#include <boost/test/unit_test.hpp>
#include <cstring>

BOOST_AUTO_TEST_SUITE(prg_sm4)

static const uint8_t test_key[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
};

static const uint8_t test_iv[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

BOOST_AUTO_TEST_CASE(test_prg_deterministic) {
  // 测试 PRG 的确定性
  uint8_t output1[64];
  uint8_t output2[64];
  
  sm4_prg(test_key, test_iv, 0, output1, 128, 64);
  sm4_prg(test_key, test_iv, 0, output2, 128, 64);
  
  // 验证输出一致
  for (int i = 0; i < 64; i++) {
    BOOST_CHECK_EQUAL(output1[i], output2[i]);
  }
}

BOOST_AUTO_TEST_CASE(test_prg_different_tweaks) {
  // 测试不同 tweak 产生不同输出
  uint8_t output1[32];
  uint8_t output2[32];
  
  sm4_prg(test_key, test_iv, 0, output1, 128, 32);
  sm4_prg(test_key, test_iv, 1, output2, 128, 32);
  
  bool different = false;
  for (int i = 0; i < 32; i++) {
    if (output1[i] != output2[i]) {
      different = true;
      break;
    }
  }
  BOOST_CHECK(different);
}

BOOST_AUTO_TEST_CASE(test_prg_different_keys) {
  // 测试不同密钥产生不同输出
  const uint8_t key2[16] = {
      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
      0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
  };
  
  uint8_t output1[32];
  uint8_t output2[32];
  
  sm4_prg(test_key, test_iv, 0, output1, 128, 32);
  sm4_prg(key2, test_iv, 0, output2, 128, 32);
  
  bool different = false;
  for (int i = 0; i < 32; i++) {
    if (output1[i] != output2[i]) {
      different = true;
      break;
    }
  }
  BOOST_CHECK(different);
}

BOOST_AUTO_TEST_CASE(test_prg_different_ivs) {
  // 测试不同 IV 产生不同输出
  const uint8_t iv2[16] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
  };
  
  uint8_t output1[32];
  uint8_t output2[32];
  
  sm4_prg(test_key, test_iv, 0, output1, 128, 32);
  sm4_prg(test_key, iv2, 0, output2, 128, 32);
  
  bool different = false;
  for (int i = 0; i < 32; i++) {
    if (output1[i] != output2[i]) {
      different = true;
      break;
    }
  }
  BOOST_CHECK(different);
}

BOOST_AUTO_TEST_CASE(test_prg_output_lengths) {
  // 测试不同输出长度
  const size_t lengths[] = {16, 32, 48, 64, 100, 128, 256};
  
  for (size_t len : lengths) {
    uint8_t* output = new uint8_t[len];
    sm4_prg(test_key, test_iv, 0, output, 128, len);
    
    // 验证输出不全为零
    bool all_zero = true;
    for (size_t i = 0; i < len; i++) {
      if (output[i] != 0) {
        all_zero = false;
        break;
      }
    }
    BOOST_CHECK(!all_zero);
    
    delete[] output;
  }
}

BOOST_AUTO_TEST_CASE(test_prg_partial_block) {
  // 测试不完整块的处理
  uint8_t output_full[32];
  uint8_t output_partial[20];
  
  sm4_prg(test_key, test_iv, 0, output_full, 128, 32);
  sm4_prg(test_key, test_iv, 0, output_partial, 128, 20);
  
  // 验证前 20 字节应该相同
  for (int i = 0; i < 20; i++) {
    BOOST_CHECK_EQUAL(output_partial[i], output_full[i]);
  }
}

BOOST_AUTO_TEST_CASE(test_prg_ctr_mode) {
  // 测试 CTR 模式：连续的块应该对应递增的计数器
  uint8_t output[48]; // 3 块
  sm4_prg(test_key, test_iv, 0, output, 128, 48);
  
  // 手动验证 CTR 模式逻辑
  sm4_round_keys_t rk;
  sm4_init_round_keys(&rk, test_key);
  
  uint8_t iv_copy[16];
  memcpy(iv_copy, test_iv, 16);
  
  uint8_t expected[48];
  for (int i = 0; i < 3; i++) {
    sm4_encrypt_block(&rk, iv_copy, expected + i * 16);
    sm4_increment_iv(iv_copy);
  }
  
  // 验证输出匹配
  for (int i = 0; i < 48; i++) {
    BOOST_CHECK_EQUAL(output[i], expected[i]);
  }
}

BOOST_AUTO_TEST_CASE(test_sm4_prg_2_lambda) {
  // 测试 sm4_prg_2_lambda
  uint8_t output[32]; // 2 * 128 bits = 32 bytes
  sm4_prg_2_lambda(test_key, test_iv, 0, output, 128);
  
  // 验证与直接调用 prg 的结果一致
  uint8_t expected[32];
  sm4_prg(test_key, test_iv, 0, expected, 128, 32);
  
  for (int i = 0; i < 32; i++) {
    BOOST_CHECK_EQUAL(output[i], expected[i]);
  }
}

BOOST_AUTO_TEST_CASE(test_sm4_prg_4_lambda) {
  // 测试 sm4_prg_4_lambda
  uint8_t output[64]; // 4 * 128 bits = 64 bytes
  sm4_prg_4_lambda(test_key, test_iv, 0, output, 128);
  
  // 验证与直接调用 prg 的结果一致
  uint8_t expected[64];
  sm4_prg(test_key, test_iv, 0, expected, 128, 64);
  
  for (int i = 0; i < 64; i++) {
    BOOST_CHECK_EQUAL(output[i], expected[i]);
  }
}

BOOST_AUTO_TEST_CASE(test_prg_randomness_quality) {
  // 基础随机性质量测试（统计检验）
  uint8_t output[1024];
  sm4_prg(test_key, test_iv, 0, output, 128, 1024);
  
  // 1. 检查零和一的比特数应该大致相等（允许 10% 偏差）
  int bit_count = 0;
  for (int i = 0; i < 1024; i++) {
    for (int j = 0; j < 8; j++) {
      if (output[i] & (1 << j)) {
        bit_count++;
      }
    }
  }
  int total_bits = 1024 * 8;
  int expected_bits = total_bits / 2;
  int tolerance = total_bits / 10; // 10% 容差
  
  BOOST_CHECK(bit_count > expected_bits - tolerance);
  BOOST_CHECK(bit_count < expected_bits + tolerance);
  
  // 2. 检查不应有长串重复字节
  int max_repeat = 0;
  int current_repeat = 1;
  for (int i = 1; i < 1024; i++) {
    if (output[i] == output[i-1]) {
      current_repeat++;
      max_repeat = std::max(max_repeat, current_repeat);
    } else {
      current_repeat = 1;
    }
  }
  
  // 最长重复不应超过 8 个字节（概率性检查）
  BOOST_CHECK(max_repeat < 8);
}

BOOST_AUTO_TEST_CASE(test_prg_tweak_effect) {
  // 测试 tweak 对 IV 的影响
  uint8_t output_no_tweak[32];
  uint8_t output_with_tweak[32];
  
  sm4_prg(test_key, test_iv, 0, output_no_tweak, 128, 32);
  sm4_prg(test_key, test_iv, 0x10000000, output_with_tweak, 128, 32);
  
  // Tweak 应该加到 IV 的高位字上，产生不同输出
  bool different = false;
  for (int i = 0; i < 32; i++) {
    if (output_no_tweak[i] != output_with_tweak[i]) {
      different = true;
      break;
    }
  }
  BOOST_CHECK(different);
}

BOOST_AUTO_TEST_CASE(test_increment_iv) {
  // 测试 IV 递增功能
  uint8_t iv[16];
  memcpy(iv, test_iv, 16);
  
  uint8_t original_iv[16];
  memcpy(original_iv, test_iv, 16);
  
  // 递增一次
  sm4_increment_iv(iv);
  
  // 验证只有第一个字节（小端）增加了 1
  BOOST_CHECK_EQUAL(iv[0], original_iv[0] + 1);
  
  // 测试进位
  uint8_t iv_ff[16] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  sm4_increment_iv(iv_ff);
  BOOST_CHECK_EQUAL(iv_ff[0], 0x00);
  BOOST_CHECK_EQUAL(iv_ff[4], 0x00); // 进位被4字节边界截断
}

BOOST_AUTO_TEST_SUITE_END()
