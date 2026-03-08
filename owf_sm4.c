/*
 *  SPDX-License-Identifier: MIT
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include <assert.h>
#include <string.h>

#include "owf_sm4.h"
#include "sm4.h"
#include "utils.h"

// ============ SM4 标准模式 OWF ============
// output = SM4(key, input)
void owf_sm4_128(const uint8_t* key, const uint8_t* input, uint8_t* output) {
  // 初始化轮密钥
  sm4_round_keys_t rk;
  sm4_init_round_keys(&rk, key);
  
  // 执行 SM4 加密
  sm4_encrypt_block(&rk, input, output);
}

// ============ SM4 EM 模式 OWF ============
// output = SM4(input, key) ⊕ key
// EM 模式交换了 key 和 input 的角色，并在输出上异或 key
void owf_em_sm4_128(const uint8_t* key, const uint8_t* input, uint8_t* output) {
  // EM 模式：用 input 作为密钥，key 作为数据
  sm4_round_keys_t rk;
  sm4_init_round_keys(&rk, input);
  
  // 加密 key
  sm4_encrypt_block(&rk, key, output);
  
  // 输出异或 key
  xor_u8_array(output, key, output, 16);
}
