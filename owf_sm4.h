/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef OWF_SM4_H
#define OWF_SM4_H

#include "macros.h"

#include <stdint.h>

FAEST_BEGIN_C_DECL

// SM4 单向函数：标准模式
// output = SM4(key, input)
void owf_sm4_128(const uint8_t* key, const uint8_t* input, uint8_t* output);

// SM4 单向函数：EM (Expanding Message) 模式
// output = SM4(input, key) ⊕ key
void owf_em_sm4_128(const uint8_t* key, const uint8_t* input, uint8_t* output);

// 参数集别名（用于 FAEST 参数系统）
#define faest_sm4_128s_owf owf_sm4_128
#define faest_sm4_128f_owf owf_sm4_128

#define faest_em_sm4_128s_owf owf_em_sm4_128
#define faest_em_sm4_128f_owf owf_em_sm4_128

FAEST_END_C_DECL

#endif
