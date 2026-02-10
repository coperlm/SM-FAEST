/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef FAEST_FAEST_SM4_H
#define FAEST_FAEST_SM4_H

#include <stdint.h>

#include "instances.h"
#include "sm4.h"

FAEST_BEGIN_C_DECL

// SM4 ZK 证明系统的 Prover 函数
// 生成证明数据以证明知道私钥 w
void sm4_128_prover(uint8_t* a0_tilde, uint8_t* a1_tilde, uint8_t* a2_tilde, const uint8_t* w,
                    const uint8_t* u, uint8_t** V, const uint8_t* owf_in, const uint8_t* owf_out,
                    const uint8_t* chall_2, const faest_paramset_t* params);

// SM4 ZK 证明系统的 Verifier 函数
// 验证证明的有效性
void sm4_128_verifier(uint8_t* a0_tilde, const uint8_t* d, uint8_t** Q, const uint8_t* owf_in,
                      const uint8_t* owf_out, const uint8_t* chall_2, const uint8_t* chall_3,
                      const uint8_t* a1_tilde, const uint8_t* a2_tilde,
                      const faest_paramset_t* params);

FAEST_END_C_DECL

#endif
