/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef OWF_H
#define OWF_H

#include "macros.h"

#include <stdint.h>

FAEST_BEGIN_C_DECL

void owf_128(const uint8_t* key, const uint8_t* input, uint8_t* output);
void owf_em_128(const uint8_t* key, const uint8_t* input, uint8_t* output);

#define faest_128s_owf owf_128

// Include SM4 OWF functions
#include "owf_sm4.h"

FAEST_END_C_DECL

#endif
