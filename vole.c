/*
 *  SPDX-License-Identifier: MIT
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include "vole.h"
#include "aes.h"
#include "sm4.h"
#include "utils.h"
#include "random_oracle.h"
#include "instances.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

static const uint32_t TWEAK_OFFSET = UINT32_C(0x80000000); // 2^31

static inline uint16_t sm4_bitreverse_k(uint16_t v, unsigned int k) {
  uint16_t r = 0;
  for (unsigned int i = 0; i < k; ++i) {
    r = (uint16_t)((r << 1) | ((v >> i) & 1u));
  }
  return r;
}

static unsigned int convert_to_vole_reconstruct(const uint8_t* iv, const uint8_t* sd_compact,
                                                uint16_t i_delta, unsigned int i,
                                                unsigned int outlen, uint8_t* v,
                                                const faest_paramset_t* params) {
  const unsigned int lambda        = params->lambda;
  const unsigned int tau_1         = params->tau1;
  const unsigned int k             = params->k;
  const unsigned int num_instances = bavc_max_node_index(i, tau_1, k);
  const unsigned int lambda_bytes  = lambda / 8;
  const unsigned int depth         = bavc_max_node_depth(i, tau_1, k);

  uint8_t* r = calloc(2 * num_instances, outlen);
  if (!r) {
    return 0;
  }

#define R_REC(row, column) (r + (((row) % 2) * num_instances + (column)) * outlen)
#define V_REC(idx) (v + (idx) * outlen)

  uint32_t tweak = i ^ TWEAK_OFFSET;

  for (unsigned int dst_j = 1; dst_j < num_instances; ++dst_j) {
    const unsigned int orig_j = dst_j ^ i_delta;
    const unsigned int src_idx = (orig_j < i_delta) ? orig_j : (orig_j - 1);
    if (faest_is_sm4(params)) {
      sm4_prg(sd_compact + lambda_bytes * src_idx, iv, tweak, R_REC(0, dst_j), lambda, outlen);
    } else {
      prg(sd_compact + lambda_bytes * src_idx, iv, tweak, R_REC(0, dst_j), lambda, outlen);
    }
  }

  memset(v, 0, depth * outlen);
  for (unsigned int j = 0; j < depth; j++) {
    const unsigned int depthloop = num_instances >> (j + 1);
    for (unsigned int idx = 0; idx < depthloop; idx++) {
      xor_u8_array(V_REC(j), R_REC(j, 2 * idx + 1), V_REC(j), outlen);
      xor_u8_array(R_REC(j, 2 * idx), R_REC(j, 2 * idx + 1), R_REC(j + 1, idx), outlen);
    }
  }

#undef R_REC
#undef V_REC

  free(r);
  return depth;
}

#if !defined(FAEST_TESTS)
static
#endif
    unsigned int
    convert_to_vole(const uint8_t* iv, const uint8_t* sd, bool sd0_bot, unsigned int i,
                    unsigned int outlen, uint8_t* u, uint8_t* v, const faest_paramset_t* params) {
/* dump the first seed for SM4 on i==0 before PRG */
  const unsigned int lambda        = params->lambda;
  const unsigned int tau_1         = params->tau1;
  const unsigned int k             = params->k;
  const unsigned int num_instances = bavc_max_node_index(i, tau_1, k);
  const unsigned int lambda_bytes  = lambda / 8;
  const unsigned int depth         = bavc_max_node_depth(i, tau_1, k);

  // (depth + 1) x num_instances array of outlen; but we only need two rows at a time
  uint8_t* r = calloc(2 * num_instances, outlen);
  if (!r) {
    return 0;
  }

#define R(row, column) (r + (((row) % 2) * num_instances + (column)) * outlen)
#define V(idx) (v + (idx) * outlen)

  uint32_t tweak = i ^ TWEAK_OFFSET;

  // Step: 2
  if (!sd0_bot) {
    if (faest_is_sm4(params)) {
      sm4_prg(sd, iv, tweak, R(0, 0), lambda, outlen);
    } else {
      prg(sd, iv, tweak, R(0, 0), lambda, outlen);
    }
  }

  // Step: 3..4
  for (unsigned int j = 1; j < num_instances; ++j) {
    if (faest_is_sm4(params)) {
      sm4_prg(sd + lambda_bytes * j, iv, tweak, R(0, j), lambda, outlen);
    } else {
      prg(sd + lambda_bytes * j, iv, tweak, R(0, j), lambda, outlen);
    }
  }

  // Step: 5..9
  memset(v, 0, depth * outlen);
  for (unsigned int j = 0; j < depth; j++) {
    unsigned int depthloop = num_instances >> (j + 1);
    for (unsigned int idx = 0; idx < depthloop; idx++) {
      xor_u8_array(V(j), R(j, 2 * idx + 1), V(j), outlen);
      xor_u8_array(R(j, 2 * idx), R(j, 2 * idx + 1), R(j + 1, idx), outlen);
    }
  }

  // Step: 10
  if (!sd0_bot && u != NULL) {
    memcpy(u, R(depth, 0), outlen);
  }
  free(r);
  return depth;
}

bool vole_commit(const uint8_t* rootKey, const uint8_t* iv, unsigned int ellhat,
                 const faest_paramset_t* params, bavc_t* bavc, uint8_t* c, uint8_t* u,
                 uint8_t** v) {
  const unsigned int lambda       = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int ellhat_bytes = (ellhat + 7) / 8;
  const unsigned int tau          = params->tau;
  const unsigned int tau_1        = params->tau1;
  const unsigned int k            = params->k;

  if (!bavc_commit(bavc, rootKey, iv, params)) {
    return false;
  }

  uint8_t* ui = malloc(tau * ellhat_bytes);
  if (!ui) {
    bavc_clear(bavc);
    return false;
  }

  unsigned int v_idx = 0;
  uint8_t* sd_i      = bavc->sd;
  for (unsigned int i = 0; i < tau; ++i) {
    // Step 6
    const unsigned int ki =
        convert_to_vole(iv, sd_i, false, i, ellhat_bytes, ui + i * ellhat_bytes, v[v_idx], params);
    if (ki == 0) {
      free(ui);
      bavc_clear(bavc);
      return false;
    }
    v_idx += ki;
    sd_i += lambda_bytes * bavc_max_node_index(i, tau_1, k);
  }

  // ensure 0-padding up to lambda
  assert(v_idx <= lambda);
  for (; v_idx < lambda; ++v_idx) {
    memset(v[v_idx], 0, ellhat_bytes);
  }

  // Step 9
  memcpy(u, ui, ellhat_bytes);
  for (unsigned int i = 1; i < tau; i++) {
    // Step 11
    xor_u8_array(u, ui + i * ellhat_bytes, c + (i - 1) * ellhat_bytes, ellhat_bytes);
  }
  free(ui);
  return true;
}


bool vole_reconstruct(uint8_t* com, uint8_t** q, const uint8_t* iv, const uint8_t* chall_3,
                      const uint8_t* decom_i, const uint8_t* c, unsigned int ellhat,
                      const faest_paramset_t* params) {
  const unsigned int lambda       = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int ellhat_bytes = (ellhat + 7) / 8;
  const unsigned int tau          = params->tau;
  const unsigned int tau1         = params->tau1;
  const unsigned int L            = params->L;
  const unsigned int k            = params->k;

  uint16_t i_delta[MAX_TAU];
  if (!decode_all_chall_3(i_delta, chall_3, params)) {
    return false;
  }

  bavc_rec_t bavc_rec;
  bavc_rec.h = com;
  bavc_rec.s = malloc((L - tau) * lambda_bytes);
  if (!bavc_rec.s) {
    return false;
  }

  if (!bavc_reconstruct(&bavc_rec, decom_i, i_delta, iv, params)) {
    free(bavc_rec.s);
    return false;
  }

  uint8_t* sd   = malloc((1 << k) * lambda_bytes);
  uint8_t* qtmp = malloc(MAX_DEPTH * ellhat_bytes);
  if (!sd || !qtmp) {
    free(sd);
    free(qtmp);
    free(bavc_rec.s);
    return false;
  }

  // Step: 1
  unsigned int q_idx = 0;
  uint8_t* sd_i      = bavc_rec.s;
  for (unsigned int i = 0; i < tau; i++) {
    // Step: 2
    const unsigned int Ni = bavc_max_node_index(i, tau1, k);

    // Step: 6
    const uint16_t i_delta_eff = i_delta[i];
    memset(sd, 0, (size_t)Ni * lambda_bytes);
    for (unsigned int j = 0; j < Ni; j++) {
      if (j == i_delta_eff) {
        continue;
      }

      const unsigned int src_idx = (j < i_delta_eff) ? j : (j - 1);
      memcpy(sd + (j ^ i_delta_eff) * lambda_bytes, sd_i + lambda_bytes * src_idx, lambda_bytes);
    }

    // Step: 7..8
    const unsigned int ki = convert_to_vole(iv, sd, true, i, ellhat_bytes, NULL, qtmp, params);
    if (ki == 0) {
      free(qtmp);
      free(sd);
      free(bavc_rec.s);
      return false;
    }

    // Step 11
    if (i == 0) {
      // Step 8
      memcpy(q[q_idx], qtmp, ellhat_bytes * ki);
      q_idx += ki;
    } else {
      // Step 14
      for (unsigned int d = 0; d < ki; ++d, ++q_idx) {
        masked_xor_u8_array(qtmp + d * ellhat_bytes, c + (i - 1) * ellhat_bytes, q[q_idx],
                            (i_delta[i] >> d) & 1, ellhat_bytes);
      }
    }
    sd_i += lambda_bytes * (Ni - 1);
  }

  // ensure 0-padding up to lambda
  assert(q_idx <= lambda);
  for (; q_idx < lambda; ++q_idx) {
    memset(q[q_idx], 0, ellhat_bytes);
  }

  free(qtmp);
  free(sd);
  free(bavc_rec.s);
  return true;
}

bool vole_reconstruct_sm4(uint8_t* com, uint8_t** q, const uint8_t* iv, const uint8_t* chall_3,
                          const uint8_t* decom_i, const uint8_t* c, unsigned int ellhat,
                          const faest_paramset_t* params) {
  const unsigned int lambda       = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int ellhat_bytes = (ellhat + 7) / 8;
  const unsigned int tau          = params->tau;
  const unsigned int tau1         = params->tau1;
  const unsigned int L            = params->L;
  const unsigned int k            = params->k;


  uint16_t i_delta[MAX_TAU];
  if (!decode_all_chall_3_sm4(i_delta, chall_3, params)) {
    return false;
  }


  bavc_rec_t bavc_rec;
  bavc_rec.h = com;
  bavc_rec.s = malloc((L - tau) * lambda_bytes);
  if (!bavc_rec.s) {
    return false;
  }

  if (!bavc_reconstruct_sm4(&bavc_rec, decom_i, i_delta, iv, params)) {
    free(bavc_rec.s);
    return false;
  }

  uint8_t* qtmp = malloc(MAX_DEPTH * ellhat_bytes);
  if (!qtmp) {
    free(qtmp);
    free(bavc_rec.s);
    return false;
  }

  unsigned int q_idx = 0;
  uint8_t* sd_i      = bavc_rec.s;
  for (unsigned int i = 0; i < tau; i++) {
    const unsigned int Ni = bavc_max_node_index(i, tau1, k);

    const unsigned int ki =
        convert_to_vole_reconstruct(iv, sd_i, i_delta[i], i, ellhat_bytes, qtmp, params);
    if (ki == 0) {
      free(qtmp);
      free(bavc_rec.s);
      return false;
    }

    if (i == 0) {
      memcpy(q[q_idx], qtmp, ellhat_bytes * ki);
      q_idx += ki;
    } else {
      for (unsigned int d = 0; d < ki; ++d, ++q_idx) {
        masked_xor_u8_array(qtmp + d * ellhat_bytes, c + (i - 1) * ellhat_bytes, q[q_idx],
          (i_delta[i] >> d) & 1u, ellhat_bytes);
      }
    }
    sd_i += lambda_bytes * (Ni - 1);
  }

  assert(q_idx <= lambda);
  for (; q_idx < lambda; ++q_idx) {
    memset(q[q_idx], 0, ellhat_bytes);
  }

  free(qtmp);
  free(bavc_rec.s);
  return true;
}
