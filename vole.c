/*
 *  SPDX-License-Identifier: MIT
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include "vole.h"
#include "aes.h"
#include "utils.h"
#include "random_oracle.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

static const uint32_t TWEAK_OFFSET = UINT32_C(0x80000000); // 2^31

#if defined(FAEST_SM4_DEBUG)
static uint64_t sm4_hash64_fnv1a(const uint8_t* data, size_t len) {
  uint64_t h = 1469598103934665603ULL;
  for (size_t i = 0; i < len; ++i) {
    h ^= (uint64_t)data[i];
    h *= 1099511628211ULL;
  }
  return h;
}

static void sm4_dbg_hex_bytes(const char* label, const uint8_t* data, size_t len) {
  fprintf(stderr, "%s (%zu): ", label, len);
  for (size_t i = 0; i < len; ++i) {
    fprintf(stderr, "%02x", data[i]);
  }
  fprintf(stderr, "\n");
}
#endif

static inline uint16_t sm4_bitreverse_k(uint16_t v, unsigned int k) {
  uint16_t r = 0;
  for (unsigned int i = 0; i < k; ++i) {
    r = (uint16_t)((r << 1) | ((v >> i) & 1u));
  }
  return r;
}

#if !defined(FAEST_TESTS)
static
#endif
    unsigned int
    convert_to_vole(const uint8_t* iv, const uint8_t* sd, bool sd0_bot, unsigned int i,
                    unsigned int outlen, uint8_t* u, uint8_t* v, const faest_paramset_t* params) {
  const unsigned int lambda        = params->lambda;
  const unsigned int tau_1         = params->tau1;
  const unsigned int k             = params->k;
  const unsigned int num_instances = bavc_max_node_index(i, tau_1, k);
  const unsigned int lambda_bytes  = lambda / 8;
  const unsigned int depth         = bavc_max_node_depth(i, tau_1, k);

  // (depth + 1) x num_instances array of outlen; but we only need two rows at a time
  uint8_t* r = calloc(2 * num_instances, outlen);

#define R(row, column) (r + (((row) % 2) * num_instances + (column)) * outlen)
#define V(idx) (v + (idx) * outlen)

  uint32_t tweak = i ^ TWEAK_OFFSET;

  // Step: 2
  if (!sd0_bot) {
    prg(sd, iv, tweak, R(0, 0), lambda, outlen);
  }

  // Step: 3..4
  for (unsigned int j = 1; j < num_instances; ++j) {
    prg(sd + lambda_bytes * j, iv, tweak, R(0, j), lambda, outlen);
  }

#if defined(FAEST_SM4_DEBUG)
  if (i == 0) {
    const unsigned int trace_col = 4u;
    const unsigned int trace_row = 1u;
    const unsigned int trace_j = trace_col;
    if (trace_j < num_instances) {
      const char* side = sd0_bot ? "reconstruct" : "commit";
      char label[128];
      snprintf(label, sizeof(label),
               "[SM4_DEBUG] vole_trace seed row (i==0, j=4, %s)", side);
      sm4_dbg_hex_bytes(label, sd + lambda_bytes * trace_j, lambda_bytes);
      snprintf(label, sizeof(label),
               "[SM4_DEBUG] vole_trace prg R(0,4) (i==0, %s)", side);
      sm4_dbg_hex_bytes(label, R(0, trace_j), outlen);
      fprintf(stderr,
              "[SM4_DEBUG] vole_trace meta (i==0, %s) num_instances=%u depth=%u col=%u row=%u\n",
              side, num_instances, depth, trace_col, trace_row);
    }
  }
#endif

  // Step: 5..9
  memset(v, 0, depth * outlen);
  for (unsigned int j = 0; j < depth; j++) {
    unsigned int depthloop = num_instances >> (j + 1);
    for (unsigned int idx = 0; idx < depthloop; idx++) {
      xor_u8_array(V(j), R(j, 2 * idx + 1), V(j), outlen);
      xor_u8_array(R(j, 2 * idx), R(j, 2 * idx + 1), R(j + 1, idx), outlen);
    }
  }

#if defined(FAEST_SM4_DEBUG)
  if (i == 0 && depth > 4u) {
    const unsigned int trace_col = 4u;
    const unsigned int trace_row = 1u;
    const unsigned int byte_idx = trace_row >> 3;
    const unsigned int bit_idx = trace_row & 7u;
    const char* side = sd0_bot ? "reconstruct" : "commit";
    char label[128];
    snprintf(label, sizeof(label),
             "[SM4_DEBUG] vole_trace V(col=4) (i==0, %s)", side);
    sm4_dbg_hex_bytes(label, V(trace_col), outlen);
    fprintf(stderr,
            "[SM4_DEBUG] vole_trace V bit (i==0, %s) col=%u row=%u bit=%u\n",
            side, trace_col, trace_row, (V(trace_col)[byte_idx] >> bit_idx) & 1u);
  }
#endif
  // Step: 10
  if (!sd0_bot && u != NULL) {
    memcpy(u, R(depth, 0), outlen);
  }
  free(r);
  return depth;
}

void vole_commit(const uint8_t* rootKey, const uint8_t* iv, unsigned int ellhat,
                 const faest_paramset_t* params, bavc_t* bavc, uint8_t* c, uint8_t* u,
                 uint8_t** v) {
  const unsigned int lambda       = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int ellhat_bytes = (ellhat + 7) / 8;
  const unsigned int tau          = params->tau;
  const unsigned int tau_1        = params->tau1;
  const unsigned int k            = params->k;

  bavc_commit(bavc, rootKey, iv, params);

  uint8_t* ui = malloc(tau * ellhat_bytes);
  assert(ui);

  unsigned int v_idx = 0;
  uint8_t* sd_i      = bavc->sd;
  for (unsigned int i = 0; i < tau; ++i) {
    // Step 6
    const unsigned int v_idx_before = v_idx;
    const unsigned int ki =
        convert_to_vole(iv, sd_i, false, i, ellhat_bytes, ui + i * ellhat_bytes, v[v_idx], params);
    v_idx += ki;
#if defined(FAEST_SM4_DEBUG)
    if (i < 2) {
      const unsigned int Ni = bavc_max_node_index(i, tau_1, k);
      const uint64_t qtmp_hash = sm4_hash64_fnv1a(v[v_idx_before], (size_t)ki * ellhat_bytes);
      fprintf(stderr,
              "[SM4_DEBUG] vole_commit_sm4 i=%u Ni=%u ki=%u q_idx=%u qtmp_hash=0x%016llx\n",
              i, Ni, ki, v_idx_before, (unsigned long long)qtmp_hash);
    }
#endif
    sd_i += lambda_bytes * bavc_max_node_index(i, tau_1, k);
  }

  // ensure 0-padding up to lambda
  for (; v_idx != lambda; ++v_idx) {
    memset(v[v_idx], 0, ellhat_bytes);
  }

  // Step 9
  memcpy(u, ui, ellhat_bytes);
  for (unsigned int i = 1; i < tau; i++) {
    // Step 11
    xor_u8_array(u, ui + i * ellhat_bytes, c + (i - 1) * ellhat_bytes, ellhat_bytes);
  }
#if defined(FAEST_SM4_DEBUG)
  if (tau > 1) {
    const uint64_t c_hash = sm4_hash64_fnv1a(c, ellhat_bytes);
    fprintf(stderr, "[SM4_DEBUG] vole_commit_sm4 c_hash i=1 0x%016llx\n",
            (unsigned long long)c_hash);
  }
#endif
  free(ui);
}

#if defined(FAEST_SM4_DEBUG)
void vole_debug_reconstruct_like_from_commit(const bavc_t* bavc, const uint16_t* i_delta,
                                             const uint8_t* iv, unsigned int ellhat,
                                             const faest_paramset_t* params) {
  const unsigned int lambda_bytes = params->lambda / 8;
  const unsigned int ellhat_bytes = (ellhat + 7) / 8;
  const unsigned int tau          = params->tau;
  const unsigned int tau1         = params->tau1;
  const unsigned int k            = params->k;

  uint8_t* sd   = malloc((1u << k) * lambda_bytes);
  uint8_t* qtmp = malloc(MAX_DEPTH * ellhat_bytes);
  assert(sd);
  assert(qtmp);

  unsigned int q_idx = 0;
  const uint8_t* sd_i = bavc->sd;
  for (unsigned int i = 0; i < tau; ++i) {
    const unsigned int Ni = bavc_max_node_index(i, tau1, k);

#if defined(FAEST_SM4_DEBUG)
    if (i == 0) {
      const unsigned int k_eff = (i < tau1) ? k : (k - 1);
      const uint16_t i_delta_raw = i_delta[i];
      const uint16_t i_delta_rev = sm4_bitreverse_k(i_delta[i], k_eff);
      uint8_t* sd_tmp = malloc((size_t)Ni * lambda_bytes);
      uint8_t* qtmp_dbg = malloc(MAX_DEPTH * ellhat_bytes);
      assert(sd_tmp);
      assert(qtmp_dbg);
      memset(sd_tmp, 0, (size_t)Ni * lambda_bytes);

      // Variant A: direct placement, raw i_delta.
      for (unsigned int j = 0; j < Ni; ++j) {
        if (j == i_delta_raw) {
          continue;
        }
        const unsigned int src_idx = (j < i_delta_raw) ? j : (j - 1);
        memcpy(sd_tmp + j * lambda_bytes, sd_i + src_idx * lambda_bytes, lambda_bytes);
      }
      sm4_dbg_hex_bytes("[SM4_DEBUG] mapA sd[4]", sd_tmp + 4u * lambda_bytes, lambda_bytes);
      {
        const unsigned int ki_dbg =
            convert_to_vole(iv, sd_tmp, true, i, ellhat_bytes, NULL, qtmp_dbg, params);
        const uint64_t qtmp_hash = sm4_hash64_fnv1a(qtmp_dbg, (size_t)ki_dbg * ellhat_bytes);
        fprintf(stderr, "[SM4_DEBUG] mapA qtmp_hash=0x%016llx\n",
                (unsigned long long)qtmp_hash);
      }
      {
        const unsigned int ki_dbg =
            convert_to_vole(iv, sd_tmp, false, i, ellhat_bytes, NULL, qtmp_dbg, params);
        const uint64_t qtmp_hash = sm4_hash64_fnv1a(qtmp_dbg, (size_t)ki_dbg * ellhat_bytes);
        fprintf(stderr, "[SM4_DEBUG] mapA sd0_bot=0 qtmp_hash=0x%016llx\n",
                (unsigned long long)qtmp_hash);
      }

      // Variant B: XOR placement, raw i_delta.
      memset(sd_tmp, 0, (size_t)Ni * lambda_bytes);
      for (unsigned int j = 0; j < Ni; ++j) {
        if (j == i_delta_raw) {
          continue;
        }
        const unsigned int src_idx = (j < i_delta_raw) ? j : (j - 1);
        memcpy(sd_tmp + (j ^ i_delta_raw) * lambda_bytes, sd_i + src_idx * lambda_bytes,
               lambda_bytes);
      }
      sm4_dbg_hex_bytes("[SM4_DEBUG] mapB sd[4]", sd_tmp + 4u * lambda_bytes, lambda_bytes);
      {
        const unsigned int ki_dbg =
            convert_to_vole(iv, sd_tmp, true, i, ellhat_bytes, NULL, qtmp_dbg, params);
        const uint64_t qtmp_hash = sm4_hash64_fnv1a(qtmp_dbg, (size_t)ki_dbg * ellhat_bytes);
        fprintf(stderr, "[SM4_DEBUG] mapB qtmp_hash=0x%016llx\n",
                (unsigned long long)qtmp_hash);
      }

      // Variant C: direct placement, bit-reversed i_delta.
      memset(sd_tmp, 0, (size_t)Ni * lambda_bytes);
      for (unsigned int j = 0; j < Ni; ++j) {
        if (j == i_delta_rev) {
          continue;
        }
        const unsigned int src_idx = (j < i_delta_rev) ? j : (j - 1);
        memcpy(sd_tmp + j * lambda_bytes, sd_i + src_idx * lambda_bytes, lambda_bytes);
      }
      sm4_dbg_hex_bytes("[SM4_DEBUG] mapC sd[4]", sd_tmp + 4u * lambda_bytes, lambda_bytes);
      {
        const unsigned int ki_dbg =
            convert_to_vole(iv, sd_tmp, true, i, ellhat_bytes, NULL, qtmp_dbg, params);
        const uint64_t qtmp_hash = sm4_hash64_fnv1a(qtmp_dbg, (size_t)ki_dbg * ellhat_bytes);
        fprintf(stderr, "[SM4_DEBUG] mapC qtmp_hash=0x%016llx\n",
                (unsigned long long)qtmp_hash);
      }

      // Variant D: XOR placement, bit-reversed i_delta.
      memset(sd_tmp, 0, (size_t)Ni * lambda_bytes);
      for (unsigned int j = 0; j < Ni; ++j) {
        if (j == i_delta_rev) {
          continue;
        }
        const unsigned int src_idx = (j < i_delta_rev) ? j : (j - 1);
        memcpy(sd_tmp + (j ^ i_delta_rev) * lambda_bytes, sd_i + src_idx * lambda_bytes,
               lambda_bytes);
      }
      sm4_dbg_hex_bytes("[SM4_DEBUG] mapD sd[4]", sd_tmp + 4u * lambda_bytes, lambda_bytes);
      {
        const unsigned int ki_dbg =
            convert_to_vole(iv, sd_tmp, true, i, ellhat_bytes, NULL, qtmp_dbg, params);
        const uint64_t qtmp_hash = sm4_hash64_fnv1a(qtmp_dbg, (size_t)ki_dbg * ellhat_bytes);
        fprintf(stderr, "[SM4_DEBUG] mapD qtmp_hash=0x%016llx\n",
                (unsigned long long)qtmp_hash);
      }

      free(qtmp_dbg);
      free(sd_tmp);
    }
#endif

    // SM4: XOR placement using the raw i_delta index.
    const unsigned int k_eff = (i < tau1) ? k : (k - 1);
    const uint16_t i_delta_eff = sm4_bitreverse_k(i_delta[i], k_eff);
    memset(sd, 0, (size_t)Ni * lambda_bytes);
    for (unsigned int j = 0; j < Ni; ++j) {
      if (j == i_delta_eff) {
        continue;
      }

      const unsigned int src_idx = (j < i_delta_eff) ? j : (j - 1);
            memcpy(sd + (j ^ i_delta_eff) * lambda_bytes, sd_i + lambda_bytes * src_idx,
              lambda_bytes);
    }

    const unsigned int ki =
        convert_to_vole(iv, sd, true, i, ellhat_bytes, NULL, qtmp, params);
    if (i < 2) {
      const uint64_t qtmp_hash = sm4_hash64_fnv1a(qtmp, (size_t)ki * ellhat_bytes);
      fprintf(stderr,
              "[SM4_DEBUG] vole_commit_reconstruct_like i=%u Ni=%u ki=%u q_idx=%u qtmp_hash=0x%016llx\n",
              i, Ni, ki, q_idx, (unsigned long long)qtmp_hash);
    }
    q_idx += ki;
    sd_i += lambda_bytes * Ni;
  }

  free(qtmp);
  free(sd);
}
#endif

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
  assert(bavc_rec.s);

  if (!bavc_reconstruct(&bavc_rec, decom_i, i_delta, iv, params)) {
    free(bavc_rec.s);
    return false;
  }

  uint8_t* sd   = malloc((1 << k) * lambda_bytes);
  uint8_t* qtmp = malloc(MAX_DEPTH * ellhat_bytes);
  assert(sd);
  assert(qtmp);

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
            memcpy(sd + (j ^ i_delta_eff) * lambda_bytes, sd_i + lambda_bytes * src_idx,
              lambda_bytes);
    }

    // Step: 7..8
    const unsigned int ki = convert_to_vole(iv, sd, true, i, ellhat_bytes, NULL, qtmp, params);

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
  for (; q_idx != lambda; ++q_idx) {
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

#if defined(FAEST_SM4_DEBUG)
  fprintf(stderr,
          "[SM4_DEBUG] vole_reconstruct_sm4 ellhat=%u ellhat_bytes=%u tau=%u tau1=%u k=%u L=%u\n",
          ellhat, ellhat_bytes, tau, tau1, k, L);
#endif

  uint16_t i_delta[MAX_TAU];
  if (!decode_all_chall_3_sm4(i_delta, chall_3, params)) {
    return false;
  }
#if defined(FAEST_SM4_DEBUG)
  fprintf(stderr, "[SM4_DEBUG] verify i_delta:");
  for (unsigned int i = 0; i < params->tau; ++i) {
    fprintf(stderr, " %u", i_delta[i]);
  }
  fprintf(stderr, "\n");
#endif

  bavc_rec_t bavc_rec;
  bavc_rec.h = com;
  bavc_rec.s = malloc((L - tau) * lambda_bytes);
  assert(bavc_rec.s);

  if (!bavc_reconstruct_sm4(&bavc_rec, decom_i, i_delta, iv, params)) {
    free(bavc_rec.s);
    return false;
  }

  uint8_t* sd   = malloc((1 << k) * lambda_bytes);
  uint8_t* qtmp = malloc(MAX_DEPTH * ellhat_bytes);
  assert(sd);
  assert(qtmp);

  unsigned int q_idx = 0;
  uint8_t* sd_i      = bavc_rec.s;
  for (unsigned int i = 0; i < tau; i++) {
    const unsigned int Ni = bavc_max_node_index(i, tau1, k);

    const uint16_t i_delta_eff = i_delta[i];
    memset(sd, 0, (size_t)Ni * lambda_bytes);
    for (unsigned int j = 0; j < Ni; j++) {
      if (j == i_delta_eff) {
        continue;
      }
      const unsigned int src_idx = (j < i_delta_eff) ? j : (j - 1);
      memcpy(sd + (j ^ i_delta_eff) * lambda_bytes, sd_i + lambda_bytes * src_idx,
             lambda_bytes);
    }

    const unsigned int ki = convert_to_vole(iv, sd, true, i, ellhat_bytes, NULL, qtmp, params);
  #if defined(FAEST_SM4_DEBUG)
    if (i < 2) {
      const size_t qtmp_len = (size_t)ki * ellhat_bytes;
      const uint64_t qtmp_hash = sm4_hash64_fnv1a(qtmp, qtmp_len);
      const uint64_t c_hash = (i == 0) ? 0ULL : sm4_hash64_fnv1a(c + (i - 1) * ellhat_bytes, ellhat_bytes);
      fprintf(stderr,
          "[SM4_DEBUG] vole_reconstruct_sm4 i=%u Ni=%u ki=%u q_idx=%u qtmp_hash=0x%016llx c_hash=0x%016llx\n",
          i, Ni, ki, q_idx, (unsigned long long)qtmp_hash, (unsigned long long)c_hash);
    }
  #endif

    if (i == 0) {
      memcpy(q[q_idx], qtmp, ellhat_bytes * ki);
#if defined(FAEST_SM4_DEBUG)
      if (q_idx <= 4u && 4u < q_idx + ki) {
        const unsigned int trace_col = 4u;
        const unsigned int trace_row = 1u;
        const unsigned int trace_offset = trace_col - q_idx;
        const uint8_t* qtmp_blk = qtmp + trace_offset * ellhat_bytes;
        sm4_dbg_hex_bytes("[SM4_DEBUG] vole_trace qtmp (i==0)", qtmp_blk, ellhat_bytes);
        sm4_dbg_hex_bytes("[SM4_DEBUG] vole_trace q (i==0)", q[trace_col], ellhat_bytes);
        fprintf(stderr,
                "[SM4_DEBUG] vole_trace col=%u i=%u d=%u ki=%u row=%u qtmp_bit=%u q_bit=%u\n",
                trace_col, i, trace_offset, ki, trace_row,
                (qtmp_blk[0] >> (trace_row & 7u)) & 1u,
                (q[trace_col][0] >> (trace_row & 7u)) & 1u);
      }
#endif
      q_idx += ki;
    } else {
      for (unsigned int d = 0; d < ki; ++d, ++q_idx) {
        masked_xor_u8_array(qtmp + d * ellhat_bytes, c + (i - 1) * ellhat_bytes, q[q_idx],
          (i_delta[i] >> d) & 1u, ellhat_bytes);
#if defined(FAEST_SM4_DEBUG)
        if (q_idx == 4u) {
          const unsigned int trace_row = 1u;
          const unsigned int byte_idx = trace_row >> 3;
          const unsigned int bit_idx = trace_row & 7u;
          const uint8_t* qtmp_blk = qtmp + d * ellhat_bytes;
          const uint8_t* c_blk = c + (i - 1) * ellhat_bytes;
          const unsigned int i_delta_bit = (i_delta[i] >> d) & 1u;
          sm4_dbg_hex_bytes("[SM4_DEBUG] vole_trace qtmp", qtmp_blk, ellhat_bytes);
          sm4_dbg_hex_bytes("[SM4_DEBUG] vole_trace c", c_blk, ellhat_bytes);
          sm4_dbg_hex_bytes("[SM4_DEBUG] vole_trace q", q[q_idx], ellhat_bytes);
          fprintf(stderr,
            "[SM4_DEBUG] vole_trace col=%u i=%u d=%u ki=%u i_delta_bit=%u row=%u qtmp_bit=%u c_bit=%u q_bit=%u\n",
            q_idx, i, d, ki, i_delta_bit, trace_row,
                  (qtmp_blk[byte_idx] >> bit_idx) & 1u,
                  (c_blk[byte_idx] >> bit_idx) & 1u,
                  (q[q_idx][byte_idx] >> bit_idx) & 1u);
        }
#endif
      }
    }
    sd_i += lambda_bytes * (Ni - 1);
  }

  for (; q_idx != lambda; ++q_idx) {
    memset(q[q_idx], 0, ellhat_bytes);
  }

  free(qtmp);
  free(sd);
  free(bavc_rec.s);
  return true;
}
