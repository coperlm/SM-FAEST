/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "bavc.h"
#include "random_oracle.h"
#include "compat.h"
#include "aes.h"
#include "sm4.h"
#include "instances.h"
#include "universal_hashing.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

#define NODE(nodes, node, lambda_bytes) (&nodes[(node) * (lambda_bytes)])


static void expand_seeds(uint8_t* nodes, const uint8_t* iv, const faest_paramset_t* params) {
  const unsigned int lambda_bytes = params->lambda / 8;

  for (unsigned int alpha = 0; alpha < params->L - 1; ++alpha) {
    // the nodes are located in memory consecutively
    if (faest_is_sm4(params)) {
      sm4_prg_2_lambda(NODE(nodes, alpha, lambda_bytes), iv, alpha,
                       NODE(nodes, 2 * alpha + 1, lambda_bytes), params->lambda);
    } else {
      prg_2_lambda(NODE(nodes, alpha, lambda_bytes), iv, alpha,
                   NODE(nodes, 2 * alpha + 1, lambda_bytes), params->lambda);
    }
  }
}

static uint8_t* generate_seeds(const uint8_t* root_seed, const uint8_t* iv,
                               const faest_paramset_t* params) {
  unsigned int lambda_bytes = params->lambda / 8;
  uint8_t* nodes            = calloc(2 * params->L - 1, lambda_bytes);
  if (!nodes) {
    return NULL;
  }

  memcpy(NODE(nodes, 0, lambda_bytes), root_seed, lambda_bytes);
  expand_seeds(nodes, iv, params);

  return nodes;
}

// FAEST.LeafCommit
static void faest_leaf_commit(uint8_t* sd, uint8_t* com, const uint8_t* key, const uint8_t* iv,
                              uint32_t tweak, const uint8_t* uhash, const faest_paramset_t* params) {
  const unsigned int lambda = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;

  uint8_t buffer[MAX_LAMBDA_BYTES * 4];
  if (faest_is_sm4(params)) {
    sm4_prg_4_lambda(key, iv, tweak, buffer, lambda);
  } else {
    prg_4_lambda(key, iv, tweak, buffer, lambda);
  }
  leaf_hash(com, uhash, buffer, lambda);
  memcpy(sd, buffer, lambda_bytes);
}

// FAEST-EM.LeafCommit
static void faest_em_leaf_commit(uint8_t* sd, uint8_t* com, const uint8_t* key, const uint8_t* iv,
                                 uint32_t tweak, const faest_paramset_t* params) {
  const unsigned int lambda = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;

  memcpy(sd, key, lambda_bytes);
  if (faest_is_sm4(params)) {
    sm4_prg_2_lambda(key, iv, tweak, com, lambda);
  } else {
    prg_2_lambda(key, iv, tweak, com, lambda);
  }
}

#if defined(FAEST_TESTS)
void leaf_commit(uint8_t* sd, uint8_t* com, const uint8_t* key, const uint8_t* iv, uint32_t tweak,
                 const uint8_t* uhash, const faest_paramset_t* params) {
  if (faest_is_em(params)) {
    faest_em_leaf_commit(sd, com, key, iv, tweak, params);
  } else {
    faest_leaf_commit(sd, com, key, iv, tweak, uhash, params);
  }
}
#endif

// BAVC.PosInTree
ATTR_PURE static inline unsigned int pos_in_tree(unsigned int i, unsigned int j,
                                                 const faest_paramset_t* params) {
  const unsigned int tmp = 1 << (params->k - 1);
  if (j < tmp) {
    return params->L - 1 + params->tau * j + i;
  }
  // mod 2^(k-1) is the same as & 2^(k-1)-1
  const unsigned int mask = tmp - 1;
  return params->L - 1 + params->tau * tmp + params->tau1 * (j & mask) + i;
}

// BAVC.Commit for FAEST
static bool bavc_commit_faest(bavc_t* bavc, const uint8_t* root_key, const uint8_t* iv,
                              const faest_paramset_t* params) {
  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int com_size     = lambda_bytes * 3; // size of com_ij

  H0_context_t uhash_ctx;
  H0_init(&uhash_ctx, lambda);
  H0_update(&uhash_ctx, iv, IV_SIZE);
  H0_final_for_squeeze(&uhash_ctx);

  H1_context_t h1_com_ctx;
  H1_init(&h1_com_ctx, lambda);

  // Generating the tree (k)
  uint8_t* nodes = generate_seeds(root_key, iv, params);
  if (!nodes) {
    H0_clear(&uhash_ctx);
    return false;
  }

  // Initialzing stuff
  bavc->h   = malloc(lambda_bytes * 2);
  bavc->com = malloc(L * com_size);
  bavc->sd  = malloc(L * lambda_bytes);
  if (!bavc->h || !bavc->com || !bavc->sd) {
    free(nodes);
    free(bavc->h);
    free(bavc->com);
    free(bavc->sd);
    bavc->h = NULL;
    bavc->com = NULL;
    bavc->sd = NULL;
    H0_clear(&uhash_ctx);
    return false;
  }

  // Step: 1..3
  bavc->k = NODE(nodes, 0, lambda_bytes);

  // Step: 4..5
  // compute commitments for remaining instances
  for (unsigned int i = 0, offset = 0; i < params->tau; ++i) {
    uint8_t uhash[MAX_LAMBDA_BYTES * 3];
    H0_squeeze(&uhash_ctx, uhash, 3 * lambda_bytes);

    H1_context_t h1_ctx;
    H1_init(&h1_ctx, lambda);

    const unsigned int N_i = bavc_max_node_index(i, params->tau1, params->k);
    for (unsigned int j = 0; j < N_i; ++j, ++offset) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      faest_leaf_commit(bavc->sd + offset * lambda_bytes, bavc->com + offset * com_size,
                        NODE(nodes, alpha, lambda_bytes), iv, i + L - 1, uhash, params);
      H1_update(&h1_ctx, bavc->com + offset * com_size, com_size);
    }

    uint8_t hi[MAX_LAMBDA_BYTES * 2];
    // Step 11
    H1_final(&h1_ctx, hi, lambda_bytes * 2);
    // Step 12
    H1_update(&h1_com_ctx, hi, lambda_bytes * 2);
  }
  H0_clear(&uhash_ctx);

  // Step 12
  H1_final(&h1_com_ctx, bavc->h, lambda_bytes * 2);
  return true;
}

// BAVC.Commit for FAEST-EM
static bool bavc_commit_faest_em(bavc_t* bavc, const uint8_t* rootKey, const uint8_t* iv,
                                 const faest_paramset_t* params) {
  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int com_size     = lambda_bytes * 2; // size of com_ij

  H1_context_t h1_com_ctx;
  H1_init(&h1_com_ctx, lambda);

  // Generating the tree
  uint8_t* nodes = generate_seeds(rootKey, iv, params);
  if (!nodes) {
    return false;
  }

  // Initialzing stuff
  bavc->h   = malloc(lambda_bytes * 2);
  bavc->com = malloc(L * com_size);
  bavc->sd  = malloc(L * lambda_bytes);
  if (!bavc->h || !bavc->com || !bavc->sd) {
    free(nodes);
    free(bavc->h);
    free(bavc->com);
    free(bavc->sd);
    bavc->h = NULL;
    bavc->com = NULL;
    bavc->sd = NULL;
    return false;
  }

  // Step: 1..3
  bavc->k = NODE(nodes, 0, lambda_bytes);

  // Step: 4..5
  // compute commitments for remaining instances
  for (unsigned int i = 0, offset = 0; i < params->tau; ++i) {
    H1_context_t h1_ctx;
    H1_init(&h1_ctx, lambda);

    const unsigned int N_i = bavc_max_node_index(i, params->tau1, params->k);
    for (unsigned int j = 0; j < N_i; ++j, ++offset) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      faest_em_leaf_commit(bavc->sd + offset * lambda_bytes, bavc->com + offset * com_size,
                           NODE(nodes, alpha, lambda_bytes), iv, i + L - 1, params);
      H1_update(&h1_ctx, bavc->com + offset * com_size, com_size);
    }

    uint8_t hi[MAX_LAMBDA_BYTES * 2];
    // Step 11
    H1_final(&h1_ctx, hi, lambda_bytes * 2);
    // Step 12
    H1_update(&h1_com_ctx, hi, lambda_bytes * 2);
  }

  // Step 12
  H1_final(&h1_com_ctx, bavc->h, lambda_bytes * 2);
  return true;
}


// BAVC.Commit for FAEST-SM4 — SM3 variant of bavc_commit_faest
// Identical logic, H0/H1 replaced with SM_H0/SM_H1 (SM3-XOF).
static bool bavc_commit_faest_sm4(bavc_t* bavc, const uint8_t* root_key, const uint8_t* iv,
                                   const faest_paramset_t* params) {
  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int com_size     = lambda_bytes * 3; // size of com_ij

  SM_H0_context_t uhash_ctx;
  SM_H0_init(&uhash_ctx, lambda);
  SM_H0_update(&uhash_ctx, iv, IV_SIZE);
  SM_H0_final_for_squeeze(&uhash_ctx);

  SM_H1_context_t h1_com_ctx;
  SM_H1_init(&h1_com_ctx, lambda);

  // Generating the tree (k)
  uint8_t* nodes = generate_seeds(root_key, iv, params);
  if (!nodes) {
    SM_H0_clear(&uhash_ctx);
    return false;
  }

  // Initialzing stuff
  bavc->h   = malloc(lambda_bytes * 2);
  bavc->com = malloc(L * com_size);
  bavc->sd  = malloc(L * lambda_bytes);
  if (!bavc->h || !bavc->com || !bavc->sd) {
    free(nodes);
    free(bavc->h);
    free(bavc->com);
    free(bavc->sd);
    bavc->h = NULL;
    bavc->com = NULL;
    bavc->sd = NULL;
    SM_H0_clear(&uhash_ctx);
    return false;
  }

  // Step: 1..3
  bavc->k = NODE(nodes, 0, lambda_bytes);

  // Step: 4..5
  // compute commitments for remaining instances
  for (unsigned int i = 0, offset = 0; i < params->tau; ++i) {
    uint8_t uhash[MAX_LAMBDA_BYTES * 3];
    SM_H0_squeeze(&uhash_ctx, uhash, 3 * lambda_bytes);

    SM_H1_context_t h1_ctx;
    SM_H1_init(&h1_ctx, lambda);

    const unsigned int N_i = bavc_max_node_index(i, params->tau1, params->k);
    for (unsigned int j = 0; j < N_i; ++j, ++offset) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      faest_leaf_commit(bavc->sd + offset * lambda_bytes, bavc->com + offset * com_size,
                        NODE(nodes, alpha, lambda_bytes), iv, i + L - 1, uhash, params);
      SM_H1_update(&h1_ctx, bavc->com + offset * com_size, com_size);
    }

    uint8_t hi[MAX_LAMBDA_BYTES * 2];
    // Step 11
    SM_H1_final(&h1_ctx, hi, lambda_bytes * 2);
    // Step 12
    SM_H1_update(&h1_com_ctx, hi, lambda_bytes * 2);
  }
  SM_H0_clear(&uhash_ctx);

  // Step 12
  SM_H1_final(&h1_com_ctx, bavc->h, lambda_bytes * 2);
  return true;
}

// BAVC.Commit for FAEST-EM-SM4 — SM3 variant of bavc_commit_faest_em
static bool bavc_commit_faest_em_sm4(bavc_t* bavc, const uint8_t* rootKey, const uint8_t* iv,
                                      const faest_paramset_t* params) {
  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int com_size     = lambda_bytes * 2; // size of com_ij

  SM_H1_context_t h1_com_ctx;
  SM_H1_init(&h1_com_ctx, lambda);

  // Generating the tree
  uint8_t* nodes = generate_seeds(rootKey, iv, params);
  if (!nodes) {
    return false;
  }

  // Initialzing stuff
  bavc->h   = malloc(lambda_bytes * 2);
  bavc->com = malloc(L * com_size);
  bavc->sd  = malloc(L * lambda_bytes);
  if (!bavc->h || !bavc->com || !bavc->sd) {
    free(nodes);
    free(bavc->h);
    free(bavc->com);
    free(bavc->sd);
    bavc->h = NULL;
    bavc->com = NULL;
    bavc->sd = NULL;
    return false;
  }

  // Step: 1..3
  bavc->k = NODE(nodes, 0, lambda_bytes);

  // Step: 4..5
  // compute commitments for remaining instances
  for (unsigned int i = 0, offset = 0; i < params->tau; ++i) {
    SM_H1_context_t h1_ctx;
    SM_H1_init(&h1_ctx, lambda);

    const unsigned int N_i = bavc_max_node_index(i, params->tau1, params->k);
    for (unsigned int j = 0; j < N_i; ++j, ++offset) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      faest_em_leaf_commit(bavc->sd + offset * lambda_bytes, bavc->com + offset * com_size,
                           NODE(nodes, alpha, lambda_bytes), iv, i + L - 1, params);
      SM_H1_update(&h1_ctx, bavc->com + offset * com_size, com_size);
    }

    uint8_t hi[MAX_LAMBDA_BYTES * 2];
    // Step 11
    SM_H1_final(&h1_ctx, hi, lambda_bytes * 2);
    // Step 12
    SM_H1_update(&h1_com_ctx, hi, lambda_bytes * 2);
  }

  // Step 12
  SM_H1_final(&h1_com_ctx, bavc->h, lambda_bytes * 2);
  return true;
}

bool bavc_commit(bavc_t* bavc, const uint8_t* root_key, const uint8_t* iv,
                 const faest_paramset_t* params) {
  bavc->h = NULL;
  bavc->k = NULL;
  bavc->com = NULL;
  bavc->sd = NULL;
  if (faest_is_em(params)) {
    return faest_is_sm4(params)
               ? bavc_commit_faest_em_sm4(bavc, root_key, iv, params)
               : bavc_commit_faest_em(bavc, root_key, iv, params);
  } else {
    return faest_is_sm4(params)
               ? bavc_commit_faest_sm4(bavc, root_key, iv, params)
               : bavc_commit_faest(bavc, root_key, iv, params);
  }
}

bool bavc_open(uint8_t* decom_i, const bavc_t* vc, const uint16_t* i_delta,
               const faest_paramset_t* params) {
  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int k            = params->k;
  const unsigned int tau          = params->tau;
  const unsigned int tau_1        = params->tau1;
  const unsigned int com_size     = faest_is_em(params) ? (2 * lambda_bytes) : (3 * lambda_bytes);

  uint8_t* decom_i_end = decom_i + com_size * tau + params->T_open * lambda_bytes;

  // Step 5
  uint8_t* s = calloc((2 * L - 1 + 7) / 8, 1);
  if (!s) {
    return false;
  }
  // Step 6
  unsigned int nh = 0;

  // Step 7..15: mark leaves and propagate upward
  for (unsigned int i = 0; i < tau; ++i) {
    unsigned int alpha = pos_in_tree(i, i_delta[i], params);
    ptr_set_bit(s, alpha, 1);
    ++nh;

    while (alpha > 0 && ptr_get_bit(s, (alpha - 1) / 2) == 0) {
      alpha = (alpha - 1) / 2;
      ptr_set_bit(s, alpha, 1);
      ++nh;
    }
  }

  // Step 16..17
  if (nh - 2 * tau + 1 > params->T_open) {
    free(s);
    return false;
  }

  // Step 3
  const uint8_t* com = vc->com;
  for (unsigned int i = 0; i < tau; ++i) {
    decom_i = faest_mempcpy(decom_i, com + i_delta[i] * com_size, com_size);
    com += bavc_max_node_index(i, tau_1, k) * com_size;
  }

  // Step 19..25
  for (int i = L - 2; i >= 0; --i) {
    ptr_set_bit(s, i, ptr_get_bit(s, 2 * i + 1) | ptr_get_bit(s, 2 * i + 2));
    if ((ptr_get_bit(s, 2 * i + 1) ^ ptr_get_bit(s, 2 * i + 2)) == 1) {
      const unsigned int alpha = 2 * i + 1 + ptr_get_bit(s, 2 * i + 1);
      decom_i = faest_mempcpy(decom_i, NODE(vc->k, alpha, lambda_bytes), lambda_bytes);
    }
  }

  memset(decom_i, 0, decom_i_end - decom_i);

  free(s);
  return true;
}

bool bavc_open_sm4(uint8_t* decom_i, const bavc_t* vc, const uint16_t* i_delta,
                   const faest_paramset_t* params) {
  return bavc_open(decom_i, vc, i_delta, params);
}

static bool reconstruct_keys(uint8_t* s, uint8_t* keys, const uint8_t* decom_i,
                             const uint16_t* i_delta, const uint8_t* iv,
                             const faest_paramset_t* params) {
  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int tau          = params->tau;

  const uint8_t* nodes = decom_i + (faest_is_em(params) ? 2 : 3) * tau * lambda_bytes;
  const uint8_t* end   = nodes + params->T_open * lambda_bytes;

  // Step 7..10: mark leaves
  for (unsigned int i = 0; i < tau; ++i) {
    unsigned int alpha = pos_in_tree(i, i_delta[i], params);
    ptr_set_bit(s, alpha, 1);
  }

  // Step 12.12 (propagate upward)
  for (int i = L - 2; i >= 0; --i) {
    ptr_set_bit(s, i, ptr_get_bit(s, 2 * i + 1) | ptr_get_bit(s, 2 * i + 2));
    if ((ptr_get_bit(s, 2 * i + 1) ^ ptr_get_bit(s, 2 * i + 2)) == 1) {
      if (nodes == end) {
        return false;
      }

      const unsigned int alpha = 2 * i + 1 + ptr_get_bit(s, 2 * i + 1);
      memcpy(keys + alpha * lambda_bytes, nodes, lambda_bytes);
      nodes += lambda_bytes;
    }
  }

  for (; nodes != end; ++nodes) {
    if (*nodes) {
      return false;
    }
  }

  for (unsigned int i = 0; i != L - 1; ++i) {
    /* Only expand internal nodes if their subtree contains no known leaves (s bit zero).
     * Original simple logic works for both AES and SM4. */
    if (!ptr_get_bit(s, i)) {
      if (faest_is_sm4(params)) {
        sm4_prg_2_lambda(keys + i * lambda_bytes, iv, i, keys + (2 * i + 1) * lambda_bytes,
                         lambda);
      } else {
        prg_2_lambda(keys + i * lambda_bytes, iv, i, keys + (2 * i + 1) * lambda_bytes,
                     lambda);
      }
    }
  }

  return true;
}

static bool bavc_reconstruct_faest(bavc_rec_t* bavc_rec, const uint8_t* decom_i,
                                   const uint16_t* i_delta, const uint8_t* iv,
                                   const faest_paramset_t* params) {
  // Initializing
  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int k            = params->k;
  const unsigned int tau          = params->tau;
  const unsigned int tau_1        = params->tau1;
  const unsigned int com_size     = lambda_bytes * 3; // size of com_ij

  // Step 6
  uint8_t* s = calloc((2 * L - 1 + 7) / 8, 1);
  if (!s) {
    return false;
  }
  uint8_t* keys = calloc(2 * params->L - 1, lambda_bytes);
  if (!keys) {
    free(s);
    return false;
  }

  if (!reconstruct_keys(s, keys, decom_i, i_delta, iv, params)) {
    free(keys);
    free(s);
    return false;
  }
  /* debug: show reconstructed left-child key */

  H0_context_t uhash_ctx;
  H0_init(&uhash_ctx, lambda);
  H0_update(&uhash_ctx, iv, IV_SIZE);
  H0_final_for_squeeze(&uhash_ctx);

  H1_context_t h1_com_ctx;
  H1_init(&h1_com_ctx, lambda);

  for (unsigned int i = 0, offset = 0; i != tau; ++i) {
    uint8_t uhash[MAX_LAMBDA_BYTES * 3];
    H0_squeeze(&uhash_ctx, uhash, com_size);

    H1_context_t h1_ctx;
    H1_init(&h1_ctx, lambda);

    const unsigned int N_i = bavc_max_node_index(i, tau_1, k);
    for (unsigned int j = 0; j != N_i; ++j) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      if (ptr_get_bit(s, alpha)) {
        H1_update(&h1_ctx, decom_i + i * com_size, com_size);
      } else {
        uint8_t com[3 * MAX_LAMBDA_BYTES];
        faest_leaf_commit(bavc_rec->s + offset * lambda_bytes, com, keys + alpha * lambda_bytes, iv,
                          i + L - 1, uhash, params);
        ++offset;
        H1_update(&h1_ctx, com, com_size);
      }
    }

    uint8_t hi[MAX_LAMBDA_BYTES * 2];
    H1_final(&h1_ctx, hi, lambda_bytes * 2);
    H1_update(&h1_com_ctx, hi, lambda_bytes * 2);
  }
  H0_clear(&uhash_ctx);

  H1_final(&h1_com_ctx, bavc_rec->h, lambda_bytes * 2);

  free(keys);
  free(s);
  return true;
}

static bool bavc_reconstruct_faest_em(bavc_rec_t* bavc_rec, const uint8_t* decom_i,
                                      const uint16_t* i_delta, const uint8_t* iv,
                                      const faest_paramset_t* params) {
  // Initializing
  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int k            = params->k;
  const unsigned int tau          = params->tau;
  const unsigned int tau_1        = params->tau1;
  const unsigned int com_size     = lambda_bytes * 2; // size of com_ij

  // Step 6
  uint8_t* s = calloc((2 * L - 1 + 7) / 8, 1);
  if (!s) {
    return false;
  }
  uint8_t* keys = calloc(2 * params->L - 1, lambda_bytes);
  if (!keys) {
    free(s);
    return false;
  }

  // Step 7..10
  if (!reconstruct_keys(s, keys, decom_i, i_delta, iv, params)) {
    free(keys);
    free(s);
    return false;
  }

  H1_context_t h1_com_ctx;
  H1_init(&h1_com_ctx, lambda);

  for (unsigned int i = 0, offset = 0; i != tau; ++i) {
    H1_context_t h1_ctx;
    H1_init(&h1_ctx, lambda);

    const unsigned int N_i = bavc_max_node_index(i, tau_1, k);
    for (unsigned int j = 0; j != N_i; ++j) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      if (ptr_get_bit(s, alpha)) {
        H1_update(&h1_ctx, decom_i + i * com_size, com_size);
      } else {
        uint8_t com[2 * MAX_LAMBDA_BYTES];
        faest_em_leaf_commit(bavc_rec->s + offset * lambda_bytes, com, keys + alpha * lambda_bytes,
                             iv, i + L - 1, params);
        ++offset;
        H1_update(&h1_ctx, com, com_size);
      }
    }

    uint8_t hi[MAX_LAMBDA_BYTES * 2];
    H1_final(&h1_ctx, hi, lambda_bytes * 2);
    H1_update(&h1_com_ctx, hi, lambda_bytes * 2);
  }

  H1_final(&h1_com_ctx, bavc_rec->h, lambda_bytes * 2);

  free(keys);
  free(s);
  return true;
}


// BAVC.Reconstruct for FAEST-SM4 — SM3 variant of bavc_reconstruct_faest
static bool bavc_reconstruct_faest_sm4(bavc_rec_t* bavc_rec, const uint8_t* decom_i,
                                        const uint16_t* i_delta, const uint8_t* iv,
                                        const faest_paramset_t* params) {
  // Initializing
  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int k            = params->k;
  const unsigned int tau          = params->tau;
  const unsigned int tau_1        = params->tau1;
  const unsigned int com_size     = lambda_bytes * 3; // size of com_ij

  // Step 6
  uint8_t* s = calloc((2 * L - 1 + 7) / 8, 1);
  if (!s) {
    return false;
  }
  uint8_t* keys = calloc(2 * params->L - 1, lambda_bytes);
  if (!keys) {
    free(s);
    return false;
  }

  if (!reconstruct_keys(s, keys, decom_i, i_delta, iv, params)) {
    free(keys);
    free(s);
    return false;
  }

  SM_H0_context_t uhash_ctx;
  SM_H0_init(&uhash_ctx, lambda);
  SM_H0_update(&uhash_ctx, iv, IV_SIZE);
  SM_H0_final_for_squeeze(&uhash_ctx);

  SM_H1_context_t h1_com_ctx;
  SM_H1_init(&h1_com_ctx, lambda);

  for (unsigned int i = 0, offset = 0; i != tau; ++i) {
    uint8_t uhash[MAX_LAMBDA_BYTES * 3];
    SM_H0_squeeze(&uhash_ctx, uhash, com_size);

    SM_H1_context_t h1_ctx;
    SM_H1_init(&h1_ctx, lambda);

    const unsigned int N_i = bavc_max_node_index(i, tau_1, k);
    for (unsigned int j = 0; j != N_i; ++j) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      if (ptr_get_bit(s, alpha)) {
        SM_H1_update(&h1_ctx, decom_i + i * com_size, com_size);
      } else {
        uint8_t com[3 * MAX_LAMBDA_BYTES];
        faest_leaf_commit(bavc_rec->s + offset * lambda_bytes, com, keys + alpha * lambda_bytes, iv,
                          i + L - 1, uhash, params);
        ++offset;
        SM_H1_update(&h1_ctx, com, com_size);
      }
    }

    uint8_t hi[MAX_LAMBDA_BYTES * 2];
    SM_H1_final(&h1_ctx, hi, lambda_bytes * 2);
    SM_H1_update(&h1_com_ctx, hi, lambda_bytes * 2);
  }
  SM_H0_clear(&uhash_ctx);

  SM_H1_final(&h1_com_ctx, bavc_rec->h, lambda_bytes * 2);

  free(keys);
  free(s);
  return true;
}

// BAVC.Reconstruct for FAEST-EM-SM4 — SM3 variant of bavc_reconstruct_faest_em
static bool bavc_reconstruct_faest_em_sm4(bavc_rec_t* bavc_rec, const uint8_t* decom_i,
                                           const uint16_t* i_delta, const uint8_t* iv,
                                           const faest_paramset_t* params) {
  // Initializing
  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int k            = params->k;
  const unsigned int tau          = params->tau;
  const unsigned int tau_1        = params->tau1;
  const unsigned int com_size     = lambda_bytes * 2; // size of com_ij

  // Step 6
  uint8_t* s = calloc((2 * L - 1 + 7) / 8, 1);
  if (!s) {
    return false;
  }
  uint8_t* keys = calloc(2 * params->L - 1, lambda_bytes);
  if (!keys) {
    free(s);
    return false;
  }

  // Step 7..10
  if (!reconstruct_keys(s, keys, decom_i, i_delta, iv, params)) {
    free(keys);
    free(s);
    return false;
  }

  SM_H1_context_t h1_com_ctx;
  SM_H1_init(&h1_com_ctx, lambda);

  for (unsigned int i = 0, offset = 0; i != tau; ++i) {
    SM_H1_context_t h1_ctx;
    SM_H1_init(&h1_ctx, lambda);

    const unsigned int N_i = bavc_max_node_index(i, tau_1, k);
    for (unsigned int j = 0; j != N_i; ++j) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      if (ptr_get_bit(s, alpha)) {
        SM_H1_update(&h1_ctx, decom_i + i * com_size, com_size);
      } else {
        uint8_t com[2 * MAX_LAMBDA_BYTES];
        faest_em_leaf_commit(bavc_rec->s + offset * lambda_bytes, com, keys + alpha * lambda_bytes,
                             iv, i + L - 1, params);
        ++offset;
        SM_H1_update(&h1_ctx, com, com_size);
      }
    }

    uint8_t hi[MAX_LAMBDA_BYTES * 2];
    SM_H1_final(&h1_ctx, hi, lambda_bytes * 2);
    SM_H1_update(&h1_com_ctx, hi, lambda_bytes * 2);
  }

  SM_H1_final(&h1_com_ctx, bavc_rec->h, lambda_bytes * 2);

  free(keys);
  free(s);
  return true;
}

bool bavc_reconstruct(bavc_rec_t* bavc_rec, const uint8_t* decom_i, const uint16_t* i_delta,
                      const uint8_t* iv, const faest_paramset_t* params) {
  if (faest_is_em(params)) {
    return faest_is_sm4(params)
               ? bavc_reconstruct_faest_em_sm4(bavc_rec, decom_i, i_delta, iv, params)
               : bavc_reconstruct_faest_em(bavc_rec, decom_i, i_delta, iv, params);
  }
  return faest_is_sm4(params)
             ? bavc_reconstruct_faest_sm4(bavc_rec, decom_i, i_delta, iv, params)
             : bavc_reconstruct_faest(bavc_rec, decom_i, i_delta, iv, params);
}

bool bavc_reconstruct_sm4(bavc_rec_t* bavc_rec, const uint8_t* decom_i, const uint16_t* i_delta,
                          const uint8_t* iv, const faest_paramset_t* params) {
  const bool ok = bavc_reconstruct(bavc_rec, decom_i, i_delta, iv, params);
  return ok;
}

void bavc_clear(bavc_t* com) {
  free(com->sd);
  free(com->com);
  free(com->h);
  free(com->k);
}
