/*
 *  SPDX-License-Identifier: MIT
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include "instances.h"
#include "parameters.h"

const char* faest_get_param_name(faest_paramid_t paramid) {
  switch (paramid) {
  case PARAMETER_SET_INVALID:
    return "PARAMETER_SET_INVALID";
  case FAEST_128S:
    return "FAEST_128S";
  default:
    return "PARAMETER_SET_MAX_INDEX";
  }
}

#define CALC_TAU1(name) ((name##_LAMBDA - name##_W_GRIND) % name##_TAU)
#define CALC_TAU0(name) (name##_TAU - CALC_TAU1(name))
#define CALC_L(name)                                                                               \
  (CALC_TAU1(name) * (1 << CALC_K(name)) + CALC_TAU0(name) * (1 << (CALC_K(name) - 1)))
#define CALC_K(name) (((name##_LAMBDA - name##_W_GRIND) / (name##_TAU)) + 1)

#define PARAMS(name)                                                                               \
  {                                                                                                \
      name##_LAMBDA,                                                                               \
      name##_TAU,                                                                                  \
      name##_W_GRIND,                                                                              \
      name##_T_OPEN,                                                                               \
      name##_ELL,                                                                                  \
      CALC_K(name),                                                                                \
      CALC_TAU0(name),                                                                             \
      CALC_TAU1(name),                                                                             \
      CALC_L(name),                                                                                \
      name##_Nst,                                                                                  \
      name##_Ske,                                                                                  \
      name##_R,                                                                                    \
      name##_Senc,                                                                                 \
      name##_Lke,                                                                                  \
      name##_Lenc,                                                                                 \
      name##_SIG_SIZE,                                                                             \
      name##_OWF_INPUT_SIZE,                                                                       \
      name##_OWF_OUTPUT_SIZE,                                                                      \
  }

#define FAEST_128S_PARAMS PARAMS(FAEST_128S)

#define CASE_PARAM(P)                                                                              \
  case P: {                                                                                        \
    static const faest_paramset_t params = P##_PARAMS;                                             \
    return &params;                                                                                \
  }

const faest_paramset_t* faest_get_paramset(faest_paramid_t paramid) {
  switch (paramid) {
    CASE_PARAM(FAEST_128S)
  default:
    return NULL;
  }
}
