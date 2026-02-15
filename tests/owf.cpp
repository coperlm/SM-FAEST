/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "owf.h"
#include "instances.hpp"
#include "utils.hpp"

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <random>
#include <vector>

BOOST_AUTO_TEST_SUITE(owf)

namespace {
  void test_owf_basic() {
    // Basic test for owf_128 function
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t input[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t output[16];
    
    owf_128(key, input, output);
    
    // Just check that output is not all zeros (basic sanity check)
    bool all_zero = true;
    for (int i = 0; i < 16; i++) {
      if (output[i] != 0) {
        all_zero = false;
        break;
      }
    }
    BOOST_TEST(!all_zero);
  }
} // namespace

BOOST_AUTO_TEST_CASE(owf_basic_test) {
  test_owf_basic();
}

BOOST_AUTO_TEST_SUITE_END()
