/*
 *  SPDX-License-Identifier: MIT
 */

// Reference - https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
// Tested against Appendix C.1

#include "../aes.h"

#include <boost/test/unit_test.hpp>
#include <array>
#include <cstring>
#include <vector>

#include "faest_tvs.hpp"
#include "utils.hpp"

namespace {
  typedef std::array<uint8_t, 16> block_t;
} // namespace

BOOST_AUTO_TEST_SUITE(aes)

BOOST_AUTO_TEST_CASE(test_aes128) {
  constexpr uint8_t key_128[16] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  };
  constexpr uint8_t plaintext_128[16] = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  };
  constexpr block_t expected_128 = {
      0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
      0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
  };

  aes_round_keys_t ctx;
  aes128_init_round_keys(&ctx, key_128);

  block_t output_128;
  aes128_encrypt_block(&ctx, plaintext_128, output_128.data());

  BOOST_TEST(output_128 == expected_128);
}

BOOST_AUTO_TEST_CASE(test_extend_witness_aes128) {
  namespace tv = faest_tvs::faest_128s;
  auto params  = faest_get_paramset(FAEST_128S);

  std::vector<uint8_t> witness;
  witness.resize(params->l / 8);

  aes_extend_witness(witness.data(), tv::sk.data() + params->owf_input_size, tv::sk.data(), params);

  std::vector<uint8_t> expected_witness{tv::witness.begin(), tv::witness.end()};
  BOOST_TEST(expected_witness == witness);
}

BOOST_AUTO_TEST_CASE(test_invnorm) {
  BOOST_TEST(invnorm(0x00) == 0);
  BOOST_TEST(invnorm(0x01) == 1);
  BOOST_TEST(invnorm(0x02) == (1 << 3 | 1 << 2 | 1));
  BOOST_TEST(invnorm(0x80) == (1 << 3 | 1 << 2 | 1));
  BOOST_TEST(invnorm(0x88) == (1 << 2 | 1));
}

BOOST_AUTO_TEST_SUITE_END()
