/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

extern "C" {
#include "hash_sm3.h"
}

#include <array>
#include <cstring>
#include <boost/test/unit_test.hpp>

namespace {

std::array<uint8_t, 32> sm3_digest(const uint8_t* data, size_t len) {
  SM3_CTX ctx;
  std::array<uint8_t, 32> digest{};
  sm3_init(&ctx);
  sm3_update(&ctx, data, len);
  sm3_finish(&ctx, digest.data());
  return digest;
}

std::array<uint8_t, 64> reference_xof(uint8_t domain, const uint8_t* data, size_t len) {
  const uint8_t prefix[2] = {SM_SUITE_BYTE, domain};
  SM3_CTX extract;
  std::array<uint8_t, 32> base{};
  std::array<uint8_t, 64> output{};

  sm3_init(&extract);
  sm3_update(&extract, prefix, sizeof(prefix));
  sm3_update(&extract, data, len);
  sm3_finish(&extract, base.data());

  for (uint32_t counter = 1; counter <= 2; ++counter) {
    uint8_t counter_bytes[4] = {
        static_cast<uint8_t>(counter >> 24), static_cast<uint8_t>(counter >> 16),
        static_cast<uint8_t>(counter >> 8), static_cast<uint8_t>(counter)};
    SM3_CTX expand;
    sm3_init(&expand);
    sm3_update(&expand, base.data(), base.size());
    sm3_update(&expand, counter_bytes, sizeof(counter_bytes));
    sm3_finish(&expand, output.data() + (counter - 1) * 32);
  }
  return output;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(hash_sm3)

BOOST_AUTO_TEST_CASE(sm3_standard_vector) {
  constexpr std::array<uint8_t, 3> message = {'a', 'b', 'c'};
  constexpr std::array<uint8_t, 32> expected = {
      0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
      0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
      0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
      0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0,
  };
  const auto digest = sm3_digest(message.data(), message.size());
  BOOST_TEST(digest == expected);
}

BOOST_AUTO_TEST_CASE(sm3_xof_matches_reference_and_streaming) {
  constexpr std::array<uint8_t, 3> message = {'a', 'b', 'c'};
  const auto expected = reference_xof(0x00, message.data(), message.size());
  std::array<uint8_t, 64> one_shot{};
  std::array<uint8_t, 64> streaming{};
  sm3_xof_one_shot(0x00, message.data(), message.size(), one_shot.data(), one_shot.size());

  sm3_xof_ctx_t ctx;
  sm3_xof_init_with_prefix(&ctx, 0x00);
  sm3_xof_update(&ctx, message.data(), message.size());
  sm3_xof_finalize(&ctx);
  sm3_xof_squeeze(&ctx, streaming.data(), 7);
  sm3_xof_squeeze(&ctx, streaming.data() + 7, streaming.size() - 7);
  sm3_xof_clear(&ctx);

  BOOST_TEST(one_shot == expected);
  BOOST_TEST(streaming == expected);
}

BOOST_AUTO_TEST_SUITE_END()