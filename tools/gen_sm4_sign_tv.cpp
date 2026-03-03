#include "faest_sm4_128s.h"
#include "faest_em_sm4_128s.h"
#include "tests/faest_tvs.hpp"

#include <cstdio>
#include <vector>

static void print_sig(const char* name, const uint8_t* sig, size_t len) {
  std::printf("%s\n", name);
  for (size_t i = 0; i < len; ++i) {
    std::printf("0x%02x,%s", sig[i], ((i + 1) % 16 == 0) ? "\n" : " ");
  }
  if (len % 16 != 0) {
    std::printf("\n");
  }
}

int main() {
  using faest_tvs::message;
  using faest_tvs::random_seed;

  {
    namespace tv = faest_tvs::faest_sm4_128s;
    std::vector<uint8_t> sig(FAEST_SM4_128S_SIG_SIZE);
    size_t sig_len = sig.size();
    int rc = faest_sm4_128s_sign_with_randomness(tv::sk.data(), message.data(), message.size(),
                                                 random_seed.data(), random_seed.size(), sig.data(), &sig_len);
    if (rc != 0 || sig_len != sig.size()) {
      std::fprintf(stderr, "faest_sm4_128s_sign_with_randomness failed rc=%d len=%zu\n", rc, sig_len);
      return 1;
    }
    print_sig("SM4_SIG", sig.data(), sig.size());
  }

  {
    namespace tv = faest_tvs::faest_em_sm4_128s;
    std::vector<uint8_t> sig(FAEST_EM_SM4_128S_SIG_SIZE);
    size_t sig_len = sig.size();
    int rc = faest_em_sm4_128s_sign_with_randomness(tv::sk.data(), message.data(), message.size(),
                                                    random_seed.data(), random_seed.size(), sig.data(), &sig_len);
    if (rc != 0 || sig_len != sig.size()) {
      std::fprintf(stderr, "faest_em_sm4_128s_sign_with_randomness failed rc=%d len=%zu\n", rc, sig_len);
      return 1;
    }
    print_sig("EM_SM4_SIG", sig.data(), sig.size());
  }

  return 0;
}
