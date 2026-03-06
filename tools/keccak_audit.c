/*
 * keccak_audit.c — SHAKE Contamination Audit for SM4 path
 *
 * Measures the number of Keccak permutation calls during:
 *   faest_sm4_128s keygen / sign / verify
 *
 * Expected result: keccak_call_count == 0 throughout, proving that the
 * SM4 code path is completely free of SHAKE/Keccak usage.
 *
 * Build (from workspace root, after rebuilding with ninja):
 *   gcc -std=c11 -O0 -I build_bench_nn -I . -I GmSSL_Symmetric/include \
 *       tools/keccak_audit.c -L build_bench_nn -lfaest \
 *       -Wl,-rpath,build_bench_nn -o build_bench_nn/keccak_audit
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "build_bench_nn/faest_sm4_128s.h"

/* The counter is a plain non-static global exported from libfaest */
extern uint64_t keccak_call_count;

static void reset_counter(void) {
    keccak_call_count = 0;
}

static void report(const char *label) {
    printf("  [%s]  keccak_call_count = %llu  %s\n",
           label,
           (unsigned long long)keccak_call_count,
           keccak_call_count == 0 ? "\033[32mPASS (no Keccak)\033[0m"
                                   : "\033[31mFAIL (Keccak leaked!)\033[0m");
}

int main(void) {
    printf("=== SHAKE Contamination Audit: faest_sm4_128s ===\n\n");

    uint8_t pk[FAEST_SM4_128S_PUBLIC_KEY_SIZE];
    uint8_t sk[FAEST_SM4_128S_PRIVATE_KEY_SIZE];
    uint8_t sig[FAEST_SM4_128S_SIGNATURE_SIZE];
    size_t  sig_len = sizeof(sig);
    const uint8_t msg[] = "audit test message";
    int overall_pass = 1;

    /* ---- keygen ---- */
    reset_counter();
    int ret = faest_sm4_128s_keygen(pk, sk);
    assert(ret == 0 && "keygen failed");
    report("keygen ");
    if (keccak_call_count != 0) overall_pass = 0;

    /* ---- sign ---- */
    reset_counter();
    ret = faest_sm4_128s_sign(sk, msg, sizeof(msg) - 1, sig, &sig_len);
    assert(ret == 0 && "sign failed");
    printf("  (signature length: %zu bytes)\n", sig_len);
    report("sign   ");
    if (keccak_call_count != 0) overall_pass = 0;

    /* ---- verify ---- */
    reset_counter();
    ret = faest_sm4_128s_verify(pk, msg, sizeof(msg) - 1, sig, sig_len);
    assert(ret == 0 && "verify failed");
    report("verify ");
    if (keccak_call_count != 0) overall_pass = 0;

    printf("\n");
    if (overall_pass) {
        printf("\033[32m[AUDIT PASSED] SM4 path invokes zero Keccak permutations.\033[0m\n");
    } else {
        printf("\033[31m[AUDIT FAILED] Keccak permutation invoked in SM4 path!\033[0m\n");
    }
    printf("\n");
    return overall_pass ? 0 : 1;
}
