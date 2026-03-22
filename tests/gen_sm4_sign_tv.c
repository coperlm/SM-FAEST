/**
 * gen_sm4_sign_tv.c
 * 生成 FAEST-SM4-128s 和 FAEST-EM-SM4-128s 的签名测试向量
 * 用法: ./gen_sm4_sign_tv [出目标: sm4|em_sm4]
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* 引用 FAEST API */
#include "parameters.h"
#include "faest_sm4_128s.h"
#include "faest_em_sm4_128s.h"

/* SM4-128s 测试向量 key */
static const uint8_t sm4_sk[FAEST_SM4_128S_SK_SIZE] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* EM-SM4-128s 测试向量 key (from faest_tvs.hpp line ~1100) */
static const uint8_t em_sm4_sk[FAEST_EM_SM4_128S_SK_SIZE] = {
    /* 需要从 faest_tvs.hpp 中读取 em_sm4_128s::sk */
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* 固定随机种子 (from faest_tvs.hpp) */
static const uint8_t random_seed[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

/* "This document describes and specifies the FAEST digital signature algorithm." */
static const uint8_t message[76] = {
    0x54, 0x68, 0x69, 0x73, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74,
    0x20, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x73, 0x20, 0x61, 0x6e,
    0x64, 0x20, 0x73, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x65, 0x73, 0x20, 0x74,
    0x68, 0x65, 0x20, 0x46, 0x41, 0x45, 0x53, 0x54, 0x20, 0x64, 0x69, 0x67, 0x69,
    0x74, 0x61, 0x6c, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
    0x20, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e
};

static void dump_inc(const char* filename, const uint8_t* data, size_t len) {
    FILE* f = fopen(filename, "w");
    if (!f) { perror(filename); exit(1); }
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) fprintf(f, "    ");
        fprintf(f, "0x%02x", data[i]);
        if (i + 1 < len) fprintf(f, ", ");
        if ((i + 1) % 16 == 0 || i + 1 == len) fprintf(f, "\n");
    }
    fclose(f);
    fprintf(stderr, "Written %zu bytes to %s\n", len, filename);
}

int main(int argc, char** argv) {
    int do_sm4 = 1;
    int do_em_sm4 = 0;

    if (argc > 1) {
        do_sm4 = 0;
        if (strcmp(argv[1], "sm4") == 0) {
            do_sm4 = 1;
        } else if (strcmp(argv[1], "em_sm4") == 0) {
            do_em_sm4 = 1;
        } else if (strcmp(argv[1], "all") == 0) {
            do_sm4 = 1;
            do_em_sm4 = 1;
        } else {
            fprintf(stderr, "Usage: %s [sm4|em_sm4|all]\n", argv[0]);
            return 1;
        }
    }

    /* SM4-128s */
    if (do_sm4) {
        size_t sig_size = FAEST_SM4_128S_SIG_SIZE;
        uint8_t* sig = calloc(sig_size, 1);
        if (!sig) { perror("calloc"); return 1; }
        int ret = faest_sm4_128s_sign_with_randomness(sm4_sk,
                                  message,
                                  sizeof(message),
                                  random_seed,
                                  sizeof(random_seed),
                                  sig,
                                  &sig_size);
        if (ret != 0) {
            fprintf(stderr, "faest_sign SM4-128s failed: %d\n", ret);
            free(sig);
            return 1;
        }
        fprintf(stderr, "SM4-128s signature size: %zu (expected %zu)\n", sig_size,
            (size_t)FAEST_SM4_128S_SIG_SIZE);
        dump_inc("tests/faest_sm4_128s_signature.inc", sig, sig_size);
        free(sig);
    }

    /* EM-SM4-128s */
    if (do_em_sm4) {
        size_t sig_size = FAEST_EM_SM4_128S_SIG_SIZE;
        uint8_t* sig = calloc(sig_size, 1);
        if (!sig) { perror("calloc"); return 1; }
        int ret = faest_em_sm4_128s_sign_with_randomness(em_sm4_sk,
                                 message,
                                 sizeof(message),
                                 random_seed,
                                 sizeof(random_seed),
                                 sig,
                                 &sig_size);
        if (ret != 0) {
            fprintf(stderr, "faest_sign EM-SM4-128s failed: %d\n", ret);
            free(sig);
            return 1;
        }
        fprintf(stderr, "EM-SM4-128s signature size: %zu (expected %zu)\n", sig_size,
            (size_t)FAEST_EM_SM4_128S_SIG_SIZE);
        dump_inc("tests/faest_em_sm4_128s_signature.inc", sig, sig_size);
        free(sig);
    }

    return 0;
}
