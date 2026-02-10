替换 owf.c 中的 AES 调用：

// 旧代码（AES）
void owf_128(const uint8_t* key, const uint8_t* input, uint8_t* output) {
    aes_round_keys_t round_keys;
    aes128_init_round_keys(&round_keys, key);
    aes128_encrypt_block(&round_keys, input, output);
}

// 新代码（SM4）
void owf_128(const uint8_t* key, const uint8_t* input, uint8_t* output) {
    sm4_round_keys_t round_keys;
    sm4_init_round_keys(&round_keys, key);
    sm4_encrypt_block(&round_keys, input, output);
}

// EM 变体（注意：SM4 的 EM 模式需要调整）
void owf_em_128(const uint8_t* key, const uint8_t* input, uint8_t* output) {
    sm4_round_keys_t round_keys;
    sm4_init_round_keys(&round_keys, input); // EM: 用输入作为密钥
    
    uint8_t temp[16];
    sm4_encrypt_block(&round_keys, key, temp);
    xor_u8_array(temp, key, output, 16); // 输出 ⊕ key
}

关键改动点：

- #include "aes.h"
+ #include "sm4.h"

- aes_round_keys_t
+ sm4_round_keys_t

- AES_ROUNDS_128 (10)
+ SM4_ROUNDS (32)