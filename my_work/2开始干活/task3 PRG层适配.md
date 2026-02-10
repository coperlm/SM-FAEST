PRG 使用 AES-CTR 模式，需要改为 SM4-CTR：

// aes.c/sm4.c 中的 prg 函数

// 旧实现（AES-CTR）
void prg(const uint8_t* key, const uint8_t* iv, uint32_t tweak,
         uint8_t* out, unsigned int bits, size_t outlen) {
    aes_round_keys_t rk;
    aes128_init_round_keys(&rk, key);
    
    uint8_t ctr[16];
    memcpy(ctr, iv, 16);
    // ... AES-CTR 逻辑
}

// 新实现（SM4-CTR）
void prg(const uint8_t* key, const uint8_t* iv, uint32_t tweak,
         uint8_t* out, unsigned int bits, size_t outlen) {
    sm4_round_keys_t rk;
    sm4_init_round_keys(&rk, key);
    
    uint8_t ctr[16];
    memcpy(ctr, iv, 16);
    
    // SM4-CTR 模式
    const size_t blocks = (outlen + 15) / 16;
    for (size_t i = 0; i < blocks; i++) {
        sm4_encrypt_block(&rk, ctr, out + i * 16);
        sm4_increment_ctr(ctr, tweak); // 需实现计数器递增
    }
}
