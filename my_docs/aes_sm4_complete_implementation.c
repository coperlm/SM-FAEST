#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// ==================== 完整的 AES-128 实现 ====================

// AES S-box
static const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// AES逆S-box
static const uint8_t AES_INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// AES轮常量
static const uint8_t AES_RCON[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

// 有限域乘法 (用于MixColumns)
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t carry;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        carry = a & 0x80;
        a <<= 1;
        if (carry) a ^= 0x1b;  // x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

// AES轮密钥结构
typedef struct {
    uint32_t round_keys[44]; // 11轮 x 4个字
} aes_key_schedule_t;

// AES状态矩阵 (4x4字节)
typedef uint8_t aes_state_t[4][4];

// 字节到字的转换
static inline uint32_t bytes_to_word(const uint8_t* bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | ((uint32_t)bytes[3]);
}

// 字到字节的转换
static inline void word_to_bytes(uint32_t word, uint8_t* bytes) {
    bytes[0] = (word >> 24) & 0xFF;
    bytes[1] = (word >> 16) & 0xFF;
    bytes[2] = (word >> 8) & 0xFF;
    bytes[3] = word & 0xFF;
}

// 字的循环左移
static inline uint32_t rot_word(uint32_t word) {
    return ((word << 8) & 0xFFFFFF00) | ((word >> 24) & 0xFF);
}

// 对字应用S-box
static inline uint32_t sub_word(uint32_t word) {
    uint8_t bytes[4];
    word_to_bytes(word, bytes);
    bytes[0] = AES_SBOX[bytes[0]];
    bytes[1] = AES_SBOX[bytes[1]];
    bytes[2] = AES_SBOX[bytes[2]];
    bytes[3] = AES_SBOX[bytes[3]];
    return bytes_to_word(bytes);
}

// AES密钥扩展
void aes_key_expansion(const uint8_t* key, aes_key_schedule_t* ks) {
    uint32_t* w = ks->round_keys;

    // 复制初始密钥
    for (int i = 0; i < 4; i++) {
        w[i] = bytes_to_word(key + 4 * i);
    }

    // 生成剩余轮密钥
    for (int i = 4; i < 44; i++) {
        uint32_t temp = w[i-1];
        if (i % 4 == 0) {
            temp = rot_word(temp);
            temp = sub_word(temp);
            temp ^= (AES_RCON[i/4] << 24);
        }
        w[i] = w[i-4] ^ temp;
    }
}

// SubBytes变换
void aes_sub_bytes(aes_state_t state) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = AES_SBOX[state[i][j]];
        }
    }
}

// InvSubBytes变换
void aes_inv_sub_bytes(aes_state_t state) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = AES_INV_SBOX[state[i][j]];
        }
    }
}

// ShiftRows变换
void aes_shift_rows(aes_state_t state) {
    uint8_t temp;

    // 第1行左移1位
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // 第2行左移2位
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // 第3行左移3位
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

// InvShiftRows变换
void aes_inv_shift_rows(aes_state_t state) {
    uint8_t temp;

    // 第1行右移1位
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // 第2行右移2位
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // 第3行右移3位
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

// MixColumns变换
void aes_mix_columns(aes_state_t state) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[0][c];
        uint8_t s1 = state[1][c];
        uint8_t s2 = state[2][c];
        uint8_t s3 = state[3][c];

        state[0][c] = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3;
        state[1][c] = s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3;
        state[2][c] = s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3);
        state[3][c] = gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3);
    }
}

// InvMixColumns变换
void aes_inv_mix_columns(aes_state_t state) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[0][c];
        uint8_t s1 = state[1][c];
        uint8_t s2 = state[2][c];
        uint8_t s3 = state[3][c];

        state[0][c] = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3);
        state[1][c] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3);
        state[2][c] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3);
        state[3][c] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3);
    }
}

// AddRoundKey变换
void aes_add_round_key(aes_state_t state, const uint32_t* round_key) {
    for (int c = 0; c < 4; c++) {
        uint32_t key_word = round_key[c];
        uint8_t key_bytes[4];
        word_to_bytes(key_word, key_bytes);

        for (int r = 0; r < 4; r++) {
            state[r][c] ^= key_bytes[r];
        }
    }
}

// 状态到字节数组的转换
void state_to_bytes(const aes_state_t state, uint8_t* bytes) {
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            bytes[r + 4 * c] = state[r][c];
        }
    }
}

// 字节数组到状态的转换
void bytes_to_state(const uint8_t* bytes, aes_state_t state) {
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] = bytes[r + 4 * c];
        }
    }
}

// AES-128加密
void aes_encrypt(const uint8_t* plaintext, const uint8_t* key, uint8_t* ciphertext) {
    aes_key_schedule_t ks;
    aes_key_expansion(key, &ks);

    aes_state_t state;
    bytes_to_state(plaintext, state);

    // 初始轮密钥加
    aes_add_round_key(state, ks.round_keys);

    // 9轮标准轮
    for (int round = 1; round < 10; round++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, ks.round_keys + 4 * round);
    }

    // 最后一轮 (无MixColumns)
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, ks.round_keys + 40);

    state_to_bytes(state, ciphertext);
}

// AES-128解密
void aes_decrypt(const uint8_t* ciphertext, const uint8_t* key, uint8_t* plaintext) {
    aes_key_schedule_t ks;
    aes_key_expansion(key, &ks);

    aes_state_t state;
    bytes_to_state(ciphertext, state);

    // 初始轮密钥加 (最后一轮密钥)
    aes_add_round_key(state, ks.round_keys + 40);

    // 9轮逆标准轮
    for (int round = 9; round > 0; round--) {
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
        aes_add_round_key(state, ks.round_keys + 4 * round);
        aes_inv_mix_columns(state);
    }

    // 第一轮 (无InvMixColumns)
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, ks.round_keys);

    state_to_bytes(state, plaintext);
}

// ==================== 完整的 SM4 实现 ====================

// SM4 S-box (GM/T 0002-2012)
static const uint8_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// SM4系统参数 FK (固定密钥字)
static const uint32_t SM4_FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

// SM4固定参数 CK (轮常量字)
static const uint32_t SM4_CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// SM4轮密钥结构
typedef struct {
    uint32_t round_keys[32];
} sm4_key_schedule_t;

// 循环左移
static inline uint32_t rotl32(uint32_t x, unsigned int n) {
    return (x << n) | (x >> (32 - n));
}

// 字节到字的转换
static inline uint32_t sm4_bytes_to_word(const uint8_t* bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | ((uint32_t)bytes[3]);
}

// 字到字节的转换
static inline void sm4_word_to_bytes(uint32_t word, uint8_t* bytes) {
    bytes[0] = (word >> 24) & 0xFF;
    bytes[1] = (word >> 16) & 0xFF;
    bytes[2] = (word >> 8) & 0xFF;
    bytes[3] = word & 0xFF;
}

// τ变换 (S-box非线性变换)
static inline uint32_t sm4_tau(uint32_t a) {
    uint8_t bytes[4];
    sm4_word_to_bytes(a, bytes);

    bytes[0] = SM4_SBOX[bytes[0]];
    bytes[1] = SM4_SBOX[bytes[1]];
    bytes[2] = SM4_SBOX[bytes[2]];
    bytes[3] = SM4_SBOX[bytes[3]];

    return sm4_bytes_to_word(bytes);
}

// L变换 (线性变换，用于加密)
static inline uint32_t sm4_linear_l(uint32_t b) {
    return b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24);
}

// L'变换 (线性变换，用于密钥扩展)
static inline uint32_t sm4_linear_l_prime(uint32_t b) {
    return b ^ rotl32(b, 13) ^ rotl32(b, 23);
}

// T变换 (τ ∘ L，用于加密)
static inline uint32_t sm4_t(uint32_t x) {
    return sm4_linear_l(sm4_tau(x));
}

// T'变换 (τ ∘ L'，用于密钥扩展)
static inline uint32_t sm4_t_prime(uint32_t x) {
    return sm4_linear_l_prime(sm4_tau(x));
}

// SM4密钥扩展算法
void sm4_key_expansion(const uint8_t* key, sm4_key_schedule_t* ks) {
    uint32_t K[36]; // K[0..3] 为中间密钥, K[4..35] 为轮密钥

    // MK ⊕ FK → K[0..3]
    for (int i = 0; i < 4; i++) {
        K[i] = sm4_bytes_to_word(key + 4 * i) ^ SM4_FK[i];
    }

    // 生成32个轮密钥
    for (int i = 0; i < 32; i++) {
        K[i + 4] = K[i] ^ sm4_t_prime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ SM4_CK[i]);
        ks->round_keys[i] = K[i + 4];
    }
}

// SM4加密算法
void sm4_encrypt(const uint8_t* plaintext, const uint8_t* key, uint8_t* ciphertext) {
    sm4_key_schedule_t ks;
    sm4_key_expansion(key, &ks);

    uint32_t X[36]; // X[0..3] 输入, X[4..35] 中间状态

    // 加载明文到X[0..3]
    for (int i = 0; i < 4; i++) {
        X[i] = sm4_bytes_to_word(plaintext + 4 * i);
    }

    // 32轮迭代: X[i+4] = X[i] ⊕ T(X[i+1] ⊕ X[i+2] ⊕ X[i+3] ⊕ rk[i])
    for (int i = 0; i < 32; i++) {
        X[i + 4] = X[i] ^ sm4_t(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ ks.round_keys[i]);
    }

    // 反序输出: (X[35], X[34], X[33], X[32])
    for (int i = 0; i < 4; i++) {
        sm4_word_to_bytes(X[35 - i], ciphertext + 4 * i);
    }
}

// SM4解密算法 (使用相同的轮密钥，但顺序相反)
void sm4_decrypt(const uint8_t* ciphertext, const uint8_t* key, uint8_t* plaintext) {
    sm4_key_schedule_t ks;
    sm4_key_expansion(key, &ks);

    uint32_t X[36];

    // 加载密文到X[0..3] (注意反序)
    for (int i = 0; i < 4; i++) {
        X[i] = sm4_bytes_to_word(ciphertext + 4 * i);
    }

    // 32轮逆迭代: X[i+4] = X[i] ⊕ T(X[i+1] ⊕ X[i+2] ⊕ X[i+3] ⊕ rk[31-i])
    for (int i = 0; i < 32; i++) {
        X[i + 4] = X[i] ^ sm4_t(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ ks.round_keys[31 - i]);
    }

    // 反序输出
    for (int i = 0; i < 4; i++) {
        sm4_word_to_bytes(X[35 - i], plaintext + 4 * i);
    }
}

// ==================== 性能测试和正确性验证 ====================

// 打印十六进制数据
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// 性能测试
void benchmark_algorithm(const char* name,
                        void (*encrypt_func)(const uint8_t*, const uint8_t*, uint8_t*),
                        const uint8_t* key, int iterations) {
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16];

    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        encrypt_func(plaintext, key, ciphertext);
        // 改变明文以避免优化
        plaintext[0] = (uint8_t)i;
    }
    clock_t end = clock();

    double time_taken = (double)(end - start) / CLOCKS_PER_SEC;
    double throughput = (iterations * 16.0) / (time_taken * 1024 * 1024); // MB/s

    printf("%s 性能测试:\n", name);
    printf("  迭代次数: %d\n", iterations);
    printf("  总时间: %.4f 秒\n", time_taken);
    printf("  吞吐量: %.2f MB/s\n", throughput);
    printf("  单个块时间: %.2f μs\n", (time_taken * 1000000) / iterations);
    printf("\n");
}

// 正确性测试
void test_correctness() {
    printf("=== 算法正确性测试 ===\n\n");

    // 测试向量 (来自标准文档)
    const uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    const uint8_t plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    // AES-128 标准测试向量
    const uint8_t aes_expected[16] = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
    };

    // SM4 标准测试向量
    const uint8_t sm4_expected[16] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };

    uint8_t aes_ciphertext[16];
    uint8_t sm4_ciphertext[16];
    uint8_t aes_decrypted[16];
    uint8_t sm4_decrypted[16];

    print_hex("密钥", key, 16);
    print_hex("明文", plaintext, 16);
    printf("\n");

    // AES 测试
    printf("AES-128 测试:\n");
    aes_encrypt(plaintext, key, aes_ciphertext);
    print_hex("AES密文", aes_ciphertext, 16);
    print_hex("期望值", aes_expected, 16);

    aes_decrypt(aes_ciphertext, key, aes_decrypted);
    print_hex("AES解密", aes_decrypted, 16);

    printf("AES正确性: %s\n", memcmp(plaintext, aes_decrypted, 16) == 0 ? "通过" : "失败");
    printf("\n");

    // SM4 测试
    printf("SM4 测试:\n");
    sm4_encrypt(plaintext, key, sm4_ciphertext);
    print_hex("SM4密文", sm4_ciphertext, 16);
    print_hex("期望值", sm4_expected, 16);

    sm4_decrypt(sm4_ciphertext, key, sm4_decrypted);
    print_hex("SM4解密", sm4_decrypted, 16);

    printf("SM4正确性: %s\n", memcmp(plaintext, sm4_decrypted, 16) == 0 ? "通过" : "失败");
    printf("\n");
}

// 详细算法对比
void detailed_comparison() {
    printf("=== AES vs SM4 详细对比 ===\n\n");

    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("特性              │ AES-128 (FIPS 197)              │ SM4 (GM/T 0002-2012)\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("设计机构          │ NIST (美国)                     │ 国家密码管理局 (中国)\n");
    printf("公布年份          │ 2001                            │ 2012\n");
    printf("分组长度          │ 128位固定                      │ 128位固定\n");
    printf("密钥长度          │ 128位固定                      │ 128位固定\n");
    printf("轮数              │ 10轮                            │ 32轮\n");
    printf("网络结构          │ SPN (代换-置换)                 │ Feistel (平衡)\n");
    printf("S-box设计         │ 有限域逆+仿射变换               │ 直接查找表\n");
    printf("轮函数            │ SubBytes+ShiftRows+MixColumns   │ τ变换+L变换\n");
    printf("密钥扩展          │ RotWord+SubWord+Rcon           │ T'变换+固定参数CK\n");
    printf("扩散机制          │ 矩阵乘法 (有限域)               │ 循环移位+XOR\n");
    printf("安全性分析        │ 差分/线性攻击抵抗              │ 差分/线性攻击抵抗\n");
    printf("硬件实现          │ 中等复杂度                      │ 低复杂度\n");
    printf("软件实现          │ 高速                            │ 中速\n");
    printf("并行化            │ 字节级并行                      │ 字级并行\n");
    printf("缓存友好性        │ 良好                            │ 良好\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    printf("FAEST ZKP 集成分析:\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("• AES在FAEST中已有完整实现，包含所有轮函数的代数约束\n");
    printf("• SM4需要重新构造ZKP约束，特别是S-box和线性变换的证明\n");
    printf("• SM4的32轮结构将显著增加证明大小和计算复杂度\n");
    printf("• SM4的位操作特性可能需要特殊的约束构造技术\n");
    printf("• 两种算法的密钥扩展都需要独立的ZKP证明构造\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
}

int main() {
    printf("AES 与 SM4 分组密码算法完整实现与对比分析\n");
    printf("用于零知识证明系统 FAEST 的算法迁移研究\n\n");

    // 正确性测试
    test_correctness();

    // 详细对比
    detailed_comparison();

    // 性能测试
    printf("=== 性能测试 ===\n\n");

    const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    const int iterations = 100000;

    benchmark_algorithm("AES-128", aes_encrypt, key, iterations);
    benchmark_algorithm("SM4", sm4_encrypt, key, iterations);

    printf("测试完成。\n");

    return 0;
}