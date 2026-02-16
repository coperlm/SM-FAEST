# AES vs SM4 在 FAEST ZKP 中的集成对比分析

## 算法结构对比

| 特性 | AES-128 (FIPS 197) | SM4 (GM/T 0002-2012) |
|------|-------------------|---------------------|
| **密钥长度** | 128位固定 | 128位固定 |
| **分组大小** | 128位 | 128位 |
| **轮数** | 10轮 | 32轮 |
| **S-box** | 8×8位查找表 | 8×8位查找表 |
| **轮函数** | SubBytes + ShiftRows + MixColumns | τ变换 + L变换 |
| **密钥扩展** | RotWord + SubWord + Rcon | T'变换 + 固定参数CK |
| **设计理念** | 代数结构 (有限域) | 简单变换 (SPN结构) |

## FAEST ZKP 实现要点

### 当前 AES 实现结构 (faest_aes.c.in)

FAEST 的 AES ZKP 实现包含以下核心组件：

1. **S-box 仿射变换**
   - `aes_SSS_sbox_affine_prover/verifier`
   - 使用 9 个常数系数进行仿射变换

2. **行移位**
   - `aes_SSS_shiftrows_prover/verifier`
   - 简单的字节循环移位

3. **列混淆**
   - `aes_SSS_mix_columns_prover/verifier`
   - 使用有限域乘法 (×2, ×3)

4. **轮密钥加**
   - `aes_SSS_add_round_key_prover/verifier`
   - 简单的异或操作

5. **密钥扩展约束**
   - `aes_SSS_expkey_constraints_prover/verifier`
   - RotWord + SubWord + Rcon 轮常量

6. **加密约束**
   - `aes_SSS_enc_constraints_prover/verifier`
   - 完整的 AES 轮函数 ZKP 证明

### SM4 集成策略

#### 1. S-box 替换
```c
// AES S-box (有限域逆 + 仿射变换)
// SM4 S-box (直接查找表)
static const uint8_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, /* ... */
};
```

#### 2. 轮函数替换
**AES 轮函数:**
- SubBytes: S-box 查找
- ShiftRows: 行循环移位
- MixColumns: 有限域矩阵乘法

**SM4 轮函数:**
- τ变换: S-box 非线性变换
- L变换: 线性变换 (循环移位 + XOR)

#### 3. 密钥扩展差异
**AES:**
```c
// RotWord + SubWord + Rcon
temp = rotl32(temp, 8);
temp = AES_SBOX[temp & 0xFF] ^ AES_RCON[i/4];
```

**SM4:**
```c
// T'变换 + 固定参数 CK
K[i+4] = K[i] ^ sm4_t_prime(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]);
```

## 实现建议

### 阶段 1: 基础 SM4 实现
1. 创建 `faest_sm4.c.in` 和 `faest_sm4.h`
2. 实现基本的 SM4 加密/解密函数
3. 验证与标准测试向量的正确性

### 阶段 2: ZKP 约束构造
1. **S-box 约束**: 替换 AES 的仿射 S-box 为 SM4 的直接查找表
2. **轮函数约束**: 实现 τ变换和 L变换的 ZKP 证明
3. **密钥扩展约束**: 实现 SM4 密钥扩展的 ZKP 证明

### 阶段 3: 集成与测试
1. 修改 FAEST 参数集以支持 SM4
2. 实现完整的证明者和验证者函数
3. 进行全面的正确性测试

## 关键挑战

1. **轮数差异**: SM4 的 32 轮 vs AES 的 10 轮
2. **变换复杂度**: SM4 的 τ+L 变换 vs AES 的 SubBytes+ShiftRows+MixColumns
3. **密钥扩展**: SM4 的固定参数 CK vs AES 的动态 Rcon

## 代码示例: SM4 轮函数 ZKP

```c
// SM4 τ变换证明者
void sm4_tau_prover(uint8_t* out, bfSSS_t* out_tag,
                   const uint8_t* in, const bfSSS_t* in_tag) {
    uint32_t x = bytes_to_uint32(in);
    uint32_t result = sm4_tau(x);

    // ZKP 约束构造 (简化版)
    // 需要实现完整的 S-box 查找表约束
    uint32_to_bytes(result, out);
    // out_tag 计算...
}

// SM4 L变换证明者
void sm4_linear_l_prover(uint8_t* out, bfSSS_t* out_tag,
                        const uint8_t* in, const bfSSS_t* in_tag) {
    uint32_t b = bytes_to_uint32(in);
    uint32_t result = sm4_linear_l(b);

    // ZKP 约束构造 (循环移位 + XOR)
    uint32_to_bytes(result, out);
    // out_tag 计算...
}
```

## 结论

SM4 集成到 FAEST 需要：
- 重新设计轮函数的 ZKP 约束
- 修改密钥扩展算法
- 调整参数以适应 32 轮结构
- 保持与现有 FAEST 框架的兼容性

这种集成将使 FAEST 支持中国国家标准的对称加密算法，为更广泛的应用场景提供 ZKP 证明能力。