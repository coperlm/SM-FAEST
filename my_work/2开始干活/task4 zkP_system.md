这是最大的挑战，需要重写 faest_aes.c.in 中的所有约束：

1. 文件重命名与重构

faest_aes.c.in  →  faest_sm4.c.in
faest_aes.h     →  faest_sm4.h

2. 核心约束重写

AES 的约束（当前）：

// AES 使用 Degree-3 约束验证 S-box: c · a² · a¹⁶ = a
static void aes_SSS_inv_norm_constraints_prover(
    zk_hash_SSS_3_ctx* hasher,
    const bfSSS_t* conjugates,
    const bfSSS_t* conjugates_tag,
    const bfSSS_t* y,
    const bfSSS_t* y_tag) {
    
    zk_hash_SSS_3_update(
        hasher,
        bfSSS_mul(bfSSS_mul(*y_tag, conjugates_tag[1]), conjugates_tag[4]),
        // ... degree-3 乘法
    );
}

SM4 的约束（需要设计）：

// SM4 S-box 是查找表，需要用布尔电路或算术电路表示

// 电路分解（更高效但需要密码学研究）
// 使用 SM4 S-box 的代数结构
// 伪代码：SM4 S-box 约束设计
static void sm4_SSS_sbox_constraints_prover(
    zk_hash_SSS_3_ctx* hasher,
    const bfSSS_t* input,      // S-box 输入 (x)
    const bfSSS_t* output,     // S-box 输出 (y)
    // ... tags ...
) {
    // 1. 逆仿射变换 (Linear - Free cost)
    // SM4 的输出 y 先减去常数 C，再乘以 L 的逆矩阵
    // z = L_inv(y + C)
    bfSSS_t z = sm4_inverse_affine_transform(*output); 
    bfSSS_t z_tag = sm4_inverse_affine_transform(*output_tag);

    // 2. 验证逆元关系 (Degree-2 Constraint)
    // 约束方程: input * z = 1
    // 注意：这里是在 GF(2^8) 域上的乘法
    
    // 在实际 FAEST 代码中，通常使用 lift properties 或特定的乘法 API
    // 你需要调用 bfSSS_mul 来计算 input * z，并断言结果为 1
    
    // 示例逻辑 (参考 AES 的实现结构):
    zk_hash_SSS_3_update(
        hasher,
        bfSSS_mul(*input_tag, z_tag), // 计算 a * b
        // 这里需要根据 FAEST 具体的证明协议（如 BESS 协议）填充参数
        // 核心是证明 input * z - 1 = 0
    );
}

关键难点提示：域的表示 (Field Representation)AES 使用的 $GF(2^8)$ 不可约多项式是 $x^8+x^4+x^3+x+1$。SM4 使用的 $GF(2^8)$ 不可约多项式是 $x^8+x^7+x^6+x^5+x^4+x^2+1$。FAEST 内部为了加速乘法，可能使用塔域（Tower Field）$GF((2^4)^2)$ 表示。你需要做一个基变换（Basis Change）： 将 SM4 的自然基（Polynomial Basis）映射到 FAEST 内部使用的塔域基，才能进行乘法约束。

3. 轮函数约束适配

// AES: SPN 结构
// SubBytes → ShiftRows → MixColumns → AddRoundKey

// SM4: Feistel 结构  
// X_{i+4} = X_i ⊕ T(X_{i+1} ⊕ X_{i+2} ⊕ X_{i+3} ⊕ rk_i)

static void sm4_SSS_enc_constraints_prover(
    zk_hash_SSS_3_ctx* hasher,
    const uint8_t* owf_in,
    const uint8_t* owf_key,
    bfSSS_t* bf_out,
    bfSSS_t* bf_out_tag,
    const faest_paramset_t* params) {
    
    // 32轮迭代约束验证
    for (unsigned int round = 0; round < SM4_ROUNDS; round++) {
        // 1. 验证密钥扩展
        sm4_SSS_key_schedule_constraints();
        
        // 2. 验证轮函数 F
        sm4_SSS_round_function_constraints();
        
        // 3. 验证 S-box
        sm4_SSS_sbox_constraints_prover();
        
        // 4. 验证线性变换
        sm4_SSS_linear_transform_constraints();
    }
}

最终全面测试：

测试层次：
1. SM4 底层测试
   └─ tests/sm4.cpp：单元测试（密钥扩展、加密、S-box）

2. OWF 层测试
   └─ tests/owf.cpp：单向函数测试

3. PRG 层测试
   └─ tests/prg.cpp：伪随机数生成器测试

4. 约束系统测试
   └─ tests/sm4_prove.cpp：ZK 证明正确性测试

5. 集成测试
   └─ tests/api_test.c：完整签名/验证流程

6. 性能测试
   └─ tools/bench.cpp：性能基准测试

针对 FAEST 这种基于 VOLE 的零知识证明系统，实现 SM4 逆仿射变换（Inverse Affine Transformation）的关键在于：它必须是线性的。在 FAEST 中，线性操作（XOR）几乎是免费的，而非线性操作（AND/乘法）非常昂贵。因此，我们的目标是将 SM4 S-box 的结构拆解，把非线性的“求逆”孤立出来。以下是具体的数学推导、方案选择以及在 faest_sm4.c 中的代码实现方式。1. 数学推导与方案SM4 的 S-box 输出 $y$ 和输入 $x$ 的关系是：$$y = S(x) = L(I(x)) \oplus C$$其中：$I(x)$: $GF(2^8)$ 上的求逆（如果 $x=0$ 则为 $0$）。$L$: 仿射线性变换（矩阵乘法）。$C$: 仿射常数 $0xD3$ (二进制 11010011)。为了构建约束 $x \cdot z = 1$，我们需要从输出 $y$ 反向计算出中间值 $z$（即 $I(x)$ 的结果）。$$z = L^{-1}(y \oplus C)$$逆变换的逻辑SM4 的前向仿射变换 $L$ 定义为：$$b'_i = b_i \oplus b_{i+1} \oplus b_{i+2} \oplus b_{i+3} \oplus b_{i+4} \pmod 8$$这等价于多项式 $A(x) = 1 + x + x^2 + x^3 + x^4$。它的逆变换 $L^{-1}$ 对应的多项式是 $A^{-1}(x) = x^1 + x^3 + x^7$。这意味着输出的第 $i$ 位，取决于输入的第 $i+1, i+3, i+7$ 位（循环移位）。结论公式：$$z_i = (y \oplus C)_{i+1} \oplus (y \oplus C)_{i+3} \oplus (y \oplus C)_{i+7}$$2. 具体实现方式 (C 代码)在 FAEST 代码中，你操作的对象不是 uint8_t，而是 bfSSS_t（秘密共享的比特序列）或 bf8_t。我将提供两种实现：一种是基于比特操作（高效），一种是基于矩阵（通用且易于调试）。方式 A：位操作法（推荐，性能最高）这种方式利用了 SM4 仿射变换的循环特性，代码量最小。方式 B：矩阵乘法法（最稳健）如果你担心比特序（Endianness）搞错（比如 bit 0 是高位还是低位），矩阵法是最安全的，因为你可以显式定义每一行。你需要预计算逆矩阵 $M_{inv}$。$M_{inv}$ 的每一行对应上面的公式（即第 $i$ 行在 $i+1, i+3, i+7$ 列为 1）。3. 极重要的补充：基变换 (Basis Change)这是替换 AES 时最容易被忽略的一点。问题: 上述代码计算出的 z_in 是在 SM4 的多项式基 下的值。冲突: FAEST 的底层乘法器（zk_hash 或 bfSSS_mul）通常是在 AES 的塔域（Tower Field） 或 AES 的多项式基上实现的。后果: 直接让输入 $x$ 和这个 $z$ 做乘法验证 $x \cdot z = 1$，验证会失败，因为域不同。你必须在逆仿射之后，加入一个基变换矩阵 $M_{basis}$。你需要计算从 SM4 基到 FAEST 内部基的映射矩阵。找到 SM4 基 $P_{sm4} = x^8+x^7+x^6+x^5+x^4+x^2+1$。找到 FAEST 内部基（通常是 $P_{aes} = x^8+x^4+x^3+x+1$ 或同构的塔域）。生成变换矩阵 $T$。最终的约束流程：如果你的 FAEST 实现允许定义自定义多项式的域，你可以省略基变换，直接修改底层的域参数。但通常 FAEST 为了速度硬编码了塔域，所以叠加一个线性基变换矩阵（即修改上面的 SM4_INV_AFFINE_MTX，使其直接等于 $M_{basis} \times M_{inv\_affine}$）是最高效的做法。