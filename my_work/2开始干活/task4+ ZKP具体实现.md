Task 4 规划：faest_sm4.c 完整实现
faest_param_sm4.c.in 文件已经完成（它只是模板文件，调用底层函数）。真正需要实现的是 faest_sm4.c 中的 ZK 约束系统。

实现分解（按优先级）

阶段 1：S-box 约束系统 (预计 400-500 行)
// 需要实现的函数：
static void sm4_sbox_constraints_prover(...);
static void sm4_sbox_constraints_verifier(...);

目标：为 SM4 S-box 创建 ZK 约束
技术要点：
SM4 S-box = 仿射变换 ∘ GF(2⁸) 逆元（多项式：0x1F5）
需要实现逆仿射变换的 ZK 约束
参考 faest_aes.c.in 中的 aes_constraints 函数结构
依赖：fields.c（GF(2⁸) 运算）、vole.h（VOLE 承诺）

阶段 2：线性变换约束 (预计 200-300 行)
// 需要实现的函数：
static void sm4_linear_l_constraints_prover(...);
static void sm4_linear_l_constraints_verifier(...);
static void sm4_linear_l_prime_constraints_prover(...);  // 密钥扩展用
static void sm4_linear_l_prime_constraints_verifier(...);

目标：为 SM4 的 L 和 L' 线性变换创建约束
技术要点：
L 变换：循环左移 + 异或（加密用）
L' 变换：密钥扩展专用
线性变换可以直接用 VOLE 向量操作表示
阶段 3：密钥扩展约束 (预计 300-400 行)

// 需要实现的函数：
static void sm4_key_schedule_constraints_prover(...);
static void sm4_key_schedule_constraints_verifier(...);

目标：为 32 轮密钥扩展创建约束
技术要点：
处理 FK 常数异或
处理 CK 常数异或
T' 变换约束（S-box + L'）
需要记录中间密钥 K[0..3]
阶段 4：加密轮函数约束 (预计 400-500 行)

// 需要实现的函数：
static void sm4_enc_constraints_prover(...);
static void sm4_enc_constraints_verifier(...);

目标：为 32 轮 Feistel 加密创建约束
技术要点：
32 轮 Feistel 结构
T 变换约束（S-box + L）
状态更新和异或操作
前 31 轮需要约束（最后一轮不提交）
阶段 5：顶层证明/验证函数 (预计 200-300 行)

// 需要实现的函数：
void sm4_128_prover(faest_paramset_t*, vole_t*, ...);
void sm4_128_verifier(faest_paramset_t*, vole_t*, ...);

目标：整合所有约束，实现完整的证明者和验证者
技术要点：
调用密钥扩展约束
调用加密轮函数约束
处理 VOLE 承诺的聚合
Universal hashing 进行最终验证
📌 实施建议
参考 AES 实现：faest_aes.c.in 有完整的 ZK 约束系统，可以作为模板

字段运算：理解 fields.c 中的 GF(2⁸) 运算

SM4 使用多项式 0x1F5（vs AES 的 0x11B）
需要调整 bf8_inv 等函数的参数
分阶段测试：

每完成一个阶段，编译并运行 API 测试
直到 crypto_sign_open 返回 0（验证成功）
预计工作量：

总代码量：约 1500-2000 行
开发时间：熟悉 FAEST 约束系统后，约 3-5 天