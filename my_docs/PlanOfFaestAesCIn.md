基础宏 / 类型 / 常量（了解模板占位符）
字节 ↔ 多项式 / VOLE 辅助（field / tag 转换）
S‑box 与仿射（核心非线性）
线性层（ShiftRows / MixColumns / bitwise）
AddRoundKey 与 degree 对齐（tag/degree 细节）
密钥扩展（forward / backward）
密钥约束（expkey_constraints）
加密轮约束（enc_constraints —— 最大块）
OWF / 顶层包装（constraints_prover/verifier、aes_@SSS@_prover/verifier）
工具/辅助与测试点（matrix/存储、测试/实例）

章节划分（每节：包含函数 + 要点 + SM4 影响 + 小练习）
1) 模板 / 宏 / 常量（入门） 🔧
位置 / 符号：顶部宏定义（FAEST_SSS_LAMBDA、bfSSS_t 映射）、static_assert、RCON、RCON_EVERY。
要点：理解 @SSS@ 是模板占位符，编译/实例化由构建脚本决定。
与 SM4 的关系：决定实例位宽与常量（必须保证 SM4 的参数对应）。
练习（5–10min）：搜索 FAEST_@SSS@_LAMBDA 在仓库的位置，确认实例生成位置（instances.c / meson.build）。

---

