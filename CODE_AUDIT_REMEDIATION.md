# 代码审计整改记录

本文记录 2026-08-28 对 SM-FAEST 代码进行复核后的修改和仍需处理的事项。本文不修改论文仓库中的 LaTeX 文件。

## 已修改

### 1. 增加 SM3 与 SM3-XOF 测试

新增 `tests/hash_sm3.cpp`，并在 `tests/meson.build` 注册 `SM3` 测试：

- 使用 SM3 标准 `abc` 向量验证底层摘要接口；
- 用独立的直接 SM3 计算构造 Extract-then-Expand 参考值；
- 分别验证 `sm3_xof_one_shot` 和跨两次调用的 streaming squeeze；
- 这样可以覆盖前缀注入、大端计数器、块边界和连续 squeeze，而不只依赖端到端签名测试。

### 2. 将 invnorm 常数项检查从静默丢弃改为 debug 断言

`faest_sm4.c` 原来计算了约束的 degree-0 项后用 `(void)` 丢弃，只留下调试注释。现在保留计算结果，并在 debug 构建中断言它为零；发布构建显式消费该值，避免 `NDEBUG` 下的编译警告。

这不是用断言替代协议校验：该项按当前 QuickSilver 接口约定不作为独立 hash 输入，真正的安全性仍由协议最终化流程承担。断言的作用是尽早暴露 prover 内部见证或字段计算错误。

### 3. 修正过期的 quad 布局注释

将 verifier 注释中的 `quad_tags=112` 更新为实际的 `176`，减少后续维护时按旧布局修改偏移的风险。

## 已确认但没有冒险重写的部分

### 常量时间边界

默认 `FAEST_SM4_ALLOW_TTABLE=0`，SM4-CTR PRG 使用 bitsliced 逻辑门 S-box，不走 T-table。另一方面，`sm4_extend_witness` 的秘密相关见证生成仍调用 `SM4_SBOX[in]` 表查找。因此代码可以支持“PRG 路径无查表”的表述，但不能据此笼统宣称整个签名者流程严格常量时间。

将秘密路径改为 bitsliced SM4 会改变实现范围和性能，需要独立的向量、跨实现测试以及侧信道测量；本次没有进行未经证明的密码原语重写。

### 自生成 SM4 签名向量

SM4 签名测试向量由仓库工具生成，适合回归测试，但不是独立实现交叉验证。SM4 原语本身已有 GM/T 0002-2012 标准向量，FAEST 共享协议路径另有上游 FAEST 向量锚定；两者不能等同于独立验证 SM4-FAEST 签名输出。

## 论文必须同步的事项

论文正文未在本次修改。根据当前代码和 `meson.build`，应至少核对：

| 项目 | 论文现值 | 当前代码应核对值 |
|---|---:|---:|
| SM-FAEST-128S 签名大小 | 6794 bytes | 8202 bytes |
| SM-FAEST-EM-128S 签名大小 | 4286 bytes | 4682 bytes |
| SM-FAEST witness/`ELL` 口径 | 1792 bits | `ELL=3968` bits |
| SM-FAEST-EM witness/`ELL` 口径 | 896 bits | `ELL=1536` bits |

这些数字必须在摘要、正文、表格、结论和性能对比中统一。特别是 8202 bytes 大于论文表中 SPHINCS+ 的 7856 bytes，因此原有“签名更小”及其百分比不能继续保留，除非恢复旧布局并重新证明、测试和生成所有向量。

## 推荐的后续流程改进

1. 见证布局或 `SIG_SIZE` 变化时，同一变更中同时检查 `meson.build`、生成参数、签名向量、论文数字和性能结论。
2. 在 CI 中执行完整 `meson test`，并增加脚本核对论文数字与编译得到的 `crypto_sign_BYTES`。
3. 将论文性能原始样本和构建选项公开；明确普通基准的样本数与 SM4 专用基准的样本数。
4. 论文中将常量时间表述限定到实际采用 bitsliced、无查表的路径，或先完成秘密路径的无查表改造及独立验证。

## 验证记录

- `meson setup --reconfigure build`：成功；
- `meson test -C build SM3 --print-errorlogs`：通过；
- 修改前已运行完整套件：22/22 通过；
- 本次没有修改 `libs/paper_construct`，也没有撤销工作区原有的子模块指针变化。