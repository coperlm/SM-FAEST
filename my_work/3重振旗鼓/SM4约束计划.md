# SM4 约束修复记录

## 已完成
- 确认现有逆仿射路径存在根本问题：`invnorm(sbox(x)) * x == 1` 在 SM4 域内成立，但 `sbox(x)` 不是 GF(2) 上的仿射变换（对 `inv(x)` 求解无解）。
- 脚本 `my_work/tmp_sm4_check.py`：
  - 自动解析 `sm4.c` 的 S-box 和 `tools/sm4_invnorm_table.txt` 的 invnorm 表。
  - 验证乘法关系零失败。
  - 证明不存在仿射映射（`affine_exists: False`）。
- 代码现状（关键改动）：
  - witness 中的 K[0..3] 存储 `MK ^ FK`；safety check 反推 MK 后加密校验。
  - 第 32 轮偶数轮使用公开输出状态；标签顺序已调换为反序复制。
  - 逆仿射 Verifier 常数改为 `L^-1(0xD3)=0x34`（位 2/4/5）。
  - 调试日志已添加在 prover/verifier a0_tilde / q_tilde 处。

## 待办
1) 用直接 S-box 约束替换“逆仿射 + 逆范数”路径。
2) 重写 witness 布局以适配新约束。
3) 重跑 `faest_sm4_128s_api_test` 验证。

## 方案选项
- 方案 A（推荐）：S-box 查表约束
  - Prover：对每个字节直接查表 `sbox(temp_byte)`；将结果作为 witness（或存储在偶数轮/密钥扩展对应位置）。
  - Verifier：对 256 元素表做同态约束（可用 8-bit 选择信号或分段查表；需 8-bit one-hot/累加）。
  - 优点：实现最快，约束清晰；缺点：查表电路略大但仍可接受（32 轮 × 4 字节）。

- 方案 B：布尔电路 / bitslice S-box
  - 将 SM4 S-box 转成门级电路，对每位建立 AND/XOR 约束。
  - 优点：无查表；缺点：实现量大、易出错、调试重。

当前倾向：方案 A。

## 具体实施（按方案 A）
1) 数据路径调整
   - 密钥扩展：
     - 计算 `temp = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]`。
     - 直接约束 `tau = sbox(temp)`（逐字节），然后过 `L'` 得 `T'(temp)`，再与 `K[i]` 异或得到 `K[i+4]`。
   - 加密轮：
     - 奇/偶轮均直接约束 `sbox(temp)`，然后过 `L`。

2) witness 布局调整（每两轮 20 字节需改）
   - 奇数轮：不再存 inverse-norm，改存 S-box 输出（4 字节）或 `L(sbox(temp))`（4 字节）；选择一种并保持 prover/verifier一致。
   - 偶数轮：继续存完整状态 16 字节；第 32 轮使用公开输出反序。
   - 重新计算 `l` / `Lenc` 需求（如果改为存 4 字节 S-box 输出，可保持 20 字节结构：4+16）。

3) 约束实现要点
   - 新增 `sm4_SSS_sbox_lookup_prover/verifier`（字节级，支持 tag/delta）。
   - 移除/旁路 `sm4_SSS_inverse_affine_*`、`inv_norm`、`conjugates` 相关调用，但保留辅助函数以防编译引用，或用宏隔离。
   - 更新 key-exp / enc 约束中的调用链与 witness 偏移。
   - 确认 `params->Lke`、`params->l` 未超界；若布局不变则无需改参数。

4) 测试
   - `ninja -C build faest_sm4_128s_api_test && cd build && meson test faest_sm4_128s_api_test --verbose`

## 风险与检查点
- 查表电路实现需确保 Verifier 侧 delta 处理正确（常数项为 0，只有选择信号 × delta）。
- witness 偏移和轮序号对应关系需逐字节核对，避免 off-by-one。
- 若查表电路过大导致性能问题，可改为 4-bit nibble 分段查表或 bitslice。

如果要按文档执行，建议先实现 S-box 查表约束并调整 witness 布局，再跑 faest_sm4_128s_api_test。