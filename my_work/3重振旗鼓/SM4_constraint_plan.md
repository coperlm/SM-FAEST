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

## 待办（本次需要完成）
1) 以“直接 S-box 约束”替换当前“逆仿射 + 逆范数”路径。
2) 调整并固化 witness 布局（加密部分），确保 Prover/Verifier 一致。
3) 按更新后的约束链路重跑 `faest_sm4_128s_api_test`。

## 方案选项
- 方案 A（推荐）：S-box 查表约束
  - Prover：对每个字节直接查表 `sbox(temp_byte)`；将结果作为 witness（或存储在偶数轮/密钥扩展对应位置）。
  - Verifier：对 256 元素表做同态约束（可用 8-bit 选择信号或分段查表；需 8-bit one-hot/累加）。
  - 优点：实现最快，约束清晰；缺点：查表电路略大但仍可接受（32 轮 × 4 字节）。


## 具体实施（按方案 A，直接 S-box 约束）
### 1) 数据路径与约束链路（关键改动）
- 密钥扩展（位于 [faest_sm4.c](../../faest_sm4.c)）：
  - 继续用现有链路得到 `tau = L'^-1(T'(X))`，其中 `X = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]`。
  - 将“逆仿射 + 逆范数约束”替换为“直接 S-box 约束”：逐字节约束 `tau == sbox(X)`。
  - `T'(X)`、`K[i+4]` 的计算逻辑保持不变，仅替换 S-box 约束部分。
- 加密轮（位于 [faest_sm4.c](../../faest_sm4.c)）：
  - 奇数轮：
    - `temp = state[1] ^ state[2] ^ state[3] ^ rk[i]`。
    - 从 witness 读取 `sbox_out`（4 字节），约束 `sbox_out == sbox(temp)`。
    - `L_out = L(sbox_out)`，生成新字并更新状态。
  - 偶数轮：
    - 仍通过 witness 状态推 `L_out = new_word ^ state[0]`，再用 `L^-1` 得 `sbox_out`。
    - 约束 `sbox_out == sbox(temp)`（不再走逆仿射/逆范数）。

### 2) witness 布局（保持 20 字节/2 轮不变）
- 加密部分（见 [sm4.c](../../sm4.c) 的 `sm4_extend_witness`）：
  - 奇数轮：存 `sbox_out`（4 字节，逐字节 `sm4_sbox(temp_byte)`）。
  - 偶数轮：存完整状态（16 字节），第 32 轮仍用公开输出反序替代。
  - 每对轮结构保持 `4 + 16 = 20` 字节，因此 `params->l` 不需改。
- 密钥扩展部分：
  - witness 结构保持现状（`K[0..3]` 和挑选的 `rk` 字），不新增额外数据。
  - 通过 `L'^-1` 得到 `tau` 后直接做 S-box 约束，避免增加 `Lke`。

### 3) S-box 约束实现（新增函数）
- 新增字节级约束函数：
  - `sm4_SSS_sbox_lookup_byte_prover(...)`
  - `sm4_SSS_sbox_lookup_byte_verifier(...)`
- 约束思路（推荐版本）：
  - 基于 8-bit one-hot（256 选 1）或 4-bit 分段查表（16x16）。
  - 输出约束：$y = \sum_i sel_i * SBOX[i]$，其中 `sel_i` 为输入字节 `x` 的选择信号。
  - Verifier 端需处理常数项的 delta 注入，确保 `sel_i` 与 `x` 的 bit 一致。
- 若担心电路过大，可先实现 4-bit 分段查表版：
  - `x = (hi << 4) | lo`，先查 `SBOX_HI[hi][lo]` 或预分解表，减少 one-hot 规模。

### 4) 替换与清理
- 在 [faest_sm4.c](../../faest_sm4.c) 中：
  - `sm4_SSS_expkey_constraints_*` 与 `sm4_SSS_enc_constraints_*` 中移除：
    - `sm4_SSS_inverse_affine_*`
    - `sm4_SSS_inv_norm_*`
    - `sm4_SSS_inv_norm_to_conjugates_*`
  - 相关函数可先保留实现但不再调用，或使用宏开关隔离。
- 在 [sm4.c](../../sm4.c) 中：
  - `sm4_extend_witness` 不再写 `sm4_invnorm(sm4_sbox(...))`，改为写 `sm4_sbox(...)`。
  - `sm4_invnorm` 若无引用可保留静态函数，避免改动过大。

### 5) 验证与性能测试
- 构建与测试：
  - `ninja -C build faest_sm4_128s_api_test && cd build && meson test faest_sm4_128s_api_test --verbose`
- 若测试失败：
  - 重点检查 witness 偏移是否仍为 `20 * r_pair`。
  - 检查奇/偶轮 `temp` 与 `sbox_out` 的 byte 对齐是否一致。
  - 检查第 32 轮公开输出反序拷贝逻辑是否保持不变。

## 风险与检查点
- 查表电路需确保 Verifier 侧 delta 处理正确（常数项与选择信号的 delta 组合）。
- witness 偏移和轮序号对应关系需逐字节核对，避免 off-by-one。
- 若查表电路过大导致性能问题，可改为 4-bit nibble 分段查表或 bitslice。

如果按本文执行，建议顺序为：先改 witness（奇数轮改写 S-box 输出）→ 替换约束链路 → 运行测试。