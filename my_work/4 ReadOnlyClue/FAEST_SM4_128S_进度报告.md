# FAEST_SM4_128S 专项进度报告

> 范围仅针对 `FAEST_SM4_128S` 参数集，不覆盖 AES 参数集修复内容。

---

## 1. 当前状态（截至本次）

- 状态：**未通过**（端到端签名与 API 集成测试失败）。
- 影响范围：
  - `faest_sm4_128s_api_test` 失败；
  - `FAEST_SM4_128S` 失败（`test_extended_tests -t faest_sm4_128s`）。
- 非影响范围：
  - SM4 原语层测试通过（`SM4` / `SM4_Constraints` / `OWF_SM4` / `PRG_SM4`）。
  - AES/FAEST_128S 路径通过（已单独验证）。

---

## 2. 本轮已完成进展

### 2.1 修复了与 SM4 相关的编译阻断（非逻辑正确性）
- 文件：`sm4.c`
- 位置：`sm4_extend_witness(...)`
- 问题：`w_out` 在 `!NDEBUG` 下定义，却在 `FAEST_SM4_DEBUG` 日志分支使用。
- 结果：已修复条件编译一致性，`build_release` 恢复可编译。

### 2.2 重新验证了“原始 FAEST 是否被连带破坏”
- `meson test -C build FAEST_128S faest_128s_api_test AES --print-errorlogs`：**3/3 PASS**
- `meson test -C build_release FAEST_128S faest_128s_api_test AES --print-errorlogs`：**3/3 PASS**

结论：本次修复未破坏原始 FAEST（AES 路径）。

### 2.3 深入调试 FAEST_SM4_128S 验证失败
- 启用了 `FAEST_SM4_DEBUG` 宏，获取详细中间态输出。
- 添加了诊断打印：prover 的 v_star0/1 和 verifier 的 bf_delta, q_star_0/1。
- 确认根因：prover 和 verifier 的 q_star 值不匹配，导致 post-delta 检查失败（match ~1300/5120）。
- 尝试修复：
  - 切换位提取端序（小端到大端）。
  - 应用字节/字排列（基于启发式最佳配置）。
  - 调整行映射（使用 sm4_map_row_to_word_swap）。
  - 修改 d_bit 提取端序。
- 结果：q_star 仍不匹配，post-delta 匹配率未显著改善（未达预期 81/128）。
- 验证：禁用调试输出后问题仍存，确认非日志影响。

### 2.4 验证 SM4 原语层稳定性
- `meson test -C build SM4 SM4_Constraints OWF_SM4 PRG_SM4 --print-errorlogs`：**4/4 PASS**
- 结论：问题位于集成层（prover/verifier 一致性），非原语层。

---

## 3. 仍未解决的问题（FAEST_SM4_128S）

### 3.1 失败复现命令
```bash
meson test -C build FAEST_SM4_128S faest_sm4_128s_api_test --print-errorlogs
```

### 3.2 失败表现
- `faest_sm4_128s_api_test` 失败（exit 255）。
- `FAEST_SM4_128S` 失败（exit 201），日志尾部可见 `6 failures`。
- 日志显示 q_star prover/verifier 不匹配，以及大量 post-delta 不匹配（match ~1300/5120）。

### 3.3 当前定位结论
- 根因：prover 和 verifier 的 q_key 不同，导致 q_star_0/1 计算不一致。
- 可能原因：column_to_row_major_and_shrink_V_128_sm4 的转换逻辑有误（位/字节/字端序或排列）。
- 启发式证据：某些排列可改善匹配至 81/128，但未在代码中重现。
- 排除：非 SM4 原语问题，非调试输出影响。

---

## 4. 风险与阻塞点

- 阻塞 1：日志过量（千行级）导致“首个错误点”难以识别。
- 阻塞 2：当前缺少“阶段边界一致性断言”来快速切分失败区间。
- 阻塞 3：转换函数排列尝试未达预期改善，需更系统化方法。

---

## 5. 下一步建议（按优先级）

### P0（先做）
1. 将 `SM4_DEBUG` 改为“首错即停 + 固定最小字段输出”。
2. 在 `faest_sm4.c` 中添加阶段边界检查：
   - witness 后
   - constraints 后
   - challenge 后
   - 最终比对前

### P1（随后）
1. 以固定随机种子重复 `FAEST_SM4_128S` 测试。
2. 使用二分法定位“最后正确阶段”与“第一错误阶段”。
3. 实现代码中的排列搜索，自动找到最佳字节/字/位配置。

### P2（收敛）
1. 为 `FAEST_SM4_128S` 加入轻量一致性回归（防止同类回归）。

---

## 6. 建议交接命令集

```bash
# A. 先确认基础层健康
meson test -C build SM4 SM4_Constraints OWF_SM4 PRG_SM4 --print-errorlogs

# B. 再复现集成层失败
meson test -C build FAEST_SM4_128S faest_sm4_128s_api_test --print-errorlogs

# C. 对照原始 FAEST 基线
meson test -C build FAEST_128S faest_128s_api_test AES --print-errorlogs
meson test -C build_release FAEST_128S faest_128s_api_test AES --print-errorlogs
```

---

## 7. 结论

- `FAEST_SM4_128S` 目前是**集成正确性问题**，具体为 prover/verifier q_key 不一致，导致 q_star 和 post-delta 失败。
- 原始 FAEST（AES 路径）已验证通过，可继续作为稳定基线。
- 建议下一阶段集中做“首错定位”和“排列优化”而非继续扩大日志。