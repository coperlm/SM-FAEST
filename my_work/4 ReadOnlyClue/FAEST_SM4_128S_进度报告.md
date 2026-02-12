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

---

## 3. 仍未解决的问题（FAEST_SM4_128S）

### 3.1 失败复现命令
```bash
meson test -C build FAEST_SM4_128S faest_sm4_128s_api_test --print-errorlogs
```

### 3.2 失败表现
- `faest_sm4_128s_api_test` 失败（exit 255）。
- `FAEST_SM4_128S` 失败（exit 201），日志尾部可见 `6 failures`。
- 日志出现 `q_star` 与 `q_tilde` 不一致，以及大量 `SM4_DEBUG` 中间态输出。

### 3.3 当前定位结论
- 更可能是 `FAEST_SM4_128S` 的 prover/verifier 集成一致性问题（见证扩展、约束拼装、挑战绑定、最终对比链路之一）。
- 不是“SM4 基础算法不可用”导致。

---

## 4. 风险与阻塞点

- 阻塞 1：日志过量（千行级）导致“首个错误点”难以识别。
- 阻塞 2：当前缺少“阶段边界一致性断言”来快速切分失败区间。
- 阻塞 3：工作区非完全干净（`.gitignore` 修改、若干 `.bak` 删除）会增加回归比较噪声。

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

- `FAEST_SM4_128S` 目前是**集成正确性问题**，不是编译链问题，也不是 SM4 原语问题。
- 原始 FAEST（AES 路径）已验证通过，可继续作为稳定基线。
- 建议下一阶段集中做“首错定位”而非继续扩大日志。