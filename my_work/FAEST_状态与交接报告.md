# FAEST 项目状态与交接报告（可用性/运行方法/问题归因）

> 目标：给出当前仓库 **哪些能用、哪些不能用、怎么运行、为什么不能用、怎么继续排查** 的可交接结论。

---

## 1. 本次核验范围与结论摘要

### 1.1 核验范围
- 工作区：`/home/coper/桌面/faest-ref`
- 主要构建目录：`build/`、`build_release/`
- 核验方式：
  - 读取构建与测试配置：`README.md`、`meson.build`、`tests/meson.build`
  - 运行关键单测与 Meson 分组测试
  - 对比 debug 构建与 release 构建表现

### 1.2 一句话结论
- **可用**：AES 路径、FAEST_128S 路径、SM4 原语/约束/OWF/PRG 基础测试；`build_release` 编译链已恢复。
- **不可用**：FAEST_SM4_128S（签名与 API 集成层）。
- **失败范围集中在 SM4 参数集的“端到端签验/证明集成层”，不是 SM4 原语本身。**

---

## 2. 文件架构（面向排障的最小必要视图）

## 2.1 顶层关键源码
- `faest_impl.c/.h`：FAEST 核心实现与公共流程。
- `faest_aes.c.in`、`faest_sm4.c`：按参数集/底层分组的签名相关实现。
- `sm4.c/.h`：SM4 基础实现、轮密钥、PRG、见证扩展等底层能力。
- `owf.c/.h`、`owf_sm4.c/.h`：OWF 路径（AES/SM4）。
- `vole.c/.h`、`bavc.c/.h`、`random_oracle.c/.h`：证明系统相关基础组件。
- `instances.c/.h`、`faest_param*.in`：参数集实例定义。

### 2.2 构建与测试组织
- `meson.build`：全局构建配置、参数集注册、依赖/编译选项。
- `tests/meson.build`：测试目标映射（模块测试、参数集测试、API 测试）。
- `build/tests/test_extended_tests`：Boost 扩展测试可执行入口。

### 2.3 关键构建产物目录
- `build/`：当前主要可执行核验目录（能完成构建并运行多数测试）。
- `build_release/`：已恢复可编译并可执行 FAEST_128S/AES 测试。

---

## 3. 哪些能用（含可复现命令）

> 以下命令均在仓库根目录执行。

### 3.1 构建（debug 构建目录）
```bash
meson setup build
ninja -C build
```

### 3.2 核心模块测试：可用
```bash
meson test -C build AES SHAKE Utils BAVC VOLE --print-errorlogs
```
结果：**5/5 全通过**。

### 3.3 SM4 原语/约束/OWF/PRG：可用
```bash
meson test -C build SM4 SM4_Constraints OWF_SM4 PRG_SM4 --print-errorlogs
```
结果：**4/4 全通过**。

### 3.4 FAEST_128S：可用
```bash
./build/tests/test_extended_tests --run_test=faest_128s/test_sign
meson test -C build FAEST_128S --print-errorlogs
meson test -C build faest_128s_api_test --print-errorlogs
```
结果：均通过（签名用例、参数集、API 测试均可运行）。

---

## 4. 哪些不能用（失败证据 + 影响范围）

### 4.1 FAEST_SM4_128S 签名路径失败
```bash
./build/tests/test_extended_tests --run_test=faest_sm4_128s/test_sign
./build/tests/test_extended_tests --run_test=faest_sm4_128s/test_unpacked_sign
meson test -C build FAEST_SM4_128S --print-errorlogs
meson test -C build faest_sm4_128s_api_test --print-errorlogs
```
结果：均失败（exit 201 / 255），日志末尾可见多处失败统计（如“6 failures”）。

### 4.2 release 构建链状态（已修复）
```bash
meson test -C build_release FAEST_128S FAEST_SM4_128S --print-errorlogs
```
此前失败原因为：
- `sm4.c` 中 `sm4_extend_witness` 函数报错：`'w_out' undeclared`（`w_out` 定义与使用的宏条件不一致）。

当前状态：
- 编译阻断已修复；`ninja -C build_release` 可完成。
- `meson test -C build_release FAEST_128S faest_128s_api_test AES --print-errorlogs` 为 **3/3 PASS**。
- `FAEST_SM4_128S` 仍失败（问题已收敛到 SM4 集成逻辑，不再是编译链问题）。

---

## 5. 不能用的可能原因（按“确定性”分级）

## 5.1 已确认根因（高确定性）

### A. debug 宏与 release 宏组合导致编译错误（确定）
现象：`sm4.c` 中
- `w_out` 在 `#if !defined(NDEBUG)` 条件下定义；
- 但在 `#if defined(FAEST_SM4_DEBUG)` 的日志语句中被使用。

当 release 构建启用 `NDEBUG` 且仍编译到 `FAEST_SM4_DEBUG` 日志时，`w_out` 不存在，触发编译失败。

该问题已通过统一条件修复：将 `w_out` 的定义条件调整为与使用条件一致（均以 `FAEST_SM4_DEBUG` 为准）。

### B. 工作区当前不是“干净基线”（中高确定）
`git status --short` 显示：
- `M .gitignore`
- `D vole.c.bak`
- `D vole.h.bak`

说明当前代码状态与原始上游/稳定基线可能不一致，增加了复现偏差风险。

## 5.2 高概率原因（需要继续验证）

### C. SM4 端到端失败发生在“证明集成层”而非“原语层”
证据链：
- SM4 原语相关测试（SM4 / Constraints / OWF / PRG）通过；
- 但 `FAEST_SM4_128S` 签名、unpacked 签名、API 全部失败。

推断：
- 失败更可能位于 `faest_sm4.c` 与 `sm4_extend_witness`、约束组装、challenge/commit 对齐等集成逻辑。
- 即“底层块算法能算，但进入完整证明流程后不一致”。

### D. 大量 `SM4_DEBUG` 日志掩盖关键失败点
当前日志以千行级哈希/中间态输出为主，导致关键断点信息（首个不一致位置）被淹没，降低定位效率。

---

## 6. 推荐调试手段（按投入/收益排序）

## 6.1 先恢复可对比基线（必须）
1. 备份当前工作区（避免丢现场）。
2. 清理/对齐本地改动，确保只保留“待分析最小改动集”。
3. 在干净基线上重复第 3、4 节命令，确认问题可稳定复现。

## 6.2 release 链已恢复，保留回归命令（已完成）
已完成项：
- 已修复 `sm4.c` 中 `w_out` 的条件编译可见性问题。
- `build_release` 可编译且可执行基线测试。

建议持续回归命令：
```bash
ninja -C build_release
meson test -C build_release FAEST_128S FAEST_SM4_128S --print-errorlogs
```

## 6.3 将 SM4 调试日志从“全量”改为“首错即停”
建议：
- 增加“仅在首次 mismatch 时打印上下文”的开关；
- 默认关闭逐步轮次日志；
- 输出固定最小集合：轮次、字节偏移、期望值、实际值、上游输入摘要。

预期收益：显著减少日志噪声，快速锁定第一处偏差。

## 6.4 使用二分法定位集成断点
建议顺序：
1. 固定随机种子（确保可复现）。
2. 在 `faest_sm4.c` 的 prover/verifier 关键阶段分别做一致性断言：
   - witness 生成后
   - 约束编码后
   - challenge 派生后
   - 最终 q
tilde / q* / a0
tilde 对比前
3. 从“最后成功阶段”与“第一失败阶段”之间做二分缩小范围。

## 6.5 最小化回归命令集（建议做成脚本）
```bash
# 1) 基础健康检查
meson test -C build AES SHAKE Utils BAVC VOLE SM4 SM4_Constraints OWF_SM4 PRG_SM4 --print-errorlogs

# 2) 参数集检查
meson test -C build FAEST_128S FAEST_SM4_128S --print-errorlogs

# 3) API 检查
meson test -C build faest_128s_api_test faest_sm4_128s_api_test --print-errorlogs
```

---

## 7. 交接建议：下一位同学的执行清单

### P0（当天完成）
- （已完成）修复 `build_release` 的 `w_out` 编译错误。
- 在干净基线上跑通“最小化回归命令集”，保存完整日志。

### P1（1~2 天）
- 在 SM4 集成路径加入“首错定位”日志策略。
- 锁定第一处 prover/verifier 不一致点。

### P2（后续）
- 增加一条“SM4 集成一致性”的轻量回归测试（避免同类回归再次进入主干）。

---

## 8. 附：本次关键命令与观测（摘要）

- `meson test -C build AES SHAKE Utils BAVC VOLE --print-errorlogs` → **5/5 PASS**
- `meson test -C build SM4 SM4_Constraints OWF_SM4 PRG_SM4 --print-errorlogs` → **4/4 PASS**
- `meson test -C build FAEST_128S FAEST_SM4_128S --print-errorlogs` → `FAEST_128S PASS`，`FAEST_SM4_128S FAIL`
- `meson test -C build faest_128s_api_test faest_sm4_128s_api_test --print-errorlogs` → 前者 PASS，后者 FAIL
- `meson test -C build FAEST_128S faest_128s_api_test AES --print-errorlogs` → **3/3 PASS**
- `meson test -C build_release FAEST_128S faest_128s_api_test AES --print-errorlogs` → **3/3 PASS**
- `ninja -C build_release` → 编译恢复成功（`w_out` 问题已修复）

---

## 9. 当前可交付结论

- 你现在可以继续使用：
  - FAEST_128S 相关功能与测试；
  - 原始 FAEST（AES 路径）在 `build` 与 `build_release` 的编译与测试；
  - SM4 原语与基础组件测试。
- 你现在不应依赖：
  - FAEST_SM4_128S 端到端签验/API。
- 若目标是“尽快恢复可迭代调试”：
  - **清理日志策略 + 锁定首个 mismatch**，比继续堆日志更有效。
