# SM4 稳定性问题修复报告

## 问题描述

在之前的版本中，SM4算法的成功率不稳定，约为86-88%，而AES已经通过cbf95c5提交修复到100%。

## 根本原因分析

### 历史演进

1. **原始版本 (cb6bb8a)**
   - AES-128s: 100% 成功率 ✅
   - 使用简单逻辑: `if (!ptr_get_bit(s, i))`
   - 没有SM4支持

2. **引入SM4后 (a939991)**
   - 添加了SM4实现
   - 添加了双子节点清除workaround（无条件，影响所有算法）
   - 这时AES和SM4都出现了稳定性问题

3. **Bug引入 (66621ca)**
   - 给双子节点清除添加了 `params_is_sm4()` 条件（正确）
   - 但同时引入了**根节点强制展开**逻辑：`i == 0 || !ptr_get_bit(s, i)`（无条件）
   - 这导致AES和SM4都降到~85%成功率

4. **AES修复 (cbf95c5)**
   - 添加SM4条件：`(params_is_sm4(params) && i == 0) || !ptr_get_bit(s, i)`
   - AES恢复到100%
   - SM4仍然86-88%

5. **SM4修复 (4be1768 - 本次提交)**
   - 发现根节点强制展开完全不需要
   - 恢复原始简单逻辑：`if (!ptr_get_bit(s, i))`
   - 所有算法都达到100%

### 关键发现

用户的观察"我记得最一开始AES和SM4的失误率高度一致"指向了正确的方向：

- **共同根源**：66621ca引入的无条件根节点强制展开影响了所有算法
- **AES的修复方向错误**：cbf95c5添加了条件判断，虽然修复了AES，但这个workaround本身就不应该存在
- **正确的解决方案**：完全移除根节点强制展开，回归原始简单逻辑

### 代码修改

**bavc.c 第343-347行（之前）：**
```c
for (unsigned int i = 0; i != L - 1; ++i) {
  /* SM4 workaround: root node (i==0) always needs expansion when using SM4 
   * so that k1 is available; for AES, use original logic. Other internal 
   * nodes are only expanded if their subtree contains no known leaves (s bit zero). */
  if ((params_is_sm4(params) && i == 0) || !ptr_get_bit(s, i)) {
    prg_2_lambda(keys + i * lambda_bytes, iv, i, keys + (2 * i + 1) * lambda_bytes, lambda);
  }
}
```

**bavc.c 第343-347行（修复后）：**
```c
for (unsigned int i = 0; i != L - 1; ++i) {
  /* Only expand internal nodes if their subtree contains no known leaves (s bit zero).
   * Original simple logic works for both AES and SM4. */
  if (!ptr_get_bit(s, i)) {
    prg_2_lambda(keys + i * lambda_bytes, iv, i, keys + (2 * i + 1) * lambda_bytes, lambda);
  }
}
```

## SM4特定的Workaround

SM4算法**确实需要**一些特殊处理，但不是根节点强制展开。以下workaround在修复后仍然保留：

### 1. 双子节点位清除 (bavc_open函数，第278-283行)

```c
if (params_is_sm4(params)) {
  for (unsigned int i = 0; i < L - 1; ++i) {
    if (ptr_get_bit(s, 2*i+1) && ptr_get_bit(s, 2*i+2)) {
      ptr_clear_bit(s, i);
    }
  }
}
```

### 2. 双子节点位清除 (reconstruct_keys函数，第328-333行)

```c
if (params_is_sm4(params)) {
  for (unsigned int i = 0; i < L - 1; ++i) {
    if (ptr_get_bit(s, 2*i+1) && ptr_get_bit(s, 2*i+2)) {
      ptr_clear_bit(s, i);
    }
  }
}
```

**作用**：在prover和verifier两侧都清除父节点位，当两个子节点都被标记时，强制PRG展开填充它们。这防止验证器跳过复制和PRG操作，避免子密钥为零。

## 测试结果

### 修复前
- AES-128s: 100% ✅
- AES-EM-128s: 100% ✅
- SM4-128s: 86% ❌
- SM4-EM-128s: 88% ❌

### 修复后 (100次迭代测试)
- AES-128s: 100/100 = 100% ✅ (平均 336ms)
- AES-EM-128s: 100/100 = 100% ✅ (平均 143ms)
- SM4-128s: 100/100 = 100% ✅ (平均 1409ms)
- SM4-EM-128s: 100/100 = 100% ✅ (平均 512ms)

## 性能观察

- **EM模式优势**：EM变体比标准模式快2-3倍
  - AES: 336ms → 143ms (2.4倍)
  - SM4: 1409ms → 512ms (2.8倍)

- **SM4 vs AES**：SM4比AES慢约4倍
  - 标准模式: 1409ms vs 336ms (4.2倍)
  - EM模式: 512ms vs 143ms (3.6倍)

## 结论

1. **根本问题**：66621ca引入的无条件根节点强制展开破坏了BAVC树遍历逻辑
2. **修复方法**：恢复原始的简单逻辑，这对AES和SM4都适用
3. **SM4需求**：SM4只需要双子节点位清除workaround，不需要根节点特殊处理
4. **最终结果**：所有4种算法变体都达到100%稳定性

## 提交信息

- **提交哈希**: 4be1768
- **提交消息**: "fix: Remove unnecessary root node expansion - restore original logic"
- **修改文件**: bavc.c (3行插入，4行删除)
- **验证**: verify_all_algorithms.sh (100次测试每个算法)

---
*报告生成时间: 2026-03-03 14:58*
*测试平台: build_release*
