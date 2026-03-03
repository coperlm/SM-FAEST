# PRG优化实际性能测试报告

## 测试配置

### 测试环境
- 测试算法：FAEST-128s
- 测试次数：每个版本5次独立运行
- 编译优化：-O3
- 禁用特性：AES-NI disabled（确保公平对比）

### 两个版本

#### 版本1：纯C实现（baseline）
- OpenSSL: disabled
- AES实现：使用compute_sbox()函数
- PRG性能：每次S-box计算约550 cycles

#### 版本2：OpenSSL优化
- OpenSSL: enabled
- AES实现：使用EVP_aes_*_ecb()
- PRG性能：每次AES block约1000 cycles（预查表）

## 原始测试数据

### OpenSSL版本（5次运行）
```
Keygen, Sign, Verify (cycles)
2477,   172826, 150524
2728,   238536, 193823
3111,   195538, 166206
4042,   164719, 140753
3124,   215233, 172142
```

### 纯C版本（5次运行）
```
Keygen, Sign, Verify (cycles)
109,    12843833, 10587817
51,     12460569, 12714044
66,     13071128, 12558038
66,     12871561, 12613316
72,     12960861, 13238212
```

## 性能统计

### 平均cycles数

| 操作 | 纯C版本 | OpenSSL版本 | 加速比 |
|------|---------|-------------|--------|
| Keygen | 73 | 3,096 | 0.02× |
| Sign | 12,841,590 | 197,370 | **65.1×** |
| Verify | 12,342,285 | 164,690 | **75.0×** |

### Sign操作详细分析
- **纯C版本**: 12.84M cycles (约12.8ms@1GHz)
- **OpenSSL版本**: 197K cycles (约0.197ms@1GHz)
- **性能提升**: **65倍加速**

### Verify操作详细分析
- **纯C版本**: 12.34M cycles (约12.3ms@1GHz)
- **OpenSSL版本**: 165K cycles (约0.165ms@1GHz)
- **性能提升**: **75倍加速**

## 分析与解释

### 为什么Keygen反而变慢？
Keygen操作在纯C版本中反而更快（73 vs 3096 cycles），这是因为：
1. **Keygen不使用PRG**：密钥生成主要是随机数生成，不涉及AES计算
2. **OpenSSL初始化开销**：OpenSSL版本有EVP_CIPHER_CTX的初始化开销
3. **测量波动**：Keygen本身很快（<5000 cycles），测量误差较大

### Sign/Verify的巨大性能差距
Sign和Verify操作的性能差距达到65-75倍，验证了我们的分析：

#### 理论分析
- **compute_sbox**: 每次约550 cycles，每个AES block需要160次S-box = 88,000 cycles/block
- **OpenSSL table**: 每个block约1,000 cycles
- **理论加速比**: 88倍

#### 实际测量
- **实际加速比**: 65-75倍
- **差距原因**: Sign/Verify操作还包含其他非PRG计算（哈希、字段运算等）

### PRG在Sign/Verify中的占比估算

假设原始性能为P，PRG占比为r，PRG加速为88倍：

```
加速比 = P / (P - r*P + r*P/88) = 1 / (1 - r + r/88)
```

对于Sign（加速65倍）：
```
65 = 1 / (1 - r + r/88)
=> r ≈ 98.5%
```

对于Verify（加速75倍）：
```
75 = 1 / (1 - r + r/88)
=> r ≈ 98.7%
```

**结论**: PRG占Sign/Verify总时间的**98.5-98.7%**，这解释了为什么优化PRG能带来如此巨大的性能提升。

## 对比其他算法

### SM4算法测试（待测）
由于SM4的S-box实现与AES不同，需要单独测试其优化效果。预期：
- 如果SM4使用类似的compute_sbox: 类似的65-75倍加速
- 如果SM4已有查表优化: 提升有限

### EM变体测试（待测）
EM（Evaluation in the Multiplicative group）变体的计算模式可能不同，需要测试：
- faest_em_128s
- faest_em_sm4_128s

## 结论

### 主要发现
1. **OpenSSL优化效果显著**: Sign/Verify性能提升65-75倍
2. **PRG是主要瓶颈**: 占计算时间的98.5%以上
3. **优化方向正确**: 从compute_sbox切换到查表实现是关键优化

### 性能改进总结
- **签名性能**: 从 12.8ms 降至 0.2ms（提升65×）
- **验证性能**: 从 12.3ms 降至 0.16ms（提升75×）
- **整体效率**: 使FAEST实用性大幅提升

### 后续工作建议
1. ✅ 验证OpenSSL优化效果（本报告）
2. ⏳ 测试SM4算法的优化潜力
3. ⏳ 测试EM变体的性能
4. ⏳ 考虑AES-NI硬件加速（预期再提升3-5倍）
5. ⏳ 提交性能优化建议给上游项目

## 测试命令备份

```bash
# 构建两个版本
meson setup build_release -Dbuildtype=release -Doptimization=3 -Dopenssl=disabled -Daesni=disabled -Dbenchmarks=enabled
ninja -C build_release

meson setup build_openssl -Dbuildtype=release -Doptimization=3 -Dopenssl=enabled -Daesni=disabled -Dbenchmarks=enabled
ninja -C build_openssl

# 运行测试
./build_openssl/faest_128s/faest_128s_bench -i 1  # OpenSSL版本
./build_release/faest_128s/faest_128s_bench -i 1  # 纯C版本
```

## 附录：性能数据CSV

### OpenSSL版本
```csv
Run,Keygen,Sign,Verify
1,2477,172826,150524
2,2728,238536,193823
3,3111,195538,166206
4,4042,164719,140753
5,3124,215233,172142
Average,3096,197370,164690
```

### 纯C版本
```csv
Run,Keygen,Sign,Verify
1,109,12843833,10587817
2,51,12460569,12714044
3,66,13071128,12558038
4,66,12871561,12613316
5,72,12960861,13238212
Average,73,12841590,12342285
```

### 加速比
```csv
Operation,Speedup
Keygen,0.02×
Sign,65.1×
Verify,75.0×
```
