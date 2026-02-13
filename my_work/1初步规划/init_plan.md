# VOLE结合国密

核心：FAEST的安全性主要依赖于AES和SHA-3，而SM-FAEST安全性依赖于SM4和SM3

（AES -> SM4 , SHA-3 -> SM3）

## FAEST是什么

FAEST 是密码学中一种较新的后量子数字签名方案。目前，它是NIST后量子密码学标准化项目中“额外签名方案”（第四轮/第二阶段）的候选算法之一。

核心卖点：如果你信任 AES 是安全的，那么 FAEST 就是安全的。

### 技术原理

利用VOLEitH实现。工作方式：签名者的私钥是一个 AES 密钥。签名的过程，实际上是生成一个非交互式的零知识证明，向验证者证明“我知道一个 AES 密钥，这个密钥可以将某个公开的明文加密成某个公开的密文”，但在这个过程中不泄露密钥本身。

### 方案特点

优点：

- 极小的密钥尺寸（基本上就是 AES 密钥和密文的大小）-> 适用于传输带宽受限、存储空间极小的场景。
- 安全性假设非常可靠（依赖于 AES 和  SHA-3 的安全性）

缺点：

- 相比于基于格的算法（如 Dilithium），FAEST 的签名文件比较大（通常在几 KB 到十几 KB 之间）。
- 速度较慢：签名和验证的速度比基于哈希或格的方案要慢。

### 参考论文

[CRYPTO 2023] Publicly Verifiable Zero-Knowledge and Post-Quantum Signatures From VOLE-in-the-Head：正式提出了 VOLE-in-the-Head 范式。论文展示了如何将基于 VOLE 的交互式零知识证明转换为非交互式，并利用它构造了基于 AES 的签名方案（后来演变为 FAEST）。这是理解 VOLEitH 的源头。

[CRYPTO 2025] Shorter, Tighter, FAESTer: Optimizations and Improved (QROM) Analysis for VOLE-in-the-Head Signatures：针对 VOLEitH 的旗舰应用 **FAEST** 签名算法进行了重要优化。论文改进了安全性分析（在量子随机预言机模型 QROM 下），并进一步减小了签名尺寸，提升了性能。

[ASIACRYPT 2024] One Tree to Rule Them All: Optimizing GGM Trees and OWFs for Post-Quantum Signatures：针对 VOLEitH 和 MPCitH 中核心的 "GGM Tree"（用于生成种子的树结构）进行了优化。这项工作直接减小了基于 VOLEitH 的签名（如 FAEST、KuMQuat）的大小。

[ASIACRYPT 2025] VOLE-in-the-Head Signatures from Subfield Bilinear Collisions：将 VOLEitH 范式应用于新的困难问题（子域双线性碰撞），构造了新的签名方案。这证明了 VOLEitH 不仅仅适用于 AES (FAEST)，还具有更广泛的通用性。

### SM4

相同点：都在$FG(2^8)$ 进行运算

不同点

|   | AES-128  | SM4  |
|---|---|---|
|  基本结构 | SPN  | Feistel  |
| 轮数  | 10 | 32  |
| 不可约多项式  | 0x11B  | 0x1F5  |

核心逻辑不同：

* AES 的逻辑：每一轮都包含四个步骤：字节代替（SubBytes）、行移位（ShiftRows）、列混合（MixColumns）和轮密钥加（AddRoundKey）。它像是一个整体的“搅拌机”。
* SM4 的逻辑：每一轮只对 128 位分组中的最后 96 位进行线性与非线性变换，然后与最前 32 位异或，结果滑动到下一轮。它更像是一个“滚动”的过程。

非线性复杂度对比 (决定签名大小和速度的关键)

FAEST 的签名大小和证明生成时间主要取决于电路中非线性门（AND 门或 S 盒）的数量。

AES-128:

- 轮数：10 轮。
- 每轮 S 盒：16 个。
- 密钥扩展 S 盒：40 个。
- 总 S 盒数量 ≈ 200 个。

SM4:

- 轮数：32 轮。
- 每轮 S 盒：4 个（因为是 Feistel 结构，每轮只处理 32 位）。
- 密钥扩展 S 盒：$32 times 4 = 128$ 个。
- 总 S 盒数量 = 128 (轮函数) + 128 (密钥扩展) = 256 个。

结论：SM4 的非线性复杂度（256 个 S 盒）略高于 AES-128（200 个 S 盒）。这意味着直接移植 FAEST 到 SM4，签名长度和证明时间可能会比 AES 版本增加约 25%-30%。

结构差异

- AES (SPN)：状态更新是全并行的。
- SM4 (Feistel)：状态更新是迭代的，但在电路表示中，这种迭代只是连线方式不同，对 ZK 的并行度影响不大（因为 ZKP 是验证整个 trace）。

一点思考：针对 Feistel 结构的 VOLE 优化

FAEST 主要是为 SPN 结构设计的。在 Feistel 结构中，每一轮只有 1/4 的状态经过 S 盒，另外 3/4 直接下传。是否能在 VOLE 的承诺阶段，利用这种“数据重用”来减少通信量？（例如，是否可以减少每一轮需要提交的 witness 数量？）

### SM3

SM3和SHA-2比较像，而SHA-3是可拓展的

安全等级限制：SM3 只能支撑 **128-bit** 后量子安全等级（对应 FAEST-128）。

解法：使用 **HMAC-SM3** 作为核心组件。HMAC 结构天生抵抗长度扩展攻击，且被广泛认为不仅是 PRF，也是良好的随机预言机模拟器。

## 包装

在论文的“绪论”部分，你需要为“为什么要用 SM4 做这个”找到合理的借口。不要只说“我想换个算法试试”，要拔高立意：

1. **后量子迁移需求**：强调 NIST 正在推进后量子签名标准（FAEST 是热门候选），而我国的国密标准（SM4）在未来的量子环境下也需要相应的零知识证明或签名方案。你的工作是**探索国密算法在后量子签名框架下的可行性**。

2. **自主可控**：目前的 FAEST 是基于 AES 的，深度依赖 AES 的电路结构。研究 SM4 在此框架下的表现，有助于评估国产算法在 MPCitH（基于多方计算的零知识证明）类协议中的性能边界。

**一句话总结你的工作**：本文基于 VOLE-in-the-Head 协议，设计并实现了面向 SM4 分组密码的零知识证明方案，并构造了抗量子签名算法。

## 存在的问题

- SM4 的zkP部分始终跑不通
- SM4 性能大概率比不上AES
- SM3是固定输出哈希函数，而SHAKE基于海绵结构