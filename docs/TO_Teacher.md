许老师您好：

近期我在阅读零知识证明方向相关的文献，结合实验室在区块链和云数据访问安全控制等方面的研究背景，我有了一个初步的选题构思，拟将其作为毕业论文开展研究，想请您把关。

选题背景与痛点：目前 NIST 正在推进基于 VOLE-in-the-Head 技术的后量子签名标准（如 FAEST 算法[1]）。这类方案因其签名尺寸极小、无需繁重的公钥运算，极其适合带宽受限的边缘计算和物联网场景。 然而，目前的国际主流方案完全依赖 AES 和 SHA-3，国内在“国密算法 + 高级零知识证明”的结合上尚属空白。特别是在未来的国密区块链隐私保护中，缺乏高效的底层证明方案。

我的计划是基于最新的 VOLE 技术 [2]，设计并实现一套**完全国产化（SM4/SM3）**的后量子签名协议。主要工作包括：

- 国产化替代：将 FAEST 框架底层的 AES/SHA-3 替换为 SM4/SM3，解决国密算法在 NIZK 中的适配问题。

- 结构优化：利用 SM4 的 Feistel 结构特性（不同于 AES 的全状态更新，SM4 每轮仅部分更新），减少 ZKP 通信开销的优化方案。

- 应用场景：该方案可直接应用于区块链的隐私交易验证或云环境下的轻量级身份认证，符合“自主可控”和“后量子迁移”的国家战略需求。

我此前已在组会汇报了文献 [1]，计划在文献 [2] 的开源代码基础上进行构建，后续考虑借鉴 [3] 的思路进一步优化签名大小。

不知您觉得这个切入点是否合适？我计划接下来先编写实验代码，跑出初步的对比数据。

期待您的指导！

附录：

[1] [CRYPTO 2023] Publicly Verifiable Zero-Knowledge and Post-Quantum Signatures from VOLE-in-the-Head (Authors: Carsten Baum, Lennart Braun, Cyprien Delpech de Saint Guilhem, et al.)

[2] [CRYPTO 2025] Shorter, Tighter, FAESTer: Optimizations and Improved (QROM) Analysis for VOLE-in-the-Head Signatures (Authors: Carsten Baum, Ward Beullens, Lennart Braun, et al.)

[3] [ASIACRYPT 2024] One Tree to Rule Them All: Optimizing GGM Trees and OWFs for Post-Quantum Signatures (Authors: Carsten Baum, Ward Beullens, Shibam Mukherjee, et al.)