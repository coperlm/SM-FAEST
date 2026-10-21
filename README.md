# SM-FAEST：基于 SM4/SM3 的 FAEST 实现

本仓库是论文 **SM-FAEST** 的配套代码。论文的核心工作是在 FAEST 签名框架和证明结构保持基本不变的前提下，将原始 FAEST 中使用的 **AES 与 SHAKE** 替换为面向国密环境的 **SM4 与 SM3**，从而构造基于 SM4/SM3 的后量子签名方案，并对其正确性、签名尺寸和运行性能进行实验评估。

仓库同时保留原始 AES/SHAKE 路径，作为实现对照和实验基线。换言之，本项目不是重新设计一个独立的签名协议，而是围绕 FAEST 框架完成底层密码组件的替换、参数适配、协议接口衔接、测试向量生成和性能验证。

> **项目定位**
>
> 这是论文研究与实验复现代码，不是面向生产环境发布的通用密码库。代码的主要用途是复现论文结果、验证 SM4/SM3 替换后的 FAEST 实现，以及比较 AES/SHAKE 与 SM4/SM3 路径的行为和性能。

## 论文创新点

FAEST 是一种基于 VOLE-in-the-head 等技术构造的后量子签名方案。原始实现的主要密码组件包括 AES 和 SHAKE。本项目的主要创新是：

1. **底层分组密码替换**：将 FAEST 中的 AES 路径适配为 SM4，形成 `FAEST-SM4-128s` 和 `FAEST-EM-SM4-128s` 参数集；
2. **哈希和扩展组件替换**：将原有 SHAKE 相关路径适配为 SM3/SM3-XOF，用于国密算法环境下的哈希、随机预言机及相关扩展操作；
3. **协议与参数适配**：针对 SM4 的轮数、密钥扩展和约束表示重新组织 witness、OWF、PRG 等组件，并同步调整参数和签名布局；
4. **实现与实验验证**：补充 SM4、SM3、SM4 约束、SM4-OWF、SM4-PRG 以及端到端签名测试，并提供性能对比脚本。

仓库中的 AES/SHAKE 参数集并非论文创新本身，而是用于验证替换前后的接口一致性，并为实验提供可重复的基准。

## 参数集

当前实现包含四组 128-bit 安全级别的参数集。每组参数集的公钥和私钥均为 32 字节；签名长度以当前源码中的参数配置为准。

| 参数集 | 密码组件 | 作用 | 公钥 | 私钥 | 签名 |
| --- | --- | --- | ---: | ---: | ---: |
| `faest_128s` | AES + SHAKE | 原始 FAEST 对照组 | 32 B | 32 B | 4506 B |
| `faest_em_128s` | AES/Even-Mansour + SHAKE | EM 对照组 | 32 B | 32 B | 3890 B |
| `faest_sm4_128s` | SM4 + SM3 | 论文主要方案 | 32 B | 32 B | 8202 B |
| `faest_em_sm4_128s` | SM4/Even-Mansour + SM3 | EM 方案对照 | 32 B | 32 B | 4682 B |

其中 `EM` 表示 Even-Mansour 变体。SM4 参数集的内部 witness 布局和签名长度与 AES 参数集不同，因此论文中的尺寸、性能和安全参数应以当前代码生成的 `api.h`、`parameters.h` 及 `meson.build` 为准。

## 仓库内容

实现覆盖以下层次：

- **签名接口**：密钥生成、签名、验证和消息恢复；
- **FAEST 协议层**：核心证明、验证和签名流程；
- **SM4 路径**：SM4 分组密码、SM4 密钥扩展、SM4-OWF、SM4-PRG 及约束计算；
- **SM3 路径**：SM3 摘要、SM3-XOF、随机预言机及相关扩展；
- **通用组件**：有限域运算、通用哈希、BAVC、VOLE 和 OWF；
- **对照路径**：AES、SHAKE 及原始 FAEST 参数集；
- **实验工具**：API 测试、组件测试、测试向量生成器和性能基准。

## 依赖环境

### 必需工具

- Meson `>= 0.59`；
- Ninja；
- 支持 C11 的 C 编译器；
- 支持 C++17 的 C++ 编译器；
- Python 3；
- OpenSSL（默认启用，主要用于随机数及部分测试向量目标）。

GCC、Clang 和 Visual Studio 均可用于构建，但 AES-NI、AVX2 和其他平台指令集优化是否可用取决于编译器和目标机器。

### 可选依赖

- Boost：C++ 组件测试和普通基准程序；
- Catch2：Catch2 基准程序；
- NTL：有限域测试；
- Valgrind：内存检查和相关分析；
- Doxygen：API 文档；
- `bc`、`jq`、`timeout`：运行统一性能脚本。

Ubuntu/Debian 示例：

```bash
sudo apt update
sudo apt install -y \
  meson ninja-build gcc g++ python3 libssl-dev \
  libboost-dev libboost-program-options-dev libntl-dev \
  valgrind doxygen pkg-config bc jq
```

只构建核心库和 API 测试时，可以不安装 NTL、Valgrind、Doxygen、`bc` 和 `jq`。

## 获取源码

```bash
git clone https://github.com/coperlm/SM-FAEST.git
cd SM-FAEST
git submodule update --init --recursive
```

仓库包含以下相关子模块：

- [`libs/GmSSL_Symmetric`](./libs/GmSSL_Symmetric/)：从 GmSSL 相关代码整理而来的对称密码组件，包含 SM4、SM3 和 AES 等实现。本项目主要使用其中的 SM3 组件，为 SM-FAEST 的哈希、SM3-XOF 及相关测试提供支持。该子模块可以单独使用 CMake 构建和测试，具体方法见其 [README](./libs/GmSSL_Symmetric/README.md)。
- [`libs/catch2`](./libs/catch2/)：Catch2 测试框架源码。本项目在启用 `-Dcatch2=enabled` 且同时启用基准时，用它构建 Catch2 基准程序；不参与核心 SM4/SM3 算法实现。
- [`libs/sm4bs`](./libs/sm4bs/)：面向 SM4 的 bitslice 实验性实现，使用 Go 编写，包含 64、128 和 256 路并行实现及基准测试。该子模块主要用于 SM4 bitslice 的实现参考和性能研究，不是根目录 Meson 构建的直接依赖。其原始项目说明见 [README](./libs/sm4bs/README.md)。
- [`libs/paper_construct`](./libs/paper_construct/)：论文与实验材料子模块，包含论文 LaTeX 源码、参考文献、图表、实验记录和论文构建文件。它用于论文撰写和实验结果整理，不参与 SM-FAEST 核心库的编译。

论文材料子模块不是构建核心库的必要条件，但完整复现实验时建议一并初始化。

## 构建

### 基础构建

```bash
meson setup build --buildtype=release
ninja -C build
```

构建后主要输出包括：

- `build/libfaest.so.1.0.0`：共享库；
- `build/libfaest.a`：包含随机数接口的静态库；
- `build/libfaest_no_random.a`：不包含默认随机数实现的静态库；
- 四个参数集对应的 API 头文件、静态库、测试程序和可选基准程序。

安装库、头文件和 pkg-config 文件：

```bash
ninja -C build install
```

如需使用自定义安装目录：

```bash
meson setup build --buildtype=release --prefix="$HOME/.local"
ninja -C build
ninja -C build install
```

### 论文实验推荐构建

为了启用基准程序和 Catch2 支持，可以使用：

```bash
meson setup build-release --buildtype=release \
  -Dbenchmarks=enabled \
  -Dcatch2=enabled \
  -Dmarch-native=enabled
ninja -C build-release
```

`-Dmarch-native=enabled` 会针对当前机器启用本地指令集优化。跨机器比较性能时，应记录 CPU、编译器、编译选项和采样设置，不建议直接比较不同环境下的原始数值。

### 常用 Meson 选项

| 选项 | 说明 |
| --- | --- |
| `-Dopenssl=enabled\|disabled\|auto` | 是否使用 OpenSSL；默认启用 |
| `-Daesni=enabled\|disabled\|auto` | 是否启用 AES-NI |
| `-DSHA3=auto\|opt64\|plain32\|avx2\|armv8a-neon\|s390-cpacf` | 选择 SHAKE/Keccak 实现 |
| `-Dbenchmarks=enabled\|disabled\|auto` | 是否构建基准程序 |
| `-Dcatch2=enabled\|disabled\|auto` | 是否构建 Catch2 基准 |
| `-Dvalgrind=enabled\|disabled\|auto` | 是否启用 Valgrind 相关目标 |
| `-Dmarch-native=enabled\|disabled\|auto` | 是否使用 `-march=native` |
| `-Dtv-generators=enabled\|disabled\|auto` | 是否构建测试向量生成器 |
| `-Ddocs=enabled\|disabled\|auto` | 是否构建 Doxygen 文档 |

例如，在不支持 AES-NI 的机器上可关闭 AES-NI：

```bash
meson setup build-no-aesni --buildtype=release \
  -Daesni=disabled
ninja -C build-no-aesni
```

重新配置或清理：

```bash
meson setup build --reconfigure
ninja -C build clean
```

## API

每个参数集都会生成一组兼容 SUPERCOP/NIST 风格的 C API：

```c
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk);

int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);
```

基本调用流程如下：

1. `crypto_sign_keypair` 生成 32 字节公钥和 32 字节私钥；
2. `crypto_sign` 将消息和签名拼接写入 `sm`；
3. 输出长度为 `mlen + CRYPTO_BYTES`；
4. `crypto_sign_open` 验证成功后恢复消息并返回 `0`，验证失败返回非零值。

调用者需要根据对应参数集的 `CRYPTO_*` 宏分配缓冲区，并为签名消息预留足够空间。完整示例见 [tests/api_test.c](./tests/api_test.c)。

## 测试与正确性验证

运行 Meson 注册的全部测试：

```bash
meson test -C build
```

显示详细错误日志：

```bash
meson test -C build --print-errorlogs
meson test -C build -v
```

四组参数集的基本 API 测试程序为：

```bash
./build/faest_128s/faest_128s_api_test
./build/faest_em_128s/faest_em_128s_api_test
./build/faest_sm4_128s/faest_sm4_128s_api_test
./build/faest_em_sm4_128s/faest_em_sm4_128s_api_test
```

安装 Boost 后，还可以运行 AES、SHAKE、SM3、SM4、OWF、PRG、BAVC、VOLE、通用哈希、SM4 约束和四组参数集端到端测试。安装 NTL 后会额外启用有限域测试。

SM-FAEST 相关的重点测试包括：

- SM3 标准摘要和 SM3-XOF 测试；
- SM4 基础算法测试；
- SM4 约束构造测试；
- SM4-OWF 和 SM4-PRG 测试；
- SM4 签名与 EM-SM4 签名 API 测试；
- AES/SHAKE 与 SM4/SM3 路径的对照测试。

## 性能实验

### 单参数集基准

启用 `benchmarks` 和 Boost.Program_options 后，可运行：

```bash
./build-release/faest_128s/faest_128s_bench --iter 100
./build-release/faest_sm4_128s/faest_sm4_128s_bench --iter 100
```

每行输出依次为：

```text
keygen_us,sign_us,verify_us
```

若启用 Catch2，还会生成对应的 `*_bench_c2` 程序。

### 四组参数集统一实验

`bench.sh` 会重新配置 `build_release`，依次构建、测试并测量四组参数集：

```bash
bash bench.sh
```

可以通过环境变量调整采样和超时参数：

```bash
BENCH_SAMPLES=5 SM4_BENCH_SAMPLES=3 bash bench.sh
```

### AES-NI/OpenSSL 配置矩阵

`perf_matrix.sh` 用四种配置组合比较 AES-NI 和 OpenSSL 对性能的影响：

```bash
bash perf_matrix.sh --samples 3 --clean
```

脚本会创建以下构建目录：

- `bpm_ni_ssl`：AES-NI 开启、OpenSSL 开启；
- `bpm_ni_nossl`：AES-NI 开启、OpenSSL 关闭；
- `bpm_noni_ssl`：AES-NI 关闭、OpenSSL 开启；
- `bpm_noni_nossl`：AES-NI 关闭、OpenSSL 关闭。

性能结果与硬件、编译器、构建类型及采样方法相关，只用于论文实验复现和相对比较。

## 测试向量生成

启用测试向量生成器：

```bash
meson setup build-tv --buildtype=release \
  -Dtv-generators=enabled
ninja -C build-tv
```

生成器覆盖 BAVC、PRG、OWF、VOLE、通用哈希和 SM4 签名向量。OpenSSL 相关的 NIST 风格签名向量目标还要求 OpenSSL 可用。

准备 NIST/SUPERCOP 风格目录：

```bash
ninja -C build-tv prepare_nist
```

## 目录结构

```text
.
├── faest_impl.c/.h         FAEST 协议核心
├── faest_param*.c.in/.h.in 参数集和参数模板
├── crypto_sign*.in         签名 API 模板
├── aes.c/.h                AES 对照实现
├── sm4.c/.h                SM4 实现
├── hash_*.h                哈希接口
├── owf*.c/.h               OWF 实现
├── bavc.c/.h               BAVC 实现
├── vole.c/.h               VOLE 实现
├── sha3/                   SHAKE/Keccak 实现
├── faest_*/                四组参数集的 Meson 子目录
├── tests/                  API、组件和协议测试
├── tools/                  基准、向量生成和 NIST 工具
├── libs/                   外部组件和论文子模块
├── bench.sh                统一基准脚本
├── perf_matrix.sh          配置矩阵脚本
└── meson.build             顶层构建定义
```

`config.h`、`parameters.h`、`faest_*.c`、`faest_*.h`、`api.h` 和 `crypto_sign.c` 等文件由 Meson 自动生成，不应直接修改。调整参数或密码组件时，应同步检查测试向量、签名尺寸和论文实验数据。

## 实现边界与安全说明

- 本仓库服务于论文研究和实验复现，不代表经过生产级安全认证。
- 论文创新是将 FAEST 的 AES/SHAKE 路径适配为 SM4/SM3；保留 AES/SHAKE 实现是为了提供对照基线。
- 默认配置下，部分 SM4-CTR PRG 路径使用 bitsliced 逻辑实现；秘密相关的 witness 扩展仍存在 S 盒表查找路径，因此不能笼统宣称整个签名流程严格常量时间。
- 性能数据、签名尺寸和参数布局可能随代码版本变化。复现实验时应记录提交版本、编译器、硬件和完整构建选项。
- 在实际产品或敏感环境中使用前，应进行独立的密码学审计、随机数检查、编译器/平台验证和侧信道评估。

## 相关文件与子模块索引

### 核心实现

- [`faest_impl.c/.h`](./faest_impl.c)：FAEST 签名协议的核心实现；
- [`faest_sm4.c/.h`](./faest_sm4.c)：SM4 参数集相关的协议、witness 和约束处理；
- [`sm4.c/.h`](./sm4.c)：SM4 基础实现；
- [`sm4_ni.h`](./sm4_ni.h)：SM4 相关硬件指令集接口；
- [`sm_random_oracle.c/.h`](./sm_random_oracle.c)：SM3 路径使用的随机预言机相关实现；
- [`hash_sm3.h`](./hash_sm3.h)：SM3 哈希接口；
- [`faest_param_sm4.c.in`](./faest_param_sm4.c.in)：SM4 参数集代码模板；
- [`faest_param.c.in`](./faest_param.c.in)：AES/SHAKE 参数集代码模板；
- [`crypto_sign.c.in`](./crypto_sign.c.in) 和 [`crypto_sign.h.in`](./crypto_sign.h.in)：统一签名 API 模板。

### 构建与参数

- [`meson.build`](./meson.build)：顶层构建定义、参数集配置和库目标；
- [`meson_options.txt`](./meson_options.txt)：OpenSSL、AES-NI、SHAKE 实现、基准、测试向量等构建选项；
- [`faest_128s/`](./faest_128s/)：AES 参数集构建配置；
- [`faest_em_128s/`](./faest_em_128s/)：AES/Even-Mansour 参数集构建配置；
- [`faest_sm4_128s/`](./faest_sm4_128s/)：SM4 参数集构建配置；
- [`faest_em_sm4_128s/`](./faest_em_sm4_128s/)：SM4/Even-Mansour 参数集构建配置；
- [`sha3/`](./sha3/)：SHAKE/Keccak 的多平台实现，作为 AES/SHAKE 对照路径的一部分；
- [`doc/`](./doc/)：Doxygen 文档构建配置。

### 测试与实验

- [`tests/`](./tests/)：API、AES、SHAKE、SM3、SM4、OWF、PRG、BAVC、VOLE、有限域和端到端测试；
- [`tools/`](./tools/)：基准程序、测试向量生成器和 NIST/SUPERCOP 准备工具；
- [`bench.sh`](./bench.sh)：四组参数集的统一构建、测试和基准脚本；
- [`perf_matrix.sh`](./perf_matrix.sh)：AES-NI/OpenSSL 配置矩阵实验脚本；
- [`CODE_AUDIT_REMEDIATION.md`](./CODE_AUDIT_REMEDIATION.md)：代码审计整改记录；
- [`LICENSE`](./LICENSE)：根项目许可证。

### 全部子模块

| 子模块 | 目录 | 用途 | 是否参与根项目核心构建 |
| --- | --- | --- | --- |
| Catch2 | [`libs/catch2/`](./libs/catch2/) | C++ 测试框架和基准支持 | 仅在启用 Catch2 基准时参与 |
| GmSSL-Symmetric | [`libs/GmSSL_Symmetric/`](./libs/GmSSL_Symmetric/) | SM3、SM4、AES 等对称密码实现；本项目主要使用 SM3 | 是，SM3 源码由 Meson 纳入构建 |
| sm4bs | [`libs/sm4bs/`](./libs/sm4bs/) | Go 语言 SM4 bitslice 实验实现和性能参考 | 否，独立实验子模块 |
| SM-FAEST-paper | [`libs/paper_construct/`](./libs/paper_construct/) | 论文源码、图表、参考文献和实验材料 | 否，论文构建和结果整理使用 |

子模块地址如下：

- Catch2：<https://github.com/catchorg/Catch2>
- GmSSL-Symmetric：<https://github.com/coperlm/GmSSL-Symmetric>
- sm4bs：<https://github.com/emmansun/sm4bs>
- SM-FAEST-paper：<https://github.com/coperlm/SM-FAEST-paper>

- [FAEST 原始参考实现](https://github.com/faest-sign/faest-ref)
- [SM-FAEST 项目仓库](https://github.com/coperlm/SM-FAEST)

子模块可能拥有独立的许可证、版本和构建方式。使用或修改子模块内容时，请同时阅读其目录中的许可证和说明文件。

## 许可证

本项目采用 MIT 许可证，详见 [LICENSE](./LICENSE)。`libs/` 下的子模块可能有独立的许可证和版权声明，使用时请分别阅读对应文件。
