# FAEST - 参考实现（C/C++）

FAEST 是一种基于 AES/SM4 的后量子数字签名方案，原始论文提交给 NIST PQC 竞标。此仓库提供完整参考实现、测试套件、性能基准与参数集对比。

## 目录

- 项目简介
- 参数集
- 系统与依赖
- 构建与安装
- 测试与基准
- 代码结构
- 开发指南
- 许可证与引用

## 项目简介

FAEST 支持以下参数集：

- `FAEST-128s`
- `FAEST-EM-128s`
- `FAEST-SM4-128s`
- `FAEST-EM-SM4-128s`

实现包含：

- 签名 (sign)
- 验证 (verify)
- 密钥生成 (keygen)
- 证明确认组件（VOLE、BAVC、OWF、哈希、随机预言机）

## 参数集说明

| 参数集 | 基础块密码 | 安全目标 | 用途 |
| --- | --- | --- | --- |
| FAEST-128s | AES | 128-bit | 标准签名方案 |
| FAEST-EM-128s | AES+EM | 128-bit | 兼容对比实验 |
| FAEST-SM4-128s | SM4 | 128-bit | 国密 SM4 版本 |
| FAEST-EM-SM4-128s | SM4+EM | 128-bit | SM4 兼容对比 |

## 系统与依赖

### 支持平台

- Linux
- macOS
- Windows（Visual Studio + Ninja/Meson）

### 主要依赖

- C/C++: 编译器需支持 C11/C++17（GCC 7+/Clang 6+）
- Python 3.6+（基准脚本）
- Meson >= 0.57
- Ninja
- Boost >= 1.70（可选，测试）
- NTL >= 11.0（可选，测试）

### Debian/Ubuntu 快速安装

```bash
sudo apt update
sudo apt install -y meson ninja-build gcc g++ python3 libboost-dev libboost-program-options-dev libntl-dev
```

### macOS（Homebrew）

```bash
brew install meson ninja boost ntl python3
```

### Windows

- Visual Studio 2019+（含 C++）
- Python 3.6+
- `pip install meson ninja`

## 构建与安装

### 1. 克隆仓库

```bash
git clone https://github.com/your-repo/faest.git
cd faest
```

### 2. 配置构建目录

```bash
meson setup build_release --buildtype=release
```

### 3. 编译

```bash
cd build_release
ninja
```

### 4. 安装（可选）

```bash
ninja install
```

## 测试与基准

### 运行全部测试

```bash
cd build_release
meson test
```

### 详细测试输出

```bash
meson test -v
```

### 手动执行参数集测试

```bash
./faest_128s/faest_128s_api_test
./faest_em_128s/faest_em_128s_api_test
./faest_sm4_128s/faest_sm4_128s_api_test
./faest_em_sm4_128s/faest_em_sm4_128s_api_test
```

### 基准运行

```bash
bash bench.sh
```

或直接运行生成的基准程序：

```bash
./faest_128s/faest_128s_bench_c2
./faest_sm4_128s/faest_sm4_128s_bench_c2
```

## 代码结构

```
/                  根目录
├── aes.c/.h       AES 实现
├── sm4.c/.h       SM4 实现
├── faest_impl.c   核心签名实现
├── faest_param*.c 有参数集配置
├── instances.c    参数集注册
├── tests/         测试集和向量
├── tools/         基准与辅助脚本
├── meson.build    构建定义
├── build_release/ Meson 输出目录
└── LICENSE        MIT 许可证
```

## 开发指南

- 修改后：`cd build_release && ninja` 进行快速增量编译
- 重新配置：`meson setup --reconfigure build_release`
- 清理：`cd build_release && ninja clean`
- 新增参数集：复制 `faest_*` 目录模板，更新 `instances.*` 与 `meson.build`

## 输出说明

- `libfaest.so`, `libfaest.a`, `libfaest_no_random.a`
- 各参数集测试/基准可执行文件
- 测试结果码：0 表示成功

## 许可证

本项目采用 MIT 许可证，详见 `LICENSE`。

## 引用

https://github.com/faest-sign/faest-ref
