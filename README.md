# FAEST - Reference Implementation of the FAEST Digital Signature Scheme

## Overview

FAEST is a post-quantum cryptographic signature scheme based on the AES block cipher, submitted to the NIST Post-Quantum Cryptography standardization process. This repository contains the reference implementation in C/C++, designed for academic research and performance evaluation.

**Key Features:**
- Multiple parameter sets: FAEST-128s, FAEST-EM-128s, FAEST-SM4-128s, FAEST-EM-SM4-128s
- Comprehensive test suite with known-answer tests
- Performance benchmarking tools
- Fair comparison between AES and SM4 implementations

## Dependencies

### System Requirements
- **Operating System**: Linux, macOS, or Windows (with appropriate build tools)
- **Compiler**: GCC 7+ or Clang 6+ (C11/C++17 support required)
- **Python**: Python 3.6+ (for benchmarking scripts)

### Build Dependencies
- **Meson**: >= 0.57 (build system configuration)
- **Ninja**: Latest version (build execution)

### Test and Benchmark Dependencies
- **Boost**: >= 1.70 (for program_options and test components)
- **NTL**: >= 11.0 (Number Theory Library, for cryptographic tests)
- **Catch2**: >= 3.0 (unit testing framework, included as submodule)

### Installation on Debian/Ubuntu
```bash
# Build tools
sudo apt update
sudo apt install meson ninja-build gcc g++

# Test dependencies
sudo apt install libboost-dev libboost-program-options-dev libntl-dev

# Python for scripts
sudo apt install python3
```

### Installation on macOS
```bash
# Using Homebrew
brew install meson ninja boost ntl python3

# Or using MacPorts
sudo port install meson ninja boost ntl python3
```

### Installation on Windows
- Install Visual Studio 2019+ with C++ support
- Install Python 3.6+
- Use `pip` to install Meson and Ninja: `pip install meson ninja`

## Installation and Setup

### 1. Clone the Repository
```bash
git clone https://github.com/your-repo/faest.git
cd faest
```

### 2. Configure Build System
```bash
meson setup build_release
```
This creates a `build_release/` directory with build configuration. Meson will automatically detect available compilers and features.

### 3. Build the Project
```bash
cd build_release
ninja
```
This compiles all variants and test executables.

### 4. (Optional) Install Python Dependencies
```bash
pip install -r requirements.txt
```
(Note: Currently no external Python packages required)

## Running Tests

### One-Command Test Execution
To run all tests and verify correctness:
```bash
cd build_release
meson test
```

### Individual Component Tests
```bash
# API tests for all parameter sets
./faest_128s/faest_128s_api_test
./faest_em_128s/faest_em_128s_api_test
./faest_sm4_128s/faest_sm4_128s_api_test
./faest_em_sm4_128s/faest_em_sm4_128s_api_test

# Unit tests (if Catch2 enabled)
meson test -v
```

### Performance Benchmarks
```bash
# Quick benchmark (Python script)
python3 quick_bench.py

# Detailed benchmarks
./faest_128s/faest_128s_bench_c2
./faest_sm4_128s/faest_sm4_128s_bench_c2

# Batch benchmark script
bash bench.sh
```

## Interpreting Experimental Results

### Test Output Interpretation
- **API Tests**: Pass/fail status indicates correct implementation of sign/verify operations
- **Unit Tests**: Detailed assertions on internal components (VOLE, BAVC, etc.)
- **Known-Answer Tests**: Compare against precomputed test vectors for validation

### Performance Data Format
Benchmark outputs are in JSON format with the following fields:
- `variant`: Parameter set name (e.g., "FAEST_128S")
- `total_time_us`: Mean execution time in microseconds
- `min_ms`/`max_ms`: Min/max observed times in milliseconds
- `iterations`: Number of measurement iterations
- `sig_size_bytes`: Signature size in bytes
- `pk_size_bytes`: Public key size in bytes
- `sk_size_bytes`: Secret key size in bytes

Example output:
```json
{
  "variant": "FAEST_128S",
  "total_time_us": 15420.5,
  "min_ms": 14.8,
  "max_ms": 16.2,
  "iterations": 10,
  "sig_size_bytes": 4506,
  "pk_size_bytes": 32,
  "sk_size_bytes": 32
}
```

### Analyzing Results
- **Correctness**: All tests must pass (return code 0)
- **Performance**: Compare `total_time_us` across variants for relative performance
- **Reproducibility**: Results should be consistent across runs (±5% variance expected)
- **Fair Comparison**: AES and SM4 variants are built with identical optimizations disabled for equitable comparison

## Project Structure
```
faest/
├── meson.build              # Build configuration
├── README.md               # This file
├── requirements.txt        # Python dependencies
├── aes.c/aes.h            # AES implementation
├── sm4.c/sm4.h            # SM4 implementation
├── faest_impl.c           # Core signature logic
├── tests/                 # Test vectors and unit tests
├── tools/                 # Benchmarking tools
├── sha3/                  # Keccak/SHA-3 implementation
└── build_release/         # Generated build directory
```

## Reproducibility Notes
- All random operations use cryptographically secure PRNGs
- Test vectors are deterministic and version-controlled
- Performance measurements include statistical analysis (mean, min, max)
- Hardware-specific optimizations are disabled by default for fair comparison

## License
This project is licensed under the MIT License. See LICENSE for details.

## Citation
If you use this implementation in academic work, please cite:

```
@misc{faest-ref,
  title={FAEST: Reference Implementation},
  author={FAEST Development Team},
  year={2024},
  url={https://github.com/your-repo/faest}
}
```

For the FAEST specification:
```
@inproceedings{faest-spec,
  title={FAEST: Tightly Secure Multi-Signature Schemes from the AES Block Cipher},
  author={Baum, Carsten and others},
  booktitle={Advances in Cryptology -- EUROCRYPT 2023},
  year={2023}
}
```

### 2. 编译

```sh
cd build
ninja
```

`ninja` 会编译所有源文件并生成：
- `libfaest.so` — 共享库
- `libfaest.a` / `libfaest_no_random.a` — 静态库
- 各参数集的测试程序（如 `faest_128s_api_test` 等）

### 3. 运行测试

```sh
meson test            # 运行所有测试
meson test -v         # 运行所有测试并显示详细输出
```

### 4. 常用操作

```sh
# 重新编译（修改代码后）
cd build && ninja

# 重新配置（修改 meson.build 后）
meson setup --reconfigure build

# 清理构建
cd build && ninja clean

# Release 模式编译（开启优化）
meson setup build --buildtype=release
cd build && ninja
```

```
# 方法一：Python 采集 + 表格
python3 collect_bench.py benchmark_results.jsonl && python3 bench_table.py

# 方法二：bash bench.sh 管道（原始 bench.sh 流）
bash bench.sh 2>/dev/null | tee benchmark_results.jsonl | python3 bench_table.py

# 方法三：比较多个历史记录
python3 bench_table.py run_old.jsonl benchmark_results.jsonl
```