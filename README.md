# FAEST - Reference implementation

## 工具简介

### Meson

**Meson** 是一个现代化的构建系统配置工具（类似于 CMake），负责检测编译器、依赖库、平台特性，并生成底层构建文件。它使用简洁的 Python 风格语法（`meson.build`），比 CMake 更易读。Meson 本身**不执行编译**，而是生成 Ninja 构建文件。

### Ninja

**Ninja** 是一个专注于速度的底层构建执行工具（类似于 Make），它读取 Meson 生成的构建规则，调用编译器完成实际的编译和链接。相比 Make，Ninja 更快且输出更简洁。

> 简单理解：**Meson = 配置阶段**（生成构建计划），**Ninja = 编译阶段**（执行构建计划）。

## Dependencies

For building:
* `meson` version 0.57 or newer
* `ninja` (depending on the build system generator selected via `meson`)

For tests:
* `boost` (unit test framework)
* `NTL`

On Arch-based Linux distributions:
```sh
pacman -S meson ninja        # for build dependencies
pacman -S boost ntl           # for test dependencies
```

Both `meson` and `ninja` are also available via PyPI:
```sh
pip install meson ninja
```

## Building

### 1. 配置项目（仅首次需要）

```sh
meson setup build
```

这会在 `build/` 目录中生成构建文件。Meson 会自动检测编译器、AES-NI/AVX2 等硬件特性、以及 OpenSSL 等可选依赖。

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
