#!/usr/bin/env python3
"""
性能对比分析工具 - 比较带硬件加速 vs 纯软件实现

用法：
    python3 bench_analyze.py
"""

import json
import sys

def load_jsonl(path):
    """加载 JSONL 文件"""
    records = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    d = json.loads(line)
                    sid = d.get("setting_id", "")
                    if sid:
                        records[sid] = d
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"[错误] 文件未找到: {path}", file=sys.stderr)
        return {}
    return records


def us_to_ms(us):
    """微秒转毫秒"""
    return us / 1000.0


def analyze_performance():
    """分析性能对比"""
    
    # 加载数据
    with_aesni = load_jsonl("benchmark_results_with_aesni.jsonl")
    without_aesni = load_jsonl("benchmark_results_without_aesni.jsonl")
    
    if not with_aesni or not without_aesni:
        print("[错误] 无法load完整数据", file=sys.stderr)
        return
    
    variants = [
        ("faest_128s", "FAEST_128S (AES-std)"),
        ("faest_em_128s", "FAEST_EM_128S (AES-EM)"),
        ("faest_sm4_128s", "FAEST_SM4_128S (SM4-std)"),
        ("faest_em_sm4_128s", "FAEST_EM_SM4_128S (SM4-EM)"),
    ]
    
    print("# AES 纯软件 vs SM4 性能全面对比\n")
    print("> **测试日期:** 2026年3月1日")
    print("> **测试环境:** Intel 13th Gen CPU (x86_64)")
    print("> **编译配置:** Release with -march=native, **ALL AES optimizations DISABLED**\n")
    
    print("## 🔧 禁用的优化\n")
    print("- ❌ AES-NI (硬件指令)")
    print("- ❌ AVX2 (向量化)")
    print("- ❌ OpenSSL (库优化)\n")
    
    print("---\n")
    
    # Sign 对比
    print("## 📊 Sign 性能对比\n")
    print(f"| 变体 | 带 AES-NI (ms) | 纯软件 (ms) | 性能损失 | vs SM4 (纯软件) |")
    print(f"|------|----------------|-------------|----------|-----------------|")
    
    for sid, name in variants:
        if sid in with_aesni and sid in without_aesni:
            with_time = us_to_ms(with_aesni[sid]["sign"]["mean_us"])
            without_time = us_to_ms(without_aesni[sid]["sign"]["mean_us"])
            slowdown = without_time / with_time
            
            # 计算相对 SM4 的性能
            vs_sm4 = ""
            if "aes" in sid.lower() or "128s" == sid[-4:]:
                sm4_variant = sid.replace("128s", "sm4_128s") if "sm4" not in sid else sid
                if "em" not in sid:
                    sm4_variant = "faest_sm4_128s"
                elif "em" in sid and "sm4" not in sid:
                    sm4_variant = "faest_em_sm4_128s"
                    
                if sm4_variant in without_aesni:
                    sm4_time = us_to_ms(without_aesni[sm4_variant]["sign"]["mean_us"])
                    ratio = sm4_time / without_time
                    vs_sm4 = f"**{ratio:.2f}x 快** ✓"
                    
            print(f"| **{name}** | {with_time:.1f} | **{without_time:.1f}** | **{slowdown:.2f}x 慢** | {vs_sm4} |")
    
    print()
    
    # Verify 对比
    print("## 📊 Verify 性能对比\n")
    print(f"| 变体 | 带 AES-NI (ms) | 纯软件 (ms) | 性能损失 | vs SM4 (纯软件) |")
    print(f"|------|----------------|-------------|----------|-----------------|")
    
    for sid, name in variants:
        if sid in with_aesni and sid in without_aesni:
            with_time = us_to_ms(with_aesni[sid]["verify"]["mean_us"])
            without_time = us_to_ms(without_aesni[sid]["verify"]["mean_us"])
            slowdown = without_time / with_time
            
            # 计算相对 SM4 的性能
            vs_sm4 = ""
            if "aes" not in sid.lower() or "sm4" in sid:
                pass  # SM4 variants
            else:
                sm4_variant = "faest_em_sm4_128s" if "em" in sid else "faest_sm4_128s"
                if sm4_variant in without_aesni:
                    sm4_time = us_to_ms(without_aesni[sm4_variant]["verify"]["mean_us"])
                    ratio = sm4_time / without_time
                    vs_sm4 = f"**{ratio:.2f}x 快** ✓"
                    
            print(f"| **{name}** | {with_time:.1f} | **{without_time:.1f}** | **{slowdown:.2f}x 慢** | {vs_sm4} |")
    
    print()
    
    # 关键发现
    print("## 🔍 关键发现\n")
    
    # 计算 AES vs SM4 比例
    aes_std_sign = us_to_ms(without_aesni["faest_128s"]["sign"]["mean_us"])
    sm4_std_sign = us_to_ms(without_aesni["faest_sm4_128s"]["sign"]["mean_us"])
    aes_em_sign = us_to_ms(without_aesni["faest_em_128s"]["sign"]["mean_us"])
    sm4_em_sign = us_to_ms(without_aesni["faest_em_sm4_128s"]["sign"]["mean_us"])
    
    print(f"### 纯软件实现下 AES vs SM4")
    print()
    print(f"**Sign 性能:**")
    print(f"- Standard 模式: AES ({aes_std_sign:.1f}ms) vs SM4 ({sm4_std_sign:.1f}ms) → **AES 快 {sm4_std_sign/aes_std_sign:.2f}x** ⭐")
    print(f"- EM 模式: AES ({aes_em_sign:.1f}ms) vs SM4 ({sm4_em_sign:.1f}ms) → **AES 快 {sm4_em_sign/aes_em_sign:.2f}x** ⭐")
    print()
    
    # AES-NI 加速比
    aes_std_with = us_to_ms(with_aesni["faest_128s"]["sign"]["mean_us"])
    aes_em_with = us_to_ms(with_aesni["faest_em_128s"]["sign"]["mean_us"])
    
    print(f"### AES-NI 硬件加速效果")
    print()
    print(f"- Standard 模式: {aes_std_with:.1f}ms (硬件) → {aes_std_sign:.1f}ms (软件) = **{aes_std_sign/aes_std_with:.2f}x 慢**")
    print(f"- EM 模式: {aes_em_with:.1f}ms (硬件) → {aes_em_sign:.1f}ms (软件) = **{aes_em_sign/aes_em_with:.2f}x 慢**")
    print()
    print("**结论:** EM 模式从硬件加速中获益更多（因为使用更多 PRG 操作）")
    print()
    
    print("---\n")
    print("*分析生成时间: 2026-03-01*")


if __name__ == "__main__":
    analyze_performance()
