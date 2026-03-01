#!/usr/bin/env python3
"""快速性能测试 - 测量基本操作时间"""

import subprocess
import json
import time
import os
import sys

BUILD_DIR = "build_release"
ITERATIONS = 10  # 只运行10次取平均

VARIANTS = [
    ("faest_128s", "FAEST_128S"),
    ("faest_sm4_128s", "FAEST_SM4_128S"),
    ("faest_em_128s", "FAEST_EM_128S"),
    ("faest_em_sm4_128s", "FAEST_EM_SM4_128S"),
]


def quick_bench(variant_id, variant_name):
    """快速测量单个variant的性能"""
    test_path = f"{BUILD_DIR}/{variant_id}/{variant_id}_api_test"
    
    if not os.path.exists(test_path):
        print(f"[跳过] {variant_name}: 程序不存在", file=sys.stderr)
        return None
    
    print(f"[测试] {variant_name} ({ITERATIONS}次迭代)...", file=sys.stderr)
    
    times = []
    for i in range(ITERATIONS):
        start = time.perf_counter()
        result = subprocess.run([test_path], capture_output=True)
        end = time.perf_counter()
        
        if result.returncode != 0:
            print(f"  失败: {result.stderr.decode()[:200]}", file=sys.stderr)
            return None
        
        elapsed_us = (end - start) * 1_000_000
        times.append(elapsed_us)
        print(f"  #{i+1}: {elapsed_us/1000:.1f} ms", file=sys.stderr)
    
    mean_us = sum(times) / len(times)
    min_us = min(times)
    max_us = max(times)
    
    # 读取大小信息
    api_h = f"{BUILD_DIR}/{variant_id}/api.h"
    sig_size = pk_size = sk_size = 0
    
    try:
        with open(api_h) as f:
            for line in f:
                if "CRYPTO_BYTES" in line and "PUBLICKEY" not in line and "SECRETKEY" not in line:
                    sig_size = int(line.split()[2])
                elif "CRYPTO_PUBLICKEYBYTES" in line:
                    pk_size = int(line.split()[2])
                elif "CRYPTO_SECRETKEYBYTES" in line:
                    sk_size = int(line.split()[2])
    except:
        pass
    
    return {
        "variant": variant_name,
        "setting_id": variant_id,
        "total_time_us": mean_us,
        "total_time_ms": mean_us / 1000,
        "min_ms": min_us / 1000,
        "max_ms": max_us / 1000,
        "iterations": ITERATIONS,
        "sig_size_bytes": sig_size,
        "pk_size_bytes": pk_size,
        "sk_size_bytes": sk_size,
    }


if __name__ == "__main__":
    print("# 快速性能测试", file=sys.stderr)
    print(f"# 迭代次数: {ITERATIONS}", file=sys.stderr)
    print("", file=sys.stderr)
    
    results = []
    for vid, vname in VARIANTS:
        result = quick_bench(vid, vname)
        if result:
            results.append(result)
            print(json.dumps(result))
    
    print("", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print("测试完成！", file=sys.stderr)
