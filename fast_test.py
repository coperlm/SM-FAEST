#!/usr/bin/env python3
"""
超快速性能测试 - 只测试3次取平均值
"""

import subprocess
import json
import time
import os

BUILD_DIR = "build_release"
ITERATIONS = 3

VARIANTS = [
    ("faest_128s", "FAEST_128S"),
    ("faest_sm4_128s", "FAEST_SM4_128S"),
]


def single_test(variant_id, variant_name):
    """单次测试"""
    test_path = f"{BUILD_DIR}/{variant_id}/{variant_id}_api_test"
    
    if not os.path.exists(test_path):
        return None
    
    print(f"[{variant_name}] 测试中... ", end='', flush=True)
    
    times = []
    for i in range(ITERATIONS):
        start = time.perf_counter()
        result = subprocess.run([test_path], capture_output=True, text=True)
        end = time.perf_counter()
        
        if result.returncode != 0:
            print(f"失败!")
            return None
        
        elapsed_ms = (end - start) * 1000
        times.append(elapsed_ms)
        print(f"{elapsed_ms:.0f}ms ", end='', flush=True)
    
    mean_ms = sum(times) / len(times)
    print(f"| 平均: {mean_ms:.0f}ms")
    
    # 读取大小
    api_h = f"{BUILD_DIR}/{variant_id}/api.h"
    sig_size = 0
    try:
        with open(api_h) as f:
            for line in f:
                if "CRYPTO_BYTES" in line and "PUBLIC" not in line and "SECRET" not in line:
                    sig_size = int(line.split()[2])
                    break
    except:
        pass
    
    return {
        "variant": variant_name,
        "time_ms": mean_ms,
        "sig_size": sig_size,
        "iterations": ITERATIONS
    }


if __name__ == "__main__":
    print(f"快速测试 (每个variant {ITERATIONS}次)\n")
    
    results = []
    for vid, vname in VARIANTS:
        result = single_test(vid, vname)
        if result:
            results.append(result)
    
    print("\n=== 结果 ===")
    for r in results:
        print(f"{r['variant']:20s} {r['time_ms']:8.0f} ms    签名:{r['sig_size']:5d} bytes")
    
    if len(results) == 2:
        ratio = results[1]['time_ms'] / results[0]['time_ms']
        sig_ratio = results[1]['sig_size'] / results[0]['sig_size']
        print(f"\nSM4/AES比值:         {ratio:8.2f}x           {sig_ratio:5.2f}x")
    
    # JSON输出
    for r in results:
        print(json.dumps(r))
