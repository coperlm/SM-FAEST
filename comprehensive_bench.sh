#!/bin/bash
# 全面性能对比测试：SM4 vs AES, EM vs 非EM, OpenSSL vs 纯C

echo "=== FAEST 全面性能对比测试 ==="
echo "测试配置：每个算法运行5次，输出格式：Keygen,Sign,Verify (cycles)"
echo ""

# 测试函数
run_bench() {
    local build_dir=$1
    local algo=$2
    local version=$3
    
    echo "[$version] $algo"
    for i in {1..5}; do
        $build_dir/$algo/${algo}_bench -i 1 2>&1
    done
    echo ""
}

# 纯C版本测试
echo "========================================"
echo "纯C版本 (OpenSSL disabled)"
echo "========================================"
run_bench "build_release" "faest_128s" "AES-128s"
run_bench "build_release" "faest_em_128s" "AES-EM-128s"
run_bench "build_release" "faest_sm4_128s" "SM4-128s"
run_bench "build_release" "faest_em_sm4_128s" "SM4-EM-128s"

# OpenSSL优化版本测试
echo "========================================"
echo "OpenSSL优化版本 (OpenSSL enabled)"
echo "========================================"
run_bench "build_openssl" "faest_128s" "AES-128s"
run_bench "build_openssl" "faest_em_128s" "AES-EM-128s"
run_bench "build_openssl" "faest_sm4_128s" "SM4-128s"
run_bench "build_openssl" "faest_em_sm4_128s" "SM4-EM-128s"

echo "测试完成！"
