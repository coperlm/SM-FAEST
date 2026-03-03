#!/bin/bash
# 性能测试脚本 - 测试所有算法变体的成功率和平均时间

set -e

BUILD_DIR="build_release"
ITERATIONS=20

echo "============================================"
echo "性能和稳定性测试报告"
echo "测试时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "每个算法运行次数: $ITERATIONS"
echo "============================================"
echo ""

test_variant() {
    local name=$1
    local binary=$2
    
    echo "=== $name ==="
    
    # 测试成功率
    local success=0
    local total_time=0
    
    for i in $(seq 1 $ITERATIONS); do
        # 使用time测量执行时间（秒）
        start=$(date +%s%N)
        if $binary > /dev/null 2>&1; then
            success=$((success + 1))
        fi
        end=$(date +%s%N)
        elapsed=$(( (end - start) / 1000000 ))  # 转换为毫秒
        total_time=$((total_time + elapsed))
    done
    
    local success_rate=$((success * 100 / ITERATIONS))
    local avg_time=$((total_time / ITERATIONS))
    
    echo "  成功率: $success/$ITERATIONS = $success_rate%"
    echo "  平均时间: ${avg_time} ms"
    
    if [ $success_rate -lt 100 ]; then
        echo "  ⚠️  警告: 存在失败情况"
    else
        echo "  ✅ 全部成功"
    fi
    echo ""
}

# 测试AES-128s (非EM)
test_variant "AES-128s (标准)" "$BUILD_DIR/faest_128s/faest_128s_api_test"

# 测试AES-EM-128s
test_variant "AES-EM-128s (EM模式)" "$BUILD_DIR/faest_em_128s/faest_em_128s_api_test"

# 测试SM4-128s (非EM)
test_variant "SM4-128s (标准)" "$BUILD_DIR/faest_sm4_128s/faest_sm4_128s_api_test"

# 测试SM4-EM-128s
test_variant "SM4-EM-128s (EM模式)" "$BUILD_DIR/faest_em_sm4_128s/faest_em_sm4_128s_api_test"

echo "============================================"
echo "测试完成"
echo "============================================"
