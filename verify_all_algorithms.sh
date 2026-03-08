#!/bin/bash
# 验证所有算法变体的成功率和性能
# 验证修复后所有算法都达到100%成功率

set -e

BUILD_DIR="build_release"
ITERATIONS=100

echo "============================================"
echo "算法稳定性验证报告"
echo "测试时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "每个算法运行次数: $ITERATIONS"
echo "============================================"
echo ""

test_variant() {
    local name=$1
    local binary=$2
    
    echo -n "测试 $name ... "
    
    # 测试成功率
    local success=0
    local total_time=0
    
    for i in $(seq 1 $ITERATIONS); do
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
    
    if [ $success_rate -eq 100 ]; then
        echo "✅ $success/$ITERATIONS = $success_rate% (平均 ${avg_time}ms)"
    else
        echo "❌ $success/$ITERATIONS = $success_rate% (平均 ${avg_time}ms)"
    fi
}

echo "AES算法变体:"
test_variant "AES-128s (标准)" "$BUILD_DIR/faest_128s/faest_128s_api_test"
test_variant "AES-EM-128s (EM模式)" "$BUILD_DIR/faest_em_128s/faest_em_128s_api_test"

echo ""
echo "SM4算法变体:"
test_variant "SM4-128s (标准)" "$BUILD_DIR/faest_sm4_128s/faest_sm4_128s_api_test"
test_variant "SM4-EM-128s (EM模式)" "$BUILD_DIR/faest_em_sm4_128s/faest_em_sm4_128s_api_test"

echo ""
echo "============================================"
echo "验证完成！"
echo "============================================"
