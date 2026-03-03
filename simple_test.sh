#!/bin/bash
# 简单版本测试 - 10次迭代快速测试

cd /home/coper/桌面/FAEST

echo "======================================"
echo "快速性能测试 (10次迭代)"
echo "======================================"
echo ""

ITER=10

echo "测试 AES 非EM模式..."
build_release/faest_128s/faest_128s_bench -i $ITER > test_aes_128s.csv 2>&1 &
PID1=$!

echo "测试 SM4 非EM模式..."
build_release/faest_sm4_128s/faest_sm4_128s_bench -i $ITER > test_sm4_128s.csv 2>&1 &
PID2=$!

echo "测试 AES EM模式..."
build_release/faest_em_128s/faest_em_128s_bench -i $ITER > test_aes_em_128s.csv 2>&1 &
PID3=$!

echo "测试 SM4 EM模式..."
build_release/faest_em_sm4_128s/faest_em_sm4_128s_bench -i $ITER > test_sm4_em_128s.csv 2>&1 &
PID4=$!

echo "等待所有测试完成..."
wait $PID1 $PID2 $PID3 $PID4

echo "所有测试完成！"
echo ""
echo "分析结果..."

python3 << 'EOF'
import csv
import statistics

def analyze_file(filename, name):
    try:
        with open(filename, 'r') as f:
            reader = csv.reader(f)
            data = [[float(x) for x in row] for row in reader if len(row) >= 3]
        
        if not data:
            print(f"{name}: 无数据")
            return None
        
        keygen = [row[0] for row in data]
        sign = [row[1] for row in data]
        verify = [row[2] for row in data]
        
        return {
            'name': name,
            'keygen': statistics.mean(keygen),
            'sign': statistics.mean(sign),
            'verify': statistics.mean(verify)
        }
    except Exception as e:
        print(f"{name}: 错误 - {e}")
        return None

results = []
for f, n in [
    ('test_aes_128s.csv', 'AES 非EM'),
    ('test_sm4_128s.csv', 'SM4 非EM'),
    ('test_aes_em_128s.csv', 'AES EM'),
    ('test_sm4_em_128s.csv', 'SM4 EM')
]:
    r = analyze_file(f, n)
    if r:
        results.append(r)

print("\n" + "="*70)
print("性能测试结果 (AES-NI 已禁用 - 纯软件实现)")
print("="*70)
print(f"{'算法':<15} {'KeyGen (μs)':>15} {'Sign (μs)':>15} {'Verify (μs)':>15}")
print("-"*70)

for r in results:
    print(f"{r['name']:<15} {r['keygen']:>15.0f} {r['sign']:>15.0f} {r['verify']:>15.0f}")

print("="*70)

# 对比分析
aes = next((r for r in results if r['name'] == 'AES 非EM'), None)
sm4 = next((r for r in results if r['name'] == 'SM4 非EM'), None)
aes_em = next((r for r in results if r['name'] == 'AES EM'), None)
sm4_em = next((r for r in results if r['name'] == 'SM4 EM'), None)

print("\n对比分析 (Sign操作):")
print("-"*70)

if aes and sm4:
    ratio = sm4['sign'] / aes['sign']
    diff = (ratio - 1) * 100
    print(f"非EM模式: SM4 比 AES {"慢" if ratio > 1 else "快"} {abs(diff):.1f}%")
    print(f"  AES: {aes['sign']:.0f} μs")
    print(f"  SM4: {sm4['sign']:.0f} μs")
    print(f"  比率: {ratio:.3f}x")

if aes_em and sm4_em:
    ratio_em = sm4_em['sign'] / aes_em['sign']
    diff_em = (ratio_em - 1) * 100
    print(f"\nEM模式: SM4 比 AES {"慢" if ratio_em > 1 else "快"} {abs(diff_em):.1f}%")
    print(f"  AES: {aes_em['sign']:.0f} μs")
    print(f"  SM4: {sm4_em['sign']:.0f} μs")
    print(f"  比率: {ratio_em:.3f}x")

print("="*70)
EOF
