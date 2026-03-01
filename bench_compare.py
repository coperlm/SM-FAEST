#!/usr/bin/env python3
"""
bench_compare.py — 对比多个 benchmark 配置（例如：有 AES-NI vs 无 AES-NI）

用法：
    python3 bench_compare.py \
        benchmark_results_with_aesni.jsonl \
        benchmark_results_no_optimizations.jsonl \
        --labels "AES-NI" "Pure SW" \
        --output comparison_table.md
        
    python3 bench_compare.py file1.jsonl file2.jsonl file3.jsonl
"""

import json
import sys
import argparse
from collections import OrderedDict

# 变体显示名和顺序
DISPLAY_NAME = {
    "faest_128s":        "FAEST_128S (AES-std)",
    "faest_em_128s":     "FAEST_EM_128S (AES-EM)",
    "faest_sm4_128s":    "FAEST_SM4_128S (SM4-std)",
    "faest_em_sm4_128s": "FAEST_EM_SM4_128S (SM4-EM)",
}

ORDER = ["faest_128s", "faest_em_128s", "faest_sm4_128s", "faest_em_sm4_128s"]


def us_to_ms(us):
    """微秒转毫秒"""
    return us / 1000.0


def fmt_ms(us):
    """格式化为毫秒（1位小数）"""
    return f"{us_to_ms(us):.1f}"


def load_jsonl(path):
    """加载一个 JSONL 文件，返回 {setting_id: data} 字典"""
    records = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                sid = d.get("setting_id", "")
                if sid:
                    # 如果同一 setting_id 有多条，保留最新（这里简化为保留最后读到的）
                    records[sid] = d
    except FileNotFoundError:
        print(f"[warn] 文件未找到: {path}", file=sys.stderr)
        return {}
    return records


def compare_configs(config_files, labels=None):
    """对比多个配置文件"""
    
    # 加载所有配置的数据
    configs = []
    for i, path in enumerate(config_files):
        data = load_jsonl(path)
        label = labels[i] if labels and i < len(labels) else f"Config-{i+1}"
        configs.append({"label": label, "path": path, "data": data})
    
    if not configs:
        print("[error] 没有有效的配置数据", file=sys.stderr)
        return
    
    # 打印对比表格
    print("# Benchmark 配置对比\n")
    print(f"**对比配置数:** {len(configs)}\n")
    
    for i, cfg in enumerate(configs):
        print(f"- **{cfg['label']}**: {cfg['path']}")
    print()
    
    # === 表 1: Sign 性能对比 ===
    print("## Sign 性能对比 (ms)\n")
    
    header = ["变体"] + [cfg["label"] for cfg in configs] + ["最快", "最慢倍数"]
    
    print(make_table_row(header))
    print(make_separator(len(header)))
    
    for sid in ORDER:
        row = [DISPLAY_NAME.get(sid, sid)]
        values = []
        
        for cfg in configs:
            if sid in cfg["data"]:
                mean_us = cfg["data"][sid]["sign"]["mean_us"]
                std_us = cfg["data"][sid]["sign"]["std_dev_us"]
                row.append(f"{fmt_ms(mean_us)} ± {fmt_ms(std_us)}")
                values.append(mean_us)
            else:
                row.append("N/A")
                values.append(float('inf'))
        
        # 计算最快和最慢
        valid_values = [v for v in values if v != float('inf')]
        if valid_values:
            min_val = min(valid_values)
            max_val = max(valid_values)
            min_idx = values.index(min_val)
            ratio = max_val / min_val if min_val > 0 else 0
            
            row.append(configs[min_idx]["label"])
            row.append(f"×{ratio:.2f}")
        else:
            row.append("N/A")
            row.append("N/A")
        
        print(make_table_row(row))
    
    print()
    
    # === 表 2: Verify 性能对比 ===
    print("## Verify 性能对比 (ms)\n")
    
    print(make_table_row(header))
    print(make_separator(len(header)))
    
    for sid in ORDER:
        row = [DISPLAY_NAME.get(sid, sid)]
        values = []
        
        for cfg in configs:
            if sid in cfg["data"]:
                mean_us = cfg["data"][sid]["verify"]["mean_us"]
                std_us = cfg["data"][sid]["verify"]["std_dev_us"]
                row.append(f"{fmt_ms(mean_us)} ± {fmt_ms(std_us)}")
                values.append(mean_us)
            else:
                row.append("N/A")
                values.append(float('inf'))
        
        # 计算最快和最慢
        valid_values = [v for v in values if v != float('inf')]
        if valid_values:
            min_val = min(valid_values)
            max_val = max(valid_values)
            min_idx = values.index(min_val)
            ratio = max_val / min_val if min_val > 0 else 0
            
            row.append(configs[min_idx]["label"])
            row.append(f"×{ratio:.2f}")
        else:
            row.append("N/A")
            row.append("N/A")
        
        print(make_table_row(row))
    
    print()
    
    # === 表 3: AES vs SM4 速度比 (基于最新配置) ===
    print("## AES vs SM4 速度比较 (基于最新配置)\n")
    
    latest_cfg = configs[-1]
    data = latest_cfg["data"]
    
    print(f"**配置:** {latest_cfg['label']}\n")
    
    comparisons = [
        ("faest_128s", "faest_sm4_128s", "Standard 模式"),
        ("faest_em_128s", "faest_em_sm4_128s", "EM 模式"),
    ]
    
    header2 = ["对比", "操作", "AES (ms)", "SM4 (ms)", "AES 优势"]
    print(make_table_row(header2))
    print(make_separator(len(header2)))
    
    for aes_sid, sm4_sid, label in comparisons:
        if aes_sid in data and sm4_sid in data:
            # Sign 对比
            aes_sign = data[aes_sid]["sign"]["mean_us"]
            sm4_sign = data[sm4_sid]["sign"]["mean_us"]
            ratio_sign = sm4_sign / aes_sign if aes_sign > 0 else 0
            
            row_sign = [label, "Sign", fmt_ms(aes_sign), fmt_ms(sm4_sign), f"×{ratio_sign:.2f} 快"]
            print(make_table_row(row_sign))
            
            # Verify 对比
            aes_verify = data[aes_sid]["verify"]["mean_us"]
            sm4_verify = data[sm4_sid]["verify"]["mean_us"]
            ratio_verify = sm4_verify / aes_verify if aes_verify > 0 else 0
            
            row_verify = ["", "Verify", fmt_ms(aes_verify), fmt_ms(sm4_verify), f"×{ratio_verify:.2f} 快"]
            print(make_table_row(row_verify))
    
    print()
    
    # === 表 4: 签名大小对比 ===
    print("## 签名大小对比 (bytes)\n")
    
    header3 = ["变体"] + [cfg["label"] for cfg in configs]
    print(make_table_row(header3))
    print(make_separator(len(header3)))
    
    for sid in ORDER:
        row = [DISPLAY_NAME.get(sid, sid)]
        
        for cfg in configs:
            if sid in cfg["data"]:
                sig_size = cfg["data"][sid].get("sig_size_bytes", "?")
                row.append(str(sig_size))
            else:
                row.append("N/A")
        
        print(make_table_row(row))
    
    print()


def make_table_row(cells):
    """生成 Markdown 表格行"""
    return "| " + " | ".join(str(c) for c in cells) + " |"


def make_separator(num_cols):
    """生成 Markdown 表格分隔符"""
    return "| " + " | ".join("---" for _ in range(num_cols)) + " |"


def main():
    parser = argparse.ArgumentParser(
        description="对比多个 FAEST benchmark 配置",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 bench_compare.py \\
      benchmark_results_with_aesni.jsonl \\
      benchmark_results_no_optimizations.jsonl \\
      --labels "AES-NI enabled" "Pure Software"
      
  python3 bench_compare.py file1.jsonl file2.jsonl -o output.md
        """
    )
    
    parser.add_argument(
        "files",
        nargs="+",
        help="要对比的 benchmark JSONL 文件"
    )
    
    parser.add_argument(
        "--labels", "-l",
        nargs="+",
        help="每个配置的标签（按文件顺序）"
    )
    
    parser.add_argument(
        "--output", "-o",
        help="输出 Markdown 文件（默认输出到 stdout）"
    )
    
    args = parser.parse_args()
    
    # 重定向输出
    if args.output:
        sys.stdout = open(args.output, 'w', encoding='utf-8')
    
    try:
        compare_configs(args.files, args.labels)
    finally:
        if args.output:
            sys.stdout.close()
            sys.stdout = sys.__stdout__
            print(f"[info] 对比表格已保存到: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
