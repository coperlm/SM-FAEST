#!/usr/bin/env python3
"""
bench_table.py — 将 bench.sh 输出的 JSONL 格式化为 Markdown 对比表格

用法：
    ./bench.sh | tee run.jsonl | python3 bench_table.py
    python3 bench_table.py run.jsonl
    python3 bench_table.py benchmark_results.jsonl
    cat a.jsonl b.jsonl | python3 bench_table.py  # 合并对比多次历史记录
"""

import json
import sys
import os
import re
from collections import OrderedDict

# ──────────────────────────────────────────────────────────────
# 从 meson.build 动态读取 ELL / Lenc（避免硬编码）
# ──────────────────────────────────────────────────────────────
def load_meson_params(meson_path="meson.build"):
    """解析 meson.build，提取各 setting_id 的 ELL / Lenc。"""
    params = {}
    current = None
    # 变量名 → setting_id 映射  (param_XX → setting_id 由 PARAM_L 决定)
    var_to_param_l = {}

    if not os.path.exists(meson_path):
        return params

    with open(meson_path) as f:
        content = f.read()

    # 找出所有 param_XX = configuration_data() 块
    blocks = re.split(r'\n(?=param_\w+\s*=\s*configuration_data\(\))', content)
    for block in blocks:
        var_match = re.match(r'(param_\w+)\s*=\s*configuration_data\(\)', block)
        if not var_match:
            continue
        var_name = var_match.group(1)
        param_l_m = re.search(r"\.set\('PARAM_L',\s*'([^']+)'\)", block)
        ell_m     = re.search(r"\.set\('ELL',\s*(\d+)\)", block)
        lenc_m    = re.search(r"\.set\('Lenc',\s*(\d+)\)", block)
        if param_l_m:
            sid = "faest_" + param_l_m.group(1)
            params[sid] = {
                "ELL":  int(ell_m.group(1))  if ell_m  else "?",
                "Lenc": int(lenc_m.group(1)) if lenc_m else "?",
            }
    return params


# ──────────────────────────────────────────────────────────────
# 友好的变体显示名
# ──────────────────────────────────────────────────────────────
DISPLAY_NAME = {
    "faest_128s":        "AES-std-128s",
    "faest_em_128s":     "AES-EM-128s",
    "faest_sm4_128s":    "SM4-std-128s",
    "faest_em_sm4_128s": "SM4-EM-128s",
}

# 展示顺序
ORDER = ["faest_128s", "faest_em_128s", "faest_sm4_128s", "faest_em_sm4_128s"]


def us_to_ms(us):
    return us / 1000.0


def fmt_ms(us):
    ms = us_to_ms(us)
    return f"{ms:.1f}"


def fmt_ms_pm(mean_us, std_us):
    return f"{us_to_ms(mean_us):.1f} ± {us_to_ms(std_us):.1f}"


def load_jsonl(paths):
    """按 setting_id 聚合，同一 setting_id 多条记录保留最新的（按 meta.timestamp 排序）。"""
    records = {}  # setting_id → list of entries
    for path in paths:
        try:
            src = open(path) if path != "-" else sys.stdin
            for line in src:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                sid = d.get("setting_id", "")
                if sid not in records:
                    records[sid] = []
                records[sid].append(d)
            if path != "-":
                src.close()
        except FileNotFoundError:
            print(f"[warn] 文件未找到：{path}", file=sys.stderr)
    # 每个 setting_id 按 timestamp 排序，最新在后
    for sid in records:
        records[sid].sort(key=lambda d: d.get("meta", {}).get("timestamp", ""))
    return records


def print_table(records, meson_params):
    # ── 表 1：最新一次运行数据 ──
    print("## 最新 Benchmark 结果\n")
    header = ["变体", "ELL", "Lenc", "SIG (B)", "Sign (ms)", "Verify (ms)", "Commit"]
    col_w  = [16, 6, 6, 9, 20, 20, 10]

    def row_str(cells):
        return "| " + " | ".join(str(c).ljust(col_w[i]) for i, c in enumerate(cells)) + " |"

    sep = "| " + " | ".join("-" * col_w[i] for i in range(len(header))) + " |"
    print(row_str(header))
    print(sep)

    for sid in ORDER:
        if sid not in records:
            continue
        d   = records[sid][-1]   # 最新
        mp  = meson_params.get(sid, {})
        ell  = mp.get("ELL",  "?")
        lenc = mp.get("Lenc", "?")
        sig  = d.get("sig_size_bytes", "?")
        sign_ms  = fmt_ms_pm(d["sign"]["mean_us"],   d["sign"]["std_dev_us"])
        verify_ms= fmt_ms_pm(d["verify"]["mean_us"], d["verify"]["std_dev_us"])
        commit   = d.get("meta", {}).get("git_commit", "?")[:8]
        name     = DISPLAY_NAME.get(sid, sid)
        print(row_str([name, ell, lenc, sig, sign_ms, verify_ms, commit]))

    print()

    # ── 表 2：sign/verify 横向比较（以 AES-EM 为 1× 基准）──
    em_aes = records.get("faest_em_128s", [None])[-1]
    if em_aes:
        print("## 相对 AES-EM-128s 的倍数（Sign / Verify）\n")
        base_sign   = em_aes["sign"]["mean_us"]
        base_verify = em_aes["verify"]["mean_us"]

        h2  = ["变体", "Sign (ms)", "×Sign", "Verify (ms)", "×Verify", "SIG (B)", "×SIG"]
        cw2 = [16, 12, 6, 13, 8, 9, 6]
        def row2(cells):
            return "| " + " | ".join(str(c).ljust(cw2[i]) for i, c in enumerate(cells)) + " |"
        sep2 = "| " + " | ".join("-" * cw2[i] for i in range(len(h2))) + " |"
        print(row2(h2))
        print(sep2)

        base_sig = em_aes.get("sig_size_bytes", 1)
        for sid in ORDER:
            if sid not in records:
                continue
            d    = records[sid][-1]
            name = DISPLAY_NAME.get(sid, sid)
            s_us = d["sign"]["mean_us"]
            v_us = d["verify"]["mean_us"]
            sig  = d.get("sig_size_bytes", 0)
            xs   = f"×{s_us/base_sign:.2f}"
            xv   = f"×{v_us/base_verify:.2f}"
            xsig = f"×{sig/base_sig:.2f}"
            print(row2([name, fmt_ms(s_us), xs, fmt_ms(v_us), xv, sig, xsig]))
        print()

    # ── 表 3：历史演进（同一 setting_id 有多次记录时） ──
    multi = {sid: vs for sid, vs in records.items() if len(vs) > 1}
    if multi:
        print("## 历史演进（多次 benchmark 对比）\n")
        for sid in ORDER:
            if sid not in multi:
                continue
            name = DISPLAY_NAME.get(sid, sid)
            print(f"### {name}\n")
            h3  = ["Commit", "SIG (B)", "Sign (ms)", "Verify (ms)", "Timestamp"]
            cw3 = [10, 9, 18, 18, 28]
            def row3(cells):
                return "| " + " | ".join(str(c).ljust(cw3[i]) for i, c in enumerate(cells)) + " |"
            sep3 = "| " + " | ".join("-" * cw3[i] for i in range(len(h3))) + " |"
            print(row3(h3))
            print(sep3)
            for d in multi[sid]:
                commit    = d.get("meta", {}).get("git_commit", "?")[:8]
                sig       = d.get("sig_size_bytes", "?")
                sign_ms   = fmt_ms_pm(d["sign"]["mean_us"],   d["sign"]["std_dev_us"])
                verify_ms = fmt_ms_pm(d["verify"]["mean_us"], d["verify"]["std_dev_us"])
                ts        = d.get("meta", {}).get("timestamp", "?")[:19]
                print(row3([commit, sig, sign_ms, verify_ms, ts]))
            print()


def main():
    # 确定输入来源
    args = sys.argv[1:]
    if not args:
        # 尝试默认路径
        defaults = ["benchmark_results.jsonl"]
        found = [p for p in defaults if os.path.exists(p)]
        if found:
            paths = found
            print(f"[info] 读取：{', '.join(paths)}", file=sys.stderr)
        else:
            paths = ["-"]   # stdin
    else:
        paths = args

    meson_params = load_meson_params("meson.build")
    records = load_jsonl(paths)

    if not records:
        print("[error] 未读取到任何 benchmark 数据。", file=sys.stderr)
        sys.exit(1)

    print_table(records, meson_params)


if __name__ == "__main__":
    main()
