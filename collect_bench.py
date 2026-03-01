#!/usr/bin/env python3
"""
collect_bench.py — 运行所有 FAEST 变体的 Catch2 基准测试，输出 JSONL

输出格式与 bench.sh 相同，可直接传给 bench_table.py:
    python3 collect_bench.py | tee benchmark_results.jsonl | python3 bench_table.py
    python3 collect_bench.py some.jsonl                  # 同时保存到文件
"""

import json
import os
import re
import subprocess
import sys
import datetime

BUILD = "build_release"

VARIANTS = [
    ("faest_128s",        "FAEST_128S"),
    ("faest_em_128s",     "FAEST_EM_128S"),
    ("faest_sm4_128s",    "FAEST_SM4_128S"),
    ("faest_em_sm4_128s", "FAEST_EM_SM4_128S"),
]


def parse_us(token_pair: str) -> float:
    """将 Catch2 时间字符串（如 '38.3 ms'）转换为 microseconds。"""
    m = re.match(r"([\d.]+)\s*(ns|us|ms|s)", token_pair.strip())
    if not m:
        return 0.0
    v, u = float(m.group(1)), m.group(2)
    return {"ns": v / 1000, "us": v, "ms": v * 1000, "s": v * 1e6}[u]


def parse_block(text: str, op: str) -> dict:
    """从 bench_c2 输出中提取 keygen/sign/verify 的统计块。"""
    lines = [l for l in text.splitlines() if l.strip()]
    for i, line in enumerate(lines):
        if re.match(rf"^{op}\s", line):
            f1 = line.split()
            f2 = lines[i + 1].split() if i + 1 < len(lines) else []
            f3 = lines[i + 2].split() if i + 2 < len(lines) else []
            return {
                "samples":        int(f1[1]),
                "iterations":     int(f1[2]),
                "estimated":      parse_us(" ".join(f1[3:5])),
                "mean_us":        parse_us(" ".join(f2[0:2])),
                "low_mean_us":    parse_us(" ".join(f2[2:4])),
                "high_mean_us":   parse_us(" ".join(f2[4:6])),
                "std_dev_us":     parse_us(" ".join(f3[0:2])),
                "low_std_dev_us": parse_us(" ".join(f3[2:4])),
                "high_std_dev_us":parse_us(" ".join(f3[4:6])),
            }
    return {}


def read_api(sid: str) -> dict:
    path = os.path.join(BUILD, sid, "api.h")
    with open(path) as f:
        txt = f.read()
    def grep_int(pat):
        m = re.search(pat + r"\s+(\d+)", txt)
        return int(m.group(1)) if m else 0
    return {
        "sig": grep_int("CRYPTO_BYTES"),
        "sk":  grep_int("CRYPTO_SECRETKEYBYTES"),
        "pk":  grep_int("CRYPTO_PUBLICKEYBYTES"),
    }


def gather_meta() -> dict:
    hostname = subprocess.check_output(["uname", "-n"]).decode().strip()
    user = os.environ.get("USER", "")
    timestamp = datetime.datetime.now().astimezone().isoformat()
    git_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
    ).decode().strip()
    return {"hostname": hostname, "user": user,
            "timestamp": timestamp, "git_commit": git_commit}


def run_variant(sid: str, name: str, meta: dict) -> dict:
    bench_bin = os.path.join(".", BUILD, sid, f"{sid}_bench_c2")
    print(f"  benching {sid}...", file=sys.stderr, flush=True)
    out = subprocess.check_output(
        [bench_bin, "[bench]"], stderr=subprocess.DEVNULL
    ).decode()
    api = read_api(sid)
    return {
        "implementation": "ref",
        "variant":        name,
        "setting_id":     sid,
        "sig_size_bytes": api["sig"],
        "sk_size_bytes":  api["sk"],
        "pk_size_bytes":  api["pk"],
        "keygen":         parse_block(out, "keygen"),
        "sign":           parse_block(out, "sign"),
        "verify":         parse_block(out, "verify"),
        "meta":           meta,
    }


def main():
    # 可选：指定输出文件名作为命令行参数
    out_file = sys.argv[1] if len(sys.argv) > 1 else None
    meta = gather_meta()
    print(f"  git commit: {meta['git_commit'][:8]}", file=sys.stderr)

    records = []
    for sid, name in VARIANTS:
        rec = run_variant(sid, name, meta)
        line = json.dumps(rec)
        print(line)          # → stdout (供管道传给 bench_table.py)
        records.append(line)

    if out_file:
        with open(out_file, "w") as f:
            f.write("\n".join(records) + "\n")
        print(f"  saved to {out_file}", file=sys.stderr)


if __name__ == "__main__":
    main()
