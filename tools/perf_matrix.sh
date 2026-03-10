#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLES=20
VARIANTS="faest_128s faest_em_128s faest_sm4_128s faest_em_sm4_128s"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --samples) SAMPLES="$2"; shift 2 ;;
    *) echo "用法: $0 [--samples N]" >&2; exit 1 ;;
  esac
done

# ANSI 颜色
C_INFO='\033[0;36m'; C_OK='\033[0;32m'; C_WARN='\033[1;33m'; C_RESET='\033[0m'
log()  { echo -e "${C_INFO}[INFO]${C_RESET} $*" >&2; }
ok()   { echo -e "${C_OK}[ OK ]${C_RESET} $*" >&2; }
warn() { echo -e "${C_WARN}[WARN]${C_RESET} $*" >&2; }

# ── 步骤 1: 定义 4 个构建配置 ────────────────────────────────────────
declare -A CFG_DIR CFG_OPTS CFG_LABEL

CFG_DIR[nn]="bpm_ni_ssl"
CFG_OPTS[nn]="-Daesni=enabled -Dopenssl=enabled -Dbenchmarks=enabled --buildtype=release"
CFG_LABEL[nn]="NI=ON  / SSL=ON"

CFG_DIR[no]="bpm_ni_nossl"
CFG_OPTS[no]="-Daesni=enabled -Dopenssl=disabled -Dbenchmarks=enabled --buildtype=release"
CFG_LABEL[no]="NI=ON  / SSL=OFF"

CFG_DIR[on]="bpm_noni_ssl"
CFG_OPTS[on]="-Daesni=disabled -Dopenssl=enabled -Dbenchmarks=enabled --buildtype=release"
CFG_LABEL[on]="NI=OFF / SSL=ON"

CFG_DIR[oo]="bpm_noni_nossl"
CFG_OPTS[oo]="-Daesni=disabled -Dopenssl=disabled -Dbenchmarks=enabled --buildtype=release"
CFG_LABEL[oo]="NI=OFF / SSL=OFF"

CONFIGS="nn no on oo"

# ── 步骤 2: 构建所有配置 ─────────────────────────────────────────────
for key in $CONFIGS; do
  dir="${ROOT}/${CFG_DIR[$key]}"
  label="${CFG_LABEL[$key]}"
  opts_str="${CFG_OPTS[$key]}"
  log "[$label] 配置 → ${CFG_DIR[$key]} ..."

  # 若目录已存在则 reconfigure，否则新建
  meson_flag="--wipe"
  [[ -d "$dir" ]] && meson_flag="--reconfigure"
  # shellcheck disable=SC2086
  meson setup "$dir" "$ROOT" $opts_str $meson_flag 2>&1 | tail -4 >&2

  log "[$label] 编译中（$(nproc) 核）..."
  ninja -C "$dir" -j"$(nproc)" 2>&1 | grep -E "Linking|error:" >&2 || true
  ok "[$label] 编译完成"
done

# ── 步骤 3: 运行基准，收集原始数据 ───────────────────────────────────
# 结果保存在关联数组 DATA[$key,$variant,$op] = 均值(µs)

declare -A DATA   # DATA["nn,faest_128s,sign"] = 均值整数(µs)

awk_mean() {
  # stdin: N 行 "keygen_us,sign_us,verify_us"
  # $1: 列索引 (1=keygen, 2=sign, 3=verify)
  awk -F',' -v col="$1" '
    NF==3 && $col+0 > 0 { sum += $col; n++ }
    END { if (n>0) printf "%.0f", sum/n; else print "N/A" }
  '
}

for key in $CONFIGS; do
  dir="${ROOT}/${CFG_DIR[$key]}"
  label="${CFG_LABEL[$key]}"

  for v in $VARIANTS; do
    BIN="$dir/${v}/${v}_bench"
    if [[ ! -x "$BIN" ]]; then
      warn "[$label] 未找到 $BIN，跳过"
      DATA["$key,$v,keygen"]="N/A"
      DATA["$key,$v,sign"]="N/A"
      DATA["$key,$v,verify"]="N/A"
      continue
    fi

    log "[$label] 运行 $v （${SAMPLES} 次迭代）..."
    # bench 输出格式: keygen_µs,sign_µs,verify_µs  每行一次
    RAW=$(timeout 600 "$BIN" -i "$SAMPLES" 2>/dev/null)

    DATA["$key,$v,keygen"]=$(echo "$RAW" | awk_mean 1)
    DATA["$key,$v,sign"]=$(echo   "$RAW" | awk_mean 2)
    DATA["$key,$v,verify"]=$(echo "$RAW" | awk_mean 3)
    ok "[$label] $v  sign=${DATA[$key,$v,sign]} µs  verify=${DATA[$key,$v,verify]} µs"
  done
done

# ── 步骤 4: 转换单位并格式化 ─────────────────────────────────────────
fmt_us() {
  local v="$1"
  if [[ "$v" == "N/A" ]]; then echo "N/A"; return; fi
  if   (( v >= 1000000 )); then printf "%.2f s"  "$(echo "scale=4; $v/1000000" | bc)"
  elif (( v >= 1000    )); then printf "%.1f ms" "$(echo "scale=4; $v/1000"    | bc)"
  else                          printf "%d µs" "$v"
  fi
}

# ── 步骤 5: 输出 Markdown 表格 ─────────────────────────────────────
echo ""
echo "## FAEST 性能对比矩阵（$SAMPLES 次采样均值，release 编译）"
echo ""
echo "> 构建日期: $(date '+%Y-%m-%d %H:%M:%S')  "
echo "> 主机: $(uname -n)  CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
echo ""

# 大表头
printf "| %-24s | %-14s | " "算法 / 操作" "配置"
printf "%10s | %10s | %10s |\n" "Keygen" "Sign" "Verify"
printf "|:%-24s|:%-14s:|" "$(printf '%0.s-' {1..24})" "$(printf '%0.s-' {1..14})"
printf "%10s:|%10s:|%10s:|\n" "----------" "----------" "----------"

for v in $VARIANTS; do
  first=1
  for key in $CONFIGS; do
    label="${CFG_LABEL[$key]}"
    kg=$(fmt_us "${DATA[$key,$v,keygen]}")
    sg=$(fmt_us "${DATA[$key,$v,sign]}")
    vf=$(fmt_us "${DATA[$key,$v,verify]}")

    if [[ $first -eq 1 ]]; then
      printf "| %-24s | %-14s | %10s | %10s | %10s |\n" \
        "$v" "$label" "$kg" "$sg" "$vf"
      first=0
    else
      printf "| %-24s | %-14s | %10s | %10s | %10s |\n" \
        "" "$label" "$kg" "$sg" "$vf"
    fi
  done
  # 分割线
  printf "|:%-24s|:%-14s:|%10s:|%10s:|%10s:|\n" \
    "$(printf '%0.s-' {1..24})" "$(printf '%0.s-' {1..14})" \
    "----------" "----------" "----------"
done

# ── 步骤 6: 加速比小结 ────────────────────────────────────────────────
echo ""
echo "## 加速比（Sign 均值，相对 NI=OFF / SSL=OFF）"
echo ""
printf "| %-24s | %12s | %12s | %12s | %12s |\n" \
  "算法" "NI=ON/SSL=ON" "NI=ON/SSL=OFF" "NI=OFF/SSL=ON" "NI=OFF/SSL=OFF"
printf "|:%-24s|%12s:|%12s:|%12s:|%12s:|\n" \
  "$(printf '%0.s-' {1..24})" "$(printf '%0.s-' {1..12})" \
  "$(printf '%0.s-' {1..12})" "$(printf '%0.s-' {1..12})" "$(printf '%0.s-' {1..12})"

for v in $VARIANTS; do
  base="${DATA[oo,$v,sign]}"
  row="| $(printf '%-24s' "$v")"
  for key in nn no on oo; do
    val="${DATA[$key,$v,sign]}"
    if [[ "$val" == "N/A" || "$base" == "N/A" || "$base" -eq 0 ]]; then
      row+=" | $(printf '%11s' 'N/A')"
    elif [[ "$key" == "oo" ]]; then
      row+=" | $(printf '%10s' '1.00×')"
    else
      ratio=$(awk "BEGIN{ printf \"%.2f×\", $base/$val }")
      row+=" | $(printf '%11s' "$ratio")"
    fi
  done
  echo "$row |"
done
