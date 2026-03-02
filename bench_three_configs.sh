#!/bin/bash
# 三组独立配置基准测试 —— 每组使用独立构建目录，互不污染
# 用法: bash bench_three_configs.sh [--samples N]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES=5
VARIANTS="faest_128s faest_em_128s faest_sm4_128s faest_em_sm4_128s"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --samples) SAMPLES="$2"; shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

# ── 构建单组 ─────────────────────────────────────────────────────────────────
build_config() {
  local dir="$1"; shift
  local label="$1"; shift
  local opts=("$@")

  log "[$label] 构建到 $dir ..."
  mkdir -p "${SCRIPT_DIR}/${dir}"
  meson setup "${SCRIPT_DIR}/${dir}" "${SCRIPT_DIR}" \
    --buildtype=release \
    -Dbenchmarks=enabled \
    -Dcatch2=enabled \
    "${opts[@]}" \
    --reconfigure 2>&1 | tail -5

  ninja -C "${SCRIPT_DIR}/${dir}" -j"$(nproc)" 2>&1 | tail -3
  ok "[$label] 编译完成"
}

# ── 运行单组基准 ──────────────────────────────────────────────────────────────
run_bench() {
  local dir="$1"; shift
  local label="$1"; shift

  local cfg="${SCRIPT_DIR}/${dir}/config.h"
  local aesni=0; local avx2=0
  if [[ -f "$cfg" ]]; then
    aesni=$(grep -c "^#define HAVE_AESNI" "$cfg" || true)
    avx2=$(grep  -c "^#define HAVE_AVX2"  "$cfg" || true)
  fi

  echo ""
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}  $label${NC}"
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  [[ $aesni -gt 0 ]] && ok "AES-NI 已启用" || warn "AES-NI 未启用"
  [[ $avx2  -gt 0 ]] && ok "AVX2    已启用" || warn "AVX2 未启用"
  echo ""

  declare -A R_SIGN R_VERIFY R_KEYGEN

  for v in $VARIANTS; do
    BIN="${SCRIPT_DIR}/${dir}/${v}/${v}_bench_c2"
    if [[ ! -x "$BIN" ]]; then
      warn "跳过 ${v}（未找到可执行文件）"
      continue
    fi

    log "测试 ${v} ..."
    RAW=$(timeout 600 "$BIN" '[bench]' --benchmark-samples "${SAMPLES}" 2>/dev/null)

    get_mean() {
      local op="$1"
      echo "$RAW" | awk -v target="$op" '
        $1 == target { grab=1; next }
        grab && /^[[:space:]]+[0-9]/ {
          gsub(/^[[:space:]]+/, "")
          split($0, a, " ")
          printf "%s %s", a[1], a[2]
          exit
        }
        grab && /^[[:space:]]*$/ { next }
      '
    }

    R_SIGN[$v]=$(get_mean "sign")
    R_VERIFY[$v]=$(get_mean "verify")
    R_KEYGEN[$v]=$(get_mean "keygen")
  done

  printf "\n${BOLD}%-26s  %18s  %18s  %18s${NC}\n" \
    "参数集" "keygen (mean)" "sign (mean)" "verify (mean)"
  printf "%-26s  %18s  %18s  %18s\n" \
    "──────────────────────────" "──────────────────" "──────────────────" "──────────────────"

  for v in $VARIANTS; do
    if [[ -n "${R_SIGN[$v]+x}" ]]; then
      printf "%-26s  %18s  %18s  %18s\n" \
        "$v" "${R_KEYGEN[$v]:--}" "${R_SIGN[$v]:--}" "${R_VERIFY[$v]:--}"
    fi
  done
  echo ""
}

# ════════════════════════════════════════════════════════════════
# 组 1: AES-NI + AVX2（march=native 自动启用）
# ════════════════════════════════════════════════════════════════
build_config "build_bench_full" "AES-NI+AVX2" \
  -Daesni=enabled \
  -Dmarch-native=enabled

# ════════════════════════════════════════════════════════════════
# 组 2: 无 AES-NI，但保留 march=native（SHA3 仍可走 AVX2）
# ════════════════════════════════════════════════════════════════
build_config "build_bench_no_aesni" "无AES-NI+有AVX2(march-native)" \
  -Daesni=disabled \
  -Dmarch-native=enabled

# ════════════════════════════════════════════════════════════════
# 组 3: 完全纯软件（无 AES-NI，无 march=native，SHA3=plain32）
# ════════════════════════════════════════════════════════════════
build_config "build_bench_plain" "纯软件(无AES-NI,无AVX2)" \
  -Daesni=disabled \
  -Dmarch-native=disabled \
  -DSHA3=plain32

echo ""
log "所有构建完成，开始运行基准测试（每组 ${SAMPLES} 次采样）..."

run_bench "build_bench_full"     "组1: AES-NI + AVX2（全部优化）"
run_bench "build_bench_no_aesni" "组2: 无 AES-NI，保留 march=native"
run_bench "build_bench_plain"    "组3: 纯软件（无任何硬件加速）"

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  完成时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
