#!/bin/bash
# FAEST 性能测试批处理脚本
# 用法: ./run_perf.sh [--samples N] [--skip-build] [--skip-tests]
# 默认: 5次采样，先构建再测试

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_release"
SAMPLES=5
SKIP_BUILD=0
SKIP_TESTS=0
VARIANTS="faest_128s faest_em_128s faest_sm4_128s faest_em_sm4_128s"

# ── 解析参数 ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --samples)   SAMPLES="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --skip-tests) SKIP_TESTS=1; shift ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done

# ── 颜色 ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# ── 构建 ─────────────────────────────────────────────────────────────────────
if [[ $SKIP_BUILD -eq 0 ]]; then
  log "配置构建目录（AES-NI + AVX2 + march=native + benchmarks）..."
  mkdir -p "${BUILD_DIR}"
  meson setup "${BUILD_DIR}" "${SCRIPT_DIR}" \
    --buildtype=release \
    -Daesni=disabled \
    -Dmarch-native=enabled \
    -Dbenchmarks=enabled \
    -Dcatch2=enabled \
    --reconfigure 2>&1 | tail -8

  log "编译中..."
  ninja -C "${BUILD_DIR}" -j"$(nproc)" 2>&1 | tail -5
  ok "编译完成"
  echo ""
fi

# 检查 config.h 中 AES 优化是否开启
if [[ -f "${BUILD_DIR}/config.h" ]]; then
  AESNI=$(grep -c "^#define HAVE_AESNI" "${BUILD_DIR}/config.h" || true)
  AVX2=$(grep  -c "^#define HAVE_AVX2"  "${BUILD_DIR}/config.h" || true)
  [[ $AESNI -gt 0 ]] && ok "AES-NI 已启用" || warn "AES-NI 未启用"
  [[ $AVX2  -gt 0 ]] && ok "AVX2    已启用" || warn "AVX2 未启用"
  echo ""
fi

# ── 正确性测试 ───────────────────────────────────────────────────────────────
if [[ $SKIP_TESTS -eq 0 ]]; then
  log "运行测试向量（test_sign_tv）..."
  "${BUILD_DIR}/tests/test_extended_tests" -t "*/test_sign_tv" 2>&1
  ok "所有测试向量通过"
  echo ""
fi

# ── 性能基准 ─────────────────────────────────────────────────────────────────
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  FAEST 性能基准测试（采样次数: ${SAMPLES}）${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# 结果临时存储
declare -A R_SIGN R_VERIFY R_KEYGEN

for v in $VARIANTS; do
  BIN="${BUILD_DIR}/${v}/${v}_bench_c2"
  if [[ ! -x "$BIN" ]]; then
    warn "跳过 ${v}（未找到可执行文件）"
    continue
  fi

  log "测试 ${v} ..."

  # 运行 bench，捕获完整输出
  RAW=$(timeout 600 "$BIN" '[bench]' --benchmark-samples "${SAMPLES}" 2>/dev/null)

  # Catch2 bench 输出格式:
  #   sign        3   1   522.259 ms     ← 本行：samples/iters/est
  #               129.706 ms  ...        ← 紧接第一个缩进行 = mean
  #               19.669 ms   ...        ← 第二个缩进行 = std dev
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

  SIGN=$(get_mean "sign")
  VERIFY=$(get_mean "verify")
  KEYGEN=$(get_mean "keygen")

  R_SIGN[$v]="$SIGN"
  R_VERIFY[$v]="$VERIFY"
  R_KEYGEN[$v]="$KEYGEN"
done

# ── 打印对比表 ───────────────────────────────────────────────────────────────
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

# ── 加速比计算(AES vs SM4，相同模式) ─────────────────────────────────────────
# 将时间字符串转成微秒浮点
to_us() {
  local val unit
  val=$(echo "$1" | awk '{print $1}')
  unit=$(echo "$1" | awk '{print $2}')
  awk -v v="$val" -v u="$unit" 'BEGIN {
    if      (u=="ns") printf "%.4f", v/1000
    else if (u=="us") printf "%.4f", v
    else if (u=="ms") printf "%.4f", v*1000
    else if (u=="s")  printf "%.4f", v*1000000
    else              printf "%.4f", v
  }'
}

if [[ -n "${R_SIGN[faest_128s]+x}" && -n "${R_SIGN[faest_sm4_128s]+x}" ]]; then
  echo -e "${BOLD}── 加速比（AES全优化 vs SM4纯软件）──────────────────────────${NC}"

  aes_sign=$(to_us "${R_SIGN[faest_128s]}")
  sm4_sign=$(to_us "${R_SIGN[faest_sm4_128s]}")
  ratio_sign=$(awk -v a="$aes_sign" -v b="$sm4_sign" 'BEGIN{printf "%.2f", b/a}')

  aes_verify=$(to_us "${R_VERIFY[faest_128s]}")
  sm4_verify=$(to_us "${R_VERIFY[faest_sm4_128s]}")
  ratio_verify=$(awk -v a="$aes_verify" -v b="$sm4_verify" 'BEGIN{printf "%.2f", b/a}')

  printf "  非EM模式: AES sign 比 SM4 快 ${GREEN}${BOLD}%sx${NC}，verify 快 ${GREEN}${BOLD}%sx${NC}\n" \
    "$ratio_sign" "$ratio_verify"
fi

if [[ -n "${R_SIGN[faest_em_128s]+x}" && -n "${R_SIGN[faest_em_sm4_128s]+x}" ]]; then
  aes_em_sign=$(to_us "${R_SIGN[faest_em_128s]}")
  sm4_em_sign=$(to_us "${R_SIGN[faest_em_sm4_128s]}")
  ratio_em_sign=$(awk -v a="$aes_em_sign" -v b="$sm4_em_sign" 'BEGIN{printf "%.2f", b/a}')

  aes_em_verify=$(to_us "${R_VERIFY[faest_em_128s]}")
  sm4_em_verify=$(to_us "${R_VERIFY[faest_em_sm4_128s]}")
  ratio_em_verify=$(awk -v a="$aes_em_verify" -v b="$sm4_em_verify" 'BEGIN{printf "%.2f", b/a}')

  printf "  EM  模式: AES sign 比 SM4 快 ${GREEN}${BOLD}%sx${NC}，verify 快 ${GREEN}${BOLD}%sx${NC}\n" \
    "$ratio_em_sign" "$ratio_em_verify"
fi

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  完成时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
