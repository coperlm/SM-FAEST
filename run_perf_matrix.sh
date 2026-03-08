#!/usr/bin/env bash
# run_perf_matrix.sh  –  全矩阵性能测试
# 用法: bash run_perf_matrix.sh [采样次数]

SAMPLES=${1:-5}
VARIANTS="faest_128s faest_em_128s faest_sm4_128s faest_em_sm4_128s"
CFGS="oo on no nn"

parse_us() {
  local op="$1"
  awk -v op="$op" '
  $1==op && NF>=4 {
    getline
    for(i=1;i<=NF;i++){
      if($i+0>0){
        val=$i; unit=$(i+1)
        if(unit=="ns")  { printf "%.2f", val/1000;  exit }
        if(unit=="us")  { printf "%.2f", val;        exit }
        if(unit=="ms")  { printf "%.2f", val*1000;   exit }
        if(unit=="s")   { printf "%.2f", val*1e6;    exit }
      }
    }
  }
  '
}

SEP="$(printf '%0.s-' {1..88})"
printf "\n%-24s %-8s %-8s  %13s %13s %13s\n" \
  "Variant" "OpenSSL" "HW-AES" "keygen(us)" "sign(us)" "verify(us)"
echo "$SEP"

for cfg in $CFGS; do
  case $cfg in
    oo) ossl="on";  hw="on"  ;;
    on) ossl="on";  hw="off" ;;
    no) ossl="off"; hw="on"  ;;
    nn) ossl="off"; hw="off" ;;
  esac
  dir="build_perf_${cfg}"

  for v in $VARIANTS; do
    exe="./${dir}/${v}/${v}_bench_c2"
    [[ -x "$exe" ]] || { printf "  [SKIP] %s\n" "$exe" >&2; continue; }

    printf "  %-28s openssl=%-3s hw-aes=%-3s ... " "$v" "$ossl" "$hw" >&2
    raw=$("$exe" "[bench]" --benchmark-samples "$SAMPLES" 2>/dev/null)

    kg=$(parse_us keygen  <<< "$raw")
    sg=$(parse_us sign    <<< "$raw")
    vf=$(parse_us verify  <<< "$raw")
    echo "done" >&2

    printf "%-24s %-8s %-8s  %13s %13s %13s\n" \
      "$v" "$ossl" "$hw" "${kg:--}" "${sg:--}" "${vf:--}"
  done
  echo "$SEP"
done
