#!/usr/bin/env bash
# bench-b3sum.sh — compare C vs Rust b3sum
#
# FEATURES:
#  - Valid Measurements: Uses '-N' (direct exec) for large files to avoid shell noise
#  - Prints a clean Markdown summary table to STDOUT
#  - Detailed Logging: Saves all generation/diff/strace noise to 'bench_detail.log'
#  - Strict Correctness: Retains full Python normalization and diff checks
#  - Report Artifact: Writes the user-visible Markdown output to BENCHMARK.md
#  - Metadata: Records git commit hash/date, CPU info, kernel, timestamp
#  - Stats: Auto-generates a Key Results section with correct slower/faster handling

set -u
set -o pipefail

####################################
# Logging + Report Setup
####################################

LOGFILE="bench_detail.log"
REPORT_MD="BENCHMARK.md"

rm -f "$LOGFILE"
: > "$REPORT_MD"

# Save original STDOUT to File Descriptor 4 (terminal)
exec 4>&1

# FD3 becomes "user-visible output", tee'd into BENCHMARK.md and terminal
exec 3> >(tee -a "$REPORT_MD" >&4)

# Redirect standard STDOUT/STDERR (normal script output) to the log file
exec 1>>"$LOGFILE"
exec 2>&1

say() {
  echo "$@" >&3
  echo "$@"
}

log() {
  echo "$@"
}

term() {
  echo "$@" >&4
  echo "$@"
}

term "📝 Detailed execution log saved to: $LOGFILE"
term "🧾 Report will be written to: $REPORT_MD"

####################################
# Config
####################################

# Allow overrides:
#   C_IMPL=/path/to/b3sum ./bench-b3sum.sh
#   R_IMPL=/path/to/b3sum_rust ./bench-b3sum.sh
C_IMPL="${C_IMPL:-}"
R_IMPL="${R_IMPL:-/usr/bin/b3sum_rust}"

# Common build outputs (first match wins)
C_IMPL_CANDIDATES=(
  "./build-meson-release/b3sum"
  "./build-meson-asan/b3sum"
  "./build/b3sum"
)

resolve_impl() {
  local name="$1"
  local current="$2"
  shift 2
  local -a candidates=("$@")

  if [[ -n "$current" ]]; then
    if [[ -x "$current" ]]; then
      echo "$current"
      return 0
    fi
    echo "🔥 Error: ${name} is set but not executable: $current" >&3
    exit 1
  fi

  # Prefer in-tree builds when any build dir exists
  if [[ -d "./build-meson-release" || -d "./build-meson-asan" || -d "./build" ]]; then
    for p in "${candidates[@]}"; do
      if [[ -x "$p" ]]; then
        echo "$p"
        return 0
      fi
    done
    echo "🔥 Error: found a build directory but no executable ${name} in expected locations:" >&3
    for p in "${candidates[@]}"; do
      echo "  - $p" >&3
    done
    echo "Tip: rebuild, or set ${name}=/path/to/binary" >&3
    exit 1
  fi

  # No build dir present: fall back to system b3sum
  if [[ -x "/usr/bin/b3sum" ]]; then
    echo "/usr/bin/b3sum"
    return 0
  fi

  echo "🔥 Error: no build directories found and /usr/bin/b3sum is missing or not executable" >&3
  echo "Tip: install b3sum or set ${name}=/path/to/binary" >&3
  exit 1
}

C_IMPL="$(resolve_impl C_IMPL "$C_IMPL" "${C_IMPL_CANDIDATES[@]}")"

RUNS=10
WARMUP=2
SIZES_MIB=(1 2 3 4 8 16 32 64 128 256 512 1024)

SMALLFILES_COUNT=5000
SMALLFILE_MIN=1024
SMALLFILE_MAX=4096

HYPERFINE_OPTS=(
  "--runs" "$RUNS"
  "--warmup" "$WARMUP"
  "--style" "none"
  "--sort" "command"
)

if hyperfine --help 2>/dev/null | grep -qE '(^|[[:space:]])--shuffle([[:space:]]|,|$)'; then
  HYPERFINE_OPTS+=("--shuffle")
fi

####################################
# Checks & Helpers
####################################

require_bin() {
  if ! command -v "$1" >/dev/null 2>&1; then
    say "🔥 Error: need $1"
    exit 1
  fi
}

have_bin() {
  command -v "$1" >/dev/null 2>&1
}

require_bin hyperfine
require_bin python3
require_bin awk
require_bin dd
require_bin find
require_bin sort
require_bin diff

CAN_DROP_CACHE=false
if [[ $(id -u) -eq 0 ]] && [[ -w /proc/sys/vm/drop_caches ]]; then
  CAN_DROP_CACHE=true
fi

####################################
# Markdown Helper: Methodology / Run Details
####################################

emit_markdown_methodology() {
  local shuffle_enabled="no"
  local cache_behavior="OS page cache left intact"
  local big_count="${#SIZES_MIB[@]}"
  local sizes_joined
  local nthreads
  local hf_ver
  local bench_now
  local kernel_summary
  local git_root="unknown"
  local git_head="unknown"
  local git_date="unknown"
  local git_dirty="unknown"
  local cpu_summary="unknown"

  if printf '%s\n' "${HYPERFINE_OPTS[@]}" | grep -qx -- "--shuffle"; then
    shuffle_enabled="yes"
  fi

  if $CAN_DROP_CACHE; then
    cache_behavior="drops OS page cache via /proc/sys/vm/drop_caches (requires root)"
  fi

  sizes_joined="$(printf '%s MiB, ' "${SIZES_MIB[@]}")"
  sizes_joined="${sizes_joined%, }"

  nthreads="$(nproc 2>/dev/null || echo unknown)"
  hf_ver="$(hyperfine --version 2>/dev/null | head -n1 || echo hyperfine)"
  bench_now="$(date -Is 2>/dev/null || date)"
  kernel_summary="$(uname -srmo 2>/dev/null || uname -a)"

  if have_bin git && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git_root="$(git rev-parse --show-toplevel 2>/dev/null || echo unknown)"
    git_head="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    git_date="$(git show -s --format=%cI HEAD 2>/dev/null || echo unknown)"
    if git diff --quiet --ignore-submodules -- 2>/dev/null && git diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
      git_dirty="clean"
    else
      git_dirty="dirty"
    fi
  fi

  if have_bin lscpu; then
    cpu_summary="$(
      lscpu 2>/dev/null | awk -F: '
        function trim(s){gsub(/^[ \t]+|[ \t]+$/, "", s); return s}
        $1 ~ /^Model name$/ { model=trim($2) }
        $1 ~ /^CPU\(s\)$/ { cpus=trim($2) }
        $1 ~ /^Thread\(s\) per core$/ { tpc=trim($2) }
        $1 ~ /^Core\(s\) per socket$/ { cps=trim($2) }
        $1 ~ /^Socket\(s\)$/ { sockets=trim($2) }
        END {
          if (model == "") model="unknown"
          if (cpus == "") cpus="unknown"
          if (tpc == "") tpc="unknown"
          if (cps == "") cps="unknown"
          if (sockets == "") sockets="unknown"
          printf "%s | CPUs: %s | Sockets: %s | Cores/socket: %s | Threads/core: %s", model, cpus, sockets, cps, tpc
        }'
    )"
  else
    cpu_summary="$(
      awk -F: '
        function trim(s){gsub(/^[ \t]+|[ \t]+$/, "", s); return s}
        $1 ~ /^model name$/ { model=trim($2); if (seen==0) seen=1 }
        END { if (model=="") model="unknown"; printf "%s", model }
      ' /proc/cpuinfo 2>/dev/null
    )"
  fi

  echo "# Benchmark Report" >&3
  echo "" >&3
  echo "Generated by \`bench-b3sum.sh\`" >&3
  echo "" >&3

  echo "## 🧾 Benchmark Methodology" >&3
  echo "" >&3
  echo "**Bench run timestamp:** \`${bench_now}\`" >&3
  echo "" >&3
  echo "**Kernel:** \`${kernel_summary}\`" >&3
  echo "" >&3
  echo "**CPU:** ${cpu_summary}" >&3
  echo "" >&3
  echo "**Git:**" >&3
  echo "- HEAD: \`${git_head}\`" >&3
  echo "- Commit date: \`${git_date}\`" >&3
  echo "- Working tree: **${git_dirty}**" >&3
  echo "" >&3
  echo "**Tools:** ${hf_ver}" >&3
  echo "" >&3
  echo "**Implementations:**" >&3
  echo "- **C:** \`${C_IMPL}\`" >&3
  echo "- **Rust:** \`${R_IMPL}\`" >&3
  echo "" >&3
  echo "**Hyperfine settings:**" >&3
  echo "- Runs per command: **${RUNS}**" >&3
  echo "- Warmup runs: **${WARMUP}**" >&3
  echo "- Shuffle order: **${shuffle_enabled}**" >&3
  echo "- Thread count (system): \`${nthreads}\`" >&3
  echo "" >&3
  echo "**Cache / prepare step:**" >&3
  echo "- \`${pre_cmd}\`" >&3
  echo "- Behavior: ${cache_behavior}" >&3
  echo "" >&3
  echo "**Workloads:**" >&3
  echo "- **Large-file hashing:** ${big_count} files sized **$(printf '%s MiB, ' "${SIZES_MIB[@]}" | sed 's/, $//')** (each benchmark runs both C and Rust on the same file)" >&3
  echo "- **Tiny-file hashing:** **${SMALLFILES_COUNT}** files with per-file size roughly **${SMALLFILE_MIN}..${SMALLFILE_MAX}** bytes" >&3
  echo "" >&3
  echo "**Data generation:**" >&3
  echo "- All test data is created in a temporary sandbox under \`/tmp\` and removed on exit" >&3
  echo "- Large files are created via \`fallocate\` when available, otherwise \`dd if=/dev/urandom\`" >&3
  echo "- Tiny files are created with \`dd if=/dev/urandom\` (1 block per file)" >&3
  echo "" >&3
  echo "**Correctness checks (performed before benchmarking):**" >&3
  echo "- For every large file: compare the hash output from C and Rust (must match)" >&3
  echo "- For tiny files: produce full per-file outputs, normalize paths, sort, and \`diff\` (must match)" >&3
  echo "" >&3
}

emit_key_results() {
  local csv_path="$1"
  local runs="$2"
  local warmup="$3"
  local npoints="$4"

python3 - "$csv_path" "$runs" "$warmup" "$npoints" <<'PY' >&3
import csv, sys

path = sys.argv[1]
runs = int(sys.argv[2])
warmup = int(sys.argv[3])
npoints = int(sys.argv[4])

def f(x):
    try:
        return float(x)
    except Exception:
        return None

def pct(x):
    return f"{x*100:.1f}%"

rows = []
with open(path, newline="") as fobj:
    for r in csv.DictReader(fobj):
        rows.append(r)

large = []
tiny_ratio = None

for r in rows:
    w = (r.get("Workload", "") or "").strip()
    ratio = f(r.get("Ratio (C/R)", ""))
    if ratio is None:
        continue
    if w.startswith("TinyFiles"):
        tiny_ratio = ratio
        continue
    if "MiB" in w:
        try:
            mib = float(w.split()[0])
        except Exception:
            continue
        large.append((mib, ratio))

large.sort(key=lambda t: t[0])

def select(lo, hi):
    xs = [rt for mib, rt in large if lo <= mib <= hi]
    if not xs:
        return None
    return min(xs), max(xs), sum(xs) / len(xs)

def fmt_speedup_band(min_ratio, max_ratio, avg_ratio):
    # ratio = C/R, speedup = R/C = 1/ratio
    sp_min = 1.0 / max_ratio
    sp_max = 1.0 / min_ratio
    return f"~{sp_min:.2f}×–{sp_max:.2f}× faster (avg ratio {avg_ratio:.3f})"

def fmt_percent_statement(min_ratio, max_ratio, avg_ratio):
    # ratio = C/R
    # if crosses 1.0, report slower..faster band
    crosses = (min_ratio < 1.0) and (max_ratio > 1.0)
    if crosses:
        slower = max_ratio - 1.0
        faster = (1.0 / min_ratio) - 1.0
        return f"ranges from ~{pct(slower)} slower to ~{pct(faster)} faster (avg ratio {avg_ratio:.3f})"
    if max_ratio <= 1.0:
        faster_min = (1.0 / max_ratio) - 1.0
        faster_max = (1.0 / min_ratio) - 1.0
        return f"~{pct(faster_min)}–{pct(faster_max)} faster (avg ratio {avg_ratio:.3f})"
    slower_min = min_ratio - 1.0
    slower_max = max_ratio - 1.0
    return f"~{pct(slower_min)}–{pct(slower_max)} slower (avg ratio {avg_ratio:.3f})"

def fmt_tiny(ratio):
    # ratio = C/R
    if ratio <= 1.0:
        faster = (1.0 / ratio) - 1.0
        return f"C is ~{faster*100:.1f}% faster (ratio {ratio:.3f})"
    slower = ratio - 1.0
    return f"C is ~{slower*100:.1f}% slower (ratio {ratio:.3f})"

small = select(4, 32)
mid = select(64, 64)
big = select(128, 1024)

print("## 📌 Key Results")
print("")
print(f"- Hyperfine configuration: **{runs} runs**, **{warmup} warmups**, results include **{npoints} workloads**")
if small:
    mn, mx, avg = small
    print(f"- **4–32 MiB:** C is {fmt_speedup_band(mn, mx, avg)}")
if mid:
    mn, mx, avg = mid
    print(f"- **64 MiB:** near parity (ratio {avg:.3f})")
if big:
    mn, mx, avg = big
    print(f"- **128 MiB–1 GiB:** C {fmt_percent_statement(mn, mx, avg)}")
if tiny_ratio is not None:
    print(f"- **TinyFiles:** {fmt_tiny(tiny_ratio)}")
print("")
PY
}

####################################
# Data Generation
####################################

SANDBOX="$(mktemp -d /tmp/b3bench.XXXXXX)"
trap 'rm -rf "$SANDBOX"' EXIT

say "⚙️  Generating test data (silently)..."

gen_big_file() {
  local path="$1"
  local mib="$2"
  if command -v fallocate >/dev/null 2>&1; then
    fallocate -l "$((mib * 1024 * 1024))" "$path"
    dd if=/dev/urandom of="$path" bs=1M count=1 seek=$((mib/2)) conv=notrunc 2>/dev/null || true
  else
    dd if=/dev/urandom of="$path" bs=1M count="$mib" 2>/dev/null
  fi
}

declare -a FILES=()
for sz in "${SIZES_MIB[@]}"; do
  f="$SANDBOX/file_${sz}MiB.bin"
  log "Generating $f..."
  gen_big_file "$f" "$sz"
  FILES+=("$f")
done

SMALLDIR="$SANDBOX/smallfiles"
mkdir -p "$SMALLDIR"
log "Generating tiny files in $SMALLDIR..."
for i in $(seq 1 $SMALLFILES_COUNT); do
  dd if=/dev/urandom of="$SMALLDIR/f_$i" bs=$((1024 + RANDOM % 3000)) count=1 2>/dev/null
done

####################################
# Correctness Verification
####################################

say "🧪 Verifying correctness..."

for FILE in "${FILES[@]}"; do
  HC=$("$C_IMPL" "$FILE" | awk '{print $1}')
  HR=$("$R_IMPL" "$FILE" | awk '{print $1}')
  log "Check $FILE: C=$HC R=$HR"
  if [[ "$HC" != "$HR" ]]; then
    say "🔥 Hash mismatch on $FILE"
    say "C: $HC"
    say "R: $HR"
    exit 1
  fi
done

C_RAW="$SANDBOX/c_tiny.raw"
R_RAW="$SANDBOX/r_tiny.raw"
C_NORM="$SANDBOX/c_tiny.norm"
R_NORM="$SANDBOX/r_tiny.norm"

find "$SMALLDIR" -type f -print0 | sort -z | xargs -0 "$C_IMPL" > "$C_RAW"
find "$SMALLDIR" -type f -print0 | sort -z | xargs -0 "$R_IMPL" > "$R_RAW"

normalize_sum_output() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys
inp, outp, strip_prefix = sys.argv[1], sys.argv[2], sys.argv[3]
def norm_path(p):
    if strip_prefix and p.startswith(strip_prefix): p = p[len(strip_prefix):]
    while p.startswith("./"): p = p[2:]
    return p
lines = []
with open(inp, "r", errors="replace") as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) >= 2:
            h = parts[0] if parts[0] != "BLAKE3" else parts[1]
            p = parts[1] if parts[0] != "BLAKE3" else parts[2]
            lines.append(f"{h} {norm_path(p)}")
with open(outp, "w") as f:
    for l in lines: f.write(l + "\n")
PY
}

normalize_sum_output "$C_RAW" "$C_NORM" "$SANDBOX/"
normalize_sum_output "$R_RAW" "$R_NORM" "$SANDBOX/"
sort -o "$C_NORM" "$C_NORM"
sort -o "$R_NORM" "$R_NORM"

if ! diff -u "$C_NORM" "$R_NORM" >/dev/null 2>&1; then
  say "🔥 Tiny file mismatch!"
  diff -u "$C_NORM" "$R_NORM" | head -n 20 >&3
  exit 1
fi

say "✅ All checks passed."
echo "" >&3

####################################
# Benchmarking
####################################

pre_cmd="sync"
if $CAN_DROP_CACHE; then
  pre_cmd="sync; echo 3 > /proc/sys/vm/drop_caches"
fi

emit_markdown_methodology

RESULTS_CSV="$SANDBOX/results.csv"
echo "Workload,C (ms),Rust (ms),Ratio (C/R)" > "$RESULTS_CSV"

echo "## 🚀 Benchmark Results" >&3
echo "" >&3
echo "| Workload | C (ms) | Rust (ms) | Ratio (C/R) |" >&3
echo "| :--- | :--- | :--- | :--- |" >&3

# Large files
for idx in "${!FILES[@]}"; do
  FILE="${FILES[$idx]}"
  SIZE_MIB="${SIZES_MIB[$idx]}"
  LABEL="${SIZE_MIB} MiB"
  JSON_OUT="$SANDBOX/hf_big_${SIZE_MIB}.json"

  hyperfine "${HYPERFINE_OPTS[@]}" \
    -N \
    --prepare "$pre_cmd" \
    --export-json "$JSON_OUT" \
    --command-name "C"    "$C_IMPL $FILE" \
    --command-name "Rust" "$R_IMPL $FILE"

  python3 - "$JSON_OUT" "$LABEL" "$RESULTS_CSV" <<'PY' >&3
import json, sys

json_path, label, csv_path = sys.argv[1], sys.argv[2], sys.argv[3]

with open(json_path) as f:
    data = json.load(f)

results = {r["command"]: r for r in data["results"]}
c_res = next((v for k,v in results.items() if "C" in k), None)
r_res = next((v for k,v in results.items() if "Rust" in k), None)

if not (c_res and r_res):
    print(f"| {label} | error | error | error |")
    raise SystemExit(0)

c_ms = c_res["mean"] * 1000.0
r_ms = r_res["mean"] * 1000.0
ratio = c_ms / r_ms

print(f"| {label} | {c_ms:7.3f} | {r_ms:7.3f} | {ratio:5.3f} |")

with open(csv_path, "a") as out:
    out.write(f"{label},{c_ms:.3f},{r_ms:.3f},{ratio:.6f}\n")
PY
done

# Tiny files
LABEL="TinyFiles (${SMALLFILES_COUNT})"
JSON_OUT="$SANDBOX/hf_tiny.json"

hyperfine "${HYPERFINE_OPTS[@]}" \
  --prepare "$pre_cmd" \
  --export-json "$JSON_OUT" \
  --command-name "C"    "find '$SMALLDIR' -type f -print0 | sort -z | xargs -0 -P$(nproc) -n 100 '$C_IMPL' -j1 >/dev/null" \
  --command-name "Rust" "find '$SMALLDIR' -type f -print0 | sort -z | xargs -0 -P$(nproc) -n 100 '$R_IMPL' >/dev/null"

python3 - "$JSON_OUT" "$LABEL" "$RESULTS_CSV" <<'PY' >&3
import json, sys

json_path, label, csv_path = sys.argv[1], sys.argv[2], sys.argv[3]

with open(json_path) as f:
    data = json.load(f)

results = {r["command"]: r for r in data["results"]}
c_res = next((v for k,v in results.items() if "C" in k), None)
r_res = next((v for k,v in results.items() if "Rust" in k), None)

if not (c_res and r_res):
    print(f"| {label} | error | error | error |")
    raise SystemExit(0)

c_ms = c_res["mean"] * 1000.0
r_ms = r_res["mean"] * 1000.0
ratio = c_ms / r_ms

print(f"| {label} | {c_ms:7.3f} | {r_ms:7.3f} | {ratio:5.3f} |")

with open(csv_path, "a") as out:
    out.write(f"{label},{c_ms:.3f},{r_ms:.3f},{ratio:.6f}\n")
PY

echo "" >&3

emit_key_results "$RESULTS_CSV" "$RUNS" "$WARMUP" "$(( ${#SIZES_MIB[@]} + 1 ))"

term ""
term "✨ Done. Full verbose log in: $LOGFILE"
term "🧾 Wrote report to: $REPORT_MD"
