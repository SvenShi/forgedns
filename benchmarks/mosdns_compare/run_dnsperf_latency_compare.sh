#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

FORGEDNS_BIN="${FORGEDNS_BIN_PATH:-$BASE_DIR/forgedns}"
MOSDNS_BIN="${MOSDNS_BIN_PATH:-$BASE_DIR/mosdns}"
DNSPERF_BIN="${DNSPERF_BIN_PATH:-dnsperf}"

WARMUP_SECONDS="${WARMUP_SECONDS:-1}"
BENCH_SECONDS="${BENCH_SECONDS:-5}"
BENCH_REPEATS="${BENCH_REPEATS:-3}"
LATENCY_CLIENT_LEVELS_RAW="${LATENCY_CLIENT_LEVELS:-1 2 4}"
DNSPERF_THREADS="${DNSPERF_THREADS:-1}"
DNSPERF_TIMEOUT="${DNSPERF_TIMEOUT:-5}"
DNSPERF_MAX_QPS="${DNSPERF_MAX_QPS:-}"

RESULT_DIR="$BASE_DIR/results/latency-$(date +%Y%m%d-%H%M%S)"
SCENARIO_FILE="${SCENARIO_FILE:-$BASE_DIR/scenarios.tsv}"
SUMMARY_RAW_FILE="$RESULT_DIR/summary.raw.tsv"
SUMMARY_FILE="$RESULT_DIR/summary.tsv"
PAIR_SUMMARY_FILE="$RESULT_DIR/pair_summary.tsv"
REPORT_FILE="$RESULT_DIR/report.md"
ENV_FILE="$RESULT_DIR/environment.txt"
mkdir -p "$RESULT_DIR"

declare -a SELECTORS=("$@")
if [[ ${#SELECTORS[@]} -eq 0 ]]; then
  SELECTORS=("latency-core")
fi

declare -a LATENCY_CLIENT_LEVELS=()
declare -a LATENCY_CORE_SCENARIOS=(
  "01-baseline-udp-forward"
  "02-cache-hotpath"
  "03-dual-entry-udp"
  "03-dual-entry-tcp"
  "06-local-answers"
  "08-domain-set"
  "43-composite-provider-chain"
  "47-server-local-udp"
  "48-server-local-tcp"
)

declare -a SELECTED_ROWS=()
declare -a SCENARIO_ORDER=()
declare -A SCENARIO_FAMILY
declare -A SCENARIO_TAGS
declare -A SCENARIO_MODE
declare -A SCENARIO_QUERY_FILE
declare -A SCENARIO_WARMUP_QUERY_FILE
declare -A SCENARIO_DESCRIPTION
declare -A SCENARIO_NOTES
declare -A SCENARIO_QUERY_COUNT

declare -A AGG_QPS
declare -A AGG_LATENCY
declare -A AGG_LATENCY_STDDEV
declare -A AGG_LOST
declare -A AGG_LOSS_RATE
declare -A AGG_REPEATS

CURRENT_PID=""

require_binary() {
  local candidate="$1"
  if [[ "$candidate" == */* ]]; then
    if [[ ! -x "$candidate" ]]; then
      echo "missing executable: $candidate" >&2
      exit 1
    fi
  elif ! command -v "$candidate" >/dev/null 2>&1; then
    echo "missing command: $candidate" >&2
    exit 1
  fi
}

cleanup_current() {
  if [[ -n "$CURRENT_PID" ]] && kill -0 "$CURRENT_PID" 2>/dev/null; then
    kill "$CURRENT_PID" 2>/dev/null || true
    i=0
    while kill -0 "$CURRENT_PID" 2>/dev/null; do
      i=$((i + 1))
      if [[ "$i" -ge 20 ]]; then
        break
      fi
      sleep 0.2
    done
    kill -9 "$CURRENT_PID" 2>/dev/null || true
  fi
  CURRENT_PID=""
}

trap 'cleanup_current' EXIT

is_positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

is_number() {
  [[ "$1" =~ ^-?[0-9]+([.][0-9]+)?$ ]]
}

normalize_client_levels() {
  local raw="$1"
  local token

  raw="${raw//,/ }"
  for token in $raw; do
    if ! is_positive_integer "$token"; then
      echo "LATENCY_CLIENT_LEVELS must contain positive integers: $raw" >&2
      exit 1
    fi
    LATENCY_CLIENT_LEVELS+=("$token")
  done

  if [[ ${#LATENCY_CLIENT_LEVELS[@]} -eq 0 ]]; then
    echo "LATENCY_CLIENT_LEVELS must not be empty" >&2
    exit 1
  fi
}

has_tag() {
  local selector="$1"
  local tags_csv="$2"
  local tag

  IFS=',' read -r -a tag_items <<<"$tags_csv"
  for tag in "${tag_items[@]}"; do
    if [[ "$selector" == "$tag" ]]; then
      return 0
    fi
  done
  return 1
}

is_latency_core_scenario() {
  local label="$1"
  local scenario

  for scenario in "${LATENCY_CORE_SCENARIOS[@]}"; do
    if [[ "$label" == "$scenario" ]]; then
      return 0
    fi
  done
  return 1
}

want_scenario() {
  local label="$1"
  local family="$2"
  local tags="$3"
  shift 3 || true

  if [[ "$#" -eq 0 ]]; then
    return 0
  fi

  for arg in "$@"; do
    if [[ "$arg" == "all" || "$arg" == "$label" || "$arg" == "$family" ]]; then
      return 0
    fi
    if [[ "$arg" == "latency-core" ]] && is_latency_core_scenario "$label"; then
      return 0
    fi
    if has_tag "$arg" "$tags"; then
      return 0
    fi
  done
  return 1
}

count_queries() {
  local file="$1"
  awk 'NF && $1 !~ /^#/ { count++ } END { print count + 0 }' "$file"
}

extract_listen() {
  local config_file="$1"
  awk -F': ' '/listen:/ { gsub(/"/, "", $2); print $2; exit }' "$config_file"
}

extract_host() {
  local listen="$1"
  echo "${listen%:*}"
}

extract_port() {
  local listen="$1"
  echo "${listen##*:}"
}

detect_mosdns_launcher() {
  local help_text
  help_text="$("$MOSDNS_BIN" --help 2>&1 || true)"
  if printf '%s' "$help_text" | grep -Eq '(^|[[:space:]])start([[:space:]]|$)'; then
    echo "start"
  else
    echo "plain"
  fi
}

start_server() {
  local engine="$1"
  local config_file="$2"
  local startup_log="$3"

  if [[ "$engine" == "forgedns" ]]; then
    "$FORGEDNS_BIN" start -c "$config_file" >"$startup_log" 2>&1 &
  else
    if [[ "$MOSDNS_LAUNCHER" == "start" ]]; then
      "$MOSDNS_BIN" start -c "$config_file" >"$startup_log" 2>&1 &
    else
      "$MOSDNS_BIN" -c "$config_file" >"$startup_log" 2>&1 &
    fi
  fi

  echo $!
}

wait_for_startup() {
  local pid="$1"
  local startup_log="$2"

  sleep 1
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "server exited early, startup log:" >&2
    cat "$startup_log" >&2
    exit 1
  fi
}

run_dnsperf() {
  local mode="$1"
  local host="$2"
  local port="$3"
  local query_file="$4"
  local seconds="$5"
  local clients="$6"
  local output_file="$7"
  local outstanding="$clients"

  local cmd=(
    "$DNSPERF_BIN"
    -m "$mode"
    -s "$host"
    -p "$port"
    -d "$query_file"
    -l "$seconds"
    -c "$clients"
    -T "$DNSPERF_THREADS"
    -q "$outstanding"
    -t "$DNSPERF_TIMEOUT"
    -n 1000000
    -W
  )

  if [[ -n "$DNSPERF_MAX_QPS" ]]; then
    cmd+=(-Q "$DNSPERF_MAX_QPS")
  fi

  if ! "${cmd[@]}" >"$output_file" 2>&1; then
    echo "dnsperf failed:" >&2
    cat "$output_file" >&2
    exit 1
  fi
}

extract_metric() {
  local key="$1"
  local file="$2"

  awk -F': *' -v k="$key" '
    {
      gsub(/^[[:space:]]+/, "", $1)
      if ($1 == k) {
        gsub(/^[[:space:]]+/, "", $2)
        print $2
        exit
      }
    }
  ' "$file"
}

extract_metric_any() {
  local file="$1"
  shift

  local key value
  for key in "$@"; do
    value="$(extract_metric "$key" "$file")"
    if [[ -n "$value" ]]; then
      echo "$value"
      return 0
    fi
  done

  echo ""
  return 0
}

seconds_to_ms() {
  local raw="$1"
  raw="${raw%% *}"
  if is_number "$raw"; then
    awk -v v="$raw" 'BEGIN { printf "%.3f", v * 1000 }'
  else
    echo "n/a"
  fi
}

calc_loss_rate_percent() {
  local completed="${1:-0}"
  local lost="${2:-0}"
  awk -v c="$completed" -v l="$lost" '
    BEGIN {
      total = c + l
      if (total <= 0) {
        printf "0.0000"
        exit
      }
      printf "%.4f", (l / total) * 100
    }
  '
}

collect_run_metrics() {
  local file="$1"
  local qps avg_lat_s avg_lat_ms lat_stddev_s lat_stddev_ms completed lost loss_rate

  qps="$(extract_metric_any "$file" "Queries per second")"
  qps="${qps%% *}"

  avg_lat_s="$(extract_metric_any "$file" "Average Latency (s)" "Average Latency")"
  avg_lat_ms="$(seconds_to_ms "$avg_lat_s")"

  lat_stddev_s="$(
    extract_metric_any \
      "$file" \
      "Latency StdDev (s)" \
      "Latency Std Dev (s)" \
      "Latency StdDev" \
      "Latency Std Dev"
  )"
  lat_stddev_ms="$(seconds_to_ms "$lat_stddev_s")"

  completed="$(extract_metric_any "$file" "Queries completed")"
  completed="${completed%% *}"

  lost="$(extract_metric_any "$file" "Queries lost")"
  lost="${lost%% *}"

  loss_rate="$(calc_loss_rate_percent "${completed:-0}" "${lost:-0}")"

  printf "%s\t%s\t%s\t%s\t%s\t%s\n" \
    "${qps:-n/a}" \
    "${avg_lat_ms:-n/a}" \
    "${lat_stddev_ms:-n/a}" \
    "${completed:-0}" \
    "${lost:-0}" \
    "${loss_rate:-0.0000}"
}

record_run_summary() {
  local scenario="$1"
  local engine="$2"
  local mode="$3"
  local clients="$4"
  local repeat="$5"
  local file="$6"
  local outstanding="$clients"
  local qps avg_lat_ms lat_stddev_ms completed lost loss_rate

  IFS=$'\t' read -r qps avg_lat_ms lat_stddev_ms completed lost loss_rate \
    <<<"$(collect_run_metrics "$file")"

  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$scenario" \
    "$engine" \
    "$mode" \
    "$clients" \
    "$outstanding" \
    "$repeat" \
    "$qps" \
    "$avg_lat_ms" \
    "$lat_stddev_ms" \
    "$completed" \
    "$lost" \
    "$loss_rate" \
    >>"$SUMMARY_RAW_FILE"

  printf "  %-24s %-8s c=%-2s r%02d avg_ms=%-8s jitter_ms=%-8s qps=%-10s loss=%s%%\n" \
    "$scenario" \
    "$engine" \
    "$clients" \
    "$repeat" \
    "$avg_lat_ms" \
    "$lat_stddev_ms" \
    "$qps" \
    "$loss_rate"
}

benchmark_engine() {
  local scenario_label="$1"
  local config_file="$2"
  local query_file="$3"
  local warmup_query_file="$4"
  local mode="$5"
  local engine="$6"

  local listen host port clients repeat repeat_suffix startup_log warmup_log run_log
  listen="$(extract_listen "$config_file")"
  host="$(extract_host "$listen")"
  port="$(extract_port "$listen")"

  if [[ -z "$warmup_query_file" || "$warmup_query_file" == "-" ]]; then
    warmup_query_file="$query_file"
  fi

  echo
  echo ">>> ${scenario_label} / ${engine} / ${mode}"

  for clients in "${LATENCY_CLIENT_LEVELS[@]}"; do
    echo "    clients=$clients outstanding=$clients"

    for ((repeat = 1; repeat <= BENCH_REPEATS; repeat++)); do
      repeat_suffix=".c$(printf '%02d' "$clients")"
      if (( BENCH_REPEATS > 1 )); then
        repeat_suffix+=".r$(printf '%02d' "$repeat")"
      fi

      startup_log="$RESULT_DIR/${scenario_label}.${engine}${repeat_suffix}.startup.log"
      warmup_log="$RESULT_DIR/${scenario_label}.${engine}${repeat_suffix}.warmup.txt"
      run_log="$RESULT_DIR/${scenario_label}.${engine}${repeat_suffix}.dnsperf.txt"

      CURRENT_PID="$(start_server "$engine" "$config_file" "$startup_log")"
      wait_for_startup "$CURRENT_PID" "$startup_log"

      run_dnsperf "$mode" "$host" "$port" "$warmup_query_file" "$WARMUP_SECONDS" "$clients" "$warmup_log"
      run_dnsperf "$mode" "$host" "$port" "$query_file" "$BENCH_SECONDS" "$clients" "$run_log"

      cleanup_current
      record_run_summary "$scenario_label" "$engine" "$mode" "$clients" "$repeat" "$run_log"
    done
  done
}

numeric_series_stats() {
  if [[ "$#" -eq 0 ]]; then
    printf "n/a\tn/a\tn/a\tn/a"
    return
  fi

  printf '%s\n' "$@" | awk '
    /^[0-9]+([.][0-9]+)?$/ {
      print
    }
  ' | LC_ALL=C sort -g | awk '
    {
      vals[NR] = $1
    }
    END {
      if (NR == 0) {
        printf "n/a\tn/a\tn/a\tn/a"
        exit
      }
      if (NR % 2 == 1) {
        med = vals[(NR + 1) / 2]
      } else {
        med = (vals[NR / 2] + vals[(NR / 2) + 1]) / 2
      }
      spread = med == 0 ? 0 : ((vals[NR] - vals[1]) / med) * 100
      printf "%.6f\t%.6f\t%.6f\t%.2f", med, vals[1], vals[NR], spread
    }
  '
}

ratio_or_na() {
  local lhs="$1"
  local rhs="$2"

  if ! is_number "$lhs" || ! is_number "$rhs"; then
    echo "n/a"
    return
  fi

  awk -v l="$lhs" -v r="$rhs" '
    BEGIN {
      if (r == 0) {
        print "n/a"
        exit
      }
      printf "%.3f", l / r
    }
  '
}

pct_diff_or_na() {
  local lhs="$1"
  local rhs="$2"

  if ! is_number "$lhs" || ! is_number "$rhs"; then
    echo "n/a"
    return
  fi

  awk -v l="$lhs" -v r="$rhs" '
    BEGIN {
      if (r == 0) {
        print "n/a"
        exit
      }
      printf "%.2f", ((l - r) / r) * 100
    }
  '
}

hash_file() {
  local file="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{ print $1 }'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{ print $1 }'
  else
    echo "unavailable"
  fi
}

capture_version() {
  local binary="$1"
  shift || true
  local output

  output="$("$binary" "$@" 2>&1 | head -n 1 || true)"
  output="${output//$'\t'/ }"
  echo "${output:-n/a}"
}

capture_mosdns_version() {
  local output

  output="$("$MOSDNS_BIN" version 2>&1 | head -n 1 || true)"
  if [[ -z "$output" ]]; then
    output="$("$MOSDNS_BIN" --version 2>&1 | head -n 1 || true)"
  fi
  output="${output//$'\t'/ }"
  echo "${output:-n/a}"
}

write_environment_snapshot() {
  local git_head="n/a"

  if command -v git >/dev/null 2>&1; then
    git_head="$(git -C "$BASE_DIR" rev-parse HEAD 2>/dev/null || echo "n/a")"
  fi

  {
    echo "timestamp=$(date -Is)"
    echo "hostname=$(hostname 2>/dev/null || echo n/a)"
    echo "uname=$(uname -a 2>/dev/null || echo n/a)"
    echo "git_head=$git_head"
    echo "selectors=${SELECTORS[*]}"
    echo "scenario_file=$SCENARIO_FILE"
    echo "workload_profile=low-concurrency-latency"
    echo "warmup_seconds=$WARMUP_SECONDS"
    echo "bench_seconds=$BENCH_SECONDS"
    echo "bench_repeats=$BENCH_REPEATS"
    echo "latency_client_levels=${LATENCY_CLIENT_LEVELS[*]}"
    echo "dnsperf_threads=$DNSPERF_THREADS"
    echo "dnsperf_timeout=$DNSPERF_TIMEOUT"
    echo "dnsperf_outstanding=matches_client_count"
    echo "dnsperf_max_qps=${DNSPERF_MAX_QPS:-unlimited}"
    echo "forgedns_bin=$FORGEDNS_BIN"
    echo "forgedns_sha256=$(hash_file "$FORGEDNS_BIN")"
    echo "forgedns_version=$(capture_version "$FORGEDNS_BIN" --version)"
    echo "mosdns_bin=$MOSDNS_BIN"
    echo "mosdns_sha256=$(hash_file "$MOSDNS_BIN")"
    echo "mosdns_version=$(capture_mosdns_version)"
    echo "dnsperf_bin=$DNSPERF_BIN"
    echo "dnsperf_version=$(capture_version "$DNSPERF_BIN" -V)"
  } >"$ENV_FILE"
}

load_selected_scenarios() {
  local label forgedns_config_rel mosdns_config_rel query_rel mode family
  local warmup_query_rel tags description notes

  while IFS='|' read -r label forgedns_config_rel mosdns_config_rel query_rel mode family warmup_query_rel tags description notes; do
    if [[ -z "$label" || "$label" == \#* ]]; then
      continue
    fi

    if ! want_scenario "$label" "$family" "$tags" "${SELECTORS[@]}"; then
      continue
    fi

    SELECTED_ROWS+=(
      "$label|$forgedns_config_rel|$mosdns_config_rel|$query_rel|$mode|$family|$warmup_query_rel|$tags|$description|$notes"
    )
    SCENARIO_ORDER+=("$label")
    SCENARIO_FAMILY["$label"]="$family"
    SCENARIO_TAGS["$label"]="$tags"
    SCENARIO_MODE["$label"]="$mode"
    SCENARIO_QUERY_FILE["$label"]="$BASE_DIR/$query_rel"
    SCENARIO_DESCRIPTION["$label"]="${description:-}"
    SCENARIO_NOTES["$label"]="${notes:-}"
    SCENARIO_QUERY_COUNT["$label"]="$(count_queries "$BASE_DIR/$query_rel")"

    if [[ -z "$warmup_query_rel" || "$warmup_query_rel" == "-" ]]; then
      SCENARIO_WARMUP_QUERY_FILE["$label"]="$BASE_DIR/$query_rel"
    else
      SCENARIO_WARMUP_QUERY_FILE["$label"]="$BASE_DIR/$warmup_query_rel"
    fi
  done <"$SCENARIO_FILE"

  if [[ ${#SELECTED_ROWS[@]} -eq 0 ]]; then
    echo "no scenarios matched selectors: ${SELECTORS[*]}" >&2
    exit 1
  fi
}

print_selected_scenarios() {
  local scenario

  echo "selected scenarios (${#SCENARIO_ORDER[@]}):"
  for scenario in "${SCENARIO_ORDER[@]}"; do
    printf "  - %-24s [%s] %s\n" \
      "$scenario" \
      "${SCENARIO_TAGS[$scenario]}" \
      "${SCENARIO_DESCRIPTION[$scenario]}"
  done
}

build_aggregated_summary() {
  local -a summary_keys=()
  local -A qps_series lat_series lat_stddev_series lost_series loss_rate_series repeat_count
  local scenario engine mode clients outstanding repeat qps lat lat_stddev completed lost loss_rate key
  local qps_med qps_min qps_max qps_spread
  local lat_med lat_min lat_max lat_spread
  local lat_stddev_med lat_stddev_min lat_stddev_max lat_stddev_spread
  local lost_med lost_min lost_max lost_spread
  local loss_rate_med loss_rate_min loss_rate_max loss_rate_spread

  printf "scenario\tengine\tmode\tfamily\ttags\tclients\toutstanding\tquery_count\trepeats\tavg_latency_ms_median\tavg_latency_ms_min\tavg_latency_ms_max\tavg_latency_spread_pct\tlatency_stddev_ms_median\tlatency_stddev_ms_min\tlatency_stddev_ms_max\tlatency_stddev_spread_pct\tqps_median\tqps_min\tqps_max\tqps_spread_pct\tlost_median\tloss_rate_pct_median\tdescription\tnotes\n" \
    >"$SUMMARY_FILE"

  while IFS=$'\t' read -r scenario engine mode clients outstanding repeat qps lat lat_stddev completed lost loss_rate; do
    if [[ "$scenario" == "scenario" ]]; then
      continue
    fi

    key="${scenario}|${engine}|${mode}|${clients}"
    if [[ -z "${qps_series[$key]:-}" ]]; then
      summary_keys+=("$key")
      qps_series[$key]="$qps"
      lat_series[$key]="$lat"
      lat_stddev_series[$key]="$lat_stddev"
      lost_series[$key]="$lost"
      loss_rate_series[$key]="$loss_rate"
      repeat_count[$key]=1
    else
      qps_series[$key]+=" $qps"
      lat_series[$key]+=" $lat"
      lat_stddev_series[$key]+=" $lat_stddev"
      lost_series[$key]+=" $lost"
      loss_rate_series[$key]+=" $loss_rate"
      repeat_count[$key]=$((repeat_count[$key] + 1))
    fi
  done <"$SUMMARY_RAW_FILE"

  for key in "${summary_keys[@]}"; do
    IFS='|' read -r scenario engine mode clients <<<"$key"

    IFS=$'\t' read -r lat_med lat_min lat_max lat_spread \
      <<<"$(numeric_series_stats ${lat_series[$key]})"
    IFS=$'\t' read -r lat_stddev_med lat_stddev_min lat_stddev_max lat_stddev_spread \
      <<<"$(numeric_series_stats ${lat_stddev_series[$key]})"
    IFS=$'\t' read -r qps_med qps_min qps_max qps_spread \
      <<<"$(numeric_series_stats ${qps_series[$key]})"
    IFS=$'\t' read -r lost_med lost_min lost_max lost_spread \
      <<<"$(numeric_series_stats ${lost_series[$key]})"
    IFS=$'\t' read -r loss_rate_med loss_rate_min loss_rate_max loss_rate_spread \
      <<<"$(numeric_series_stats ${loss_rate_series[$key]})"

    AGG_QPS[$key]="$qps_med"
    AGG_LATENCY[$key]="$lat_med"
    AGG_LATENCY_STDDEV[$key]="$lat_stddev_med"
    AGG_LOST[$key]="$lost_med"
    AGG_LOSS_RATE[$key]="$loss_rate_med"
    AGG_REPEATS[$key]="${repeat_count[$key]}"

    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
      "$scenario" \
      "$engine" \
      "$mode" \
      "${SCENARIO_FAMILY[$scenario]}" \
      "${SCENARIO_TAGS[$scenario]}" \
      "$clients" \
      "$clients" \
      "${SCENARIO_QUERY_COUNT[$scenario]}" \
      "${repeat_count[$key]}" \
      "$lat_med" \
      "$lat_min" \
      "$lat_max" \
      "$lat_spread" \
      "$lat_stddev_med" \
      "$lat_stddev_min" \
      "$lat_stddev_max" \
      "$lat_stddev_spread" \
      "$qps_med" \
      "$qps_min" \
      "$qps_max" \
      "$qps_spread" \
      "$lost_med" \
      "$loss_rate_med" \
      "${SCENARIO_DESCRIPTION[$scenario]}" \
      "${SCENARIO_NOTES[$scenario]}" \
      >>"$SUMMARY_FILE"
  done
}

build_pair_summary() {
  local scenario mode family tags query_count description notes clients
  local forgedns_key mosdns_key repeats
  local forgedns_qps mosdns_qps qps_diff qps_ratio
  local forgedns_lat mosdns_lat lat_diff lat_ratio
  local forgedns_lat_stddev mosdns_lat_stddev lat_stddev_diff lat_stddev_ratio
  local forgedns_loss mosdns_loss

  printf "scenario\tmode\tfamily\ttags\tclients\toutstanding\tquery_count\trepeats\tforgedns_avg_latency_ms\tmosdns_avg_latency_ms\tlatency_diff_pct\tlatency_ratio\tforgedns_latency_stddev_ms\tmosdns_latency_stddev_ms\tlatency_stddev_diff_pct\tlatency_stddev_ratio\tforgedns_qps\tmosdns_qps\tqps_diff_pct\tqps_ratio\tforgedns_loss_rate_pct\tmosdns_loss_rate_pct\tdescription\tnotes\n" \
    >"$PAIR_SUMMARY_FILE"

  for scenario in "${SCENARIO_ORDER[@]}"; do
    mode="${SCENARIO_MODE[$scenario]}"
    family="${SCENARIO_FAMILY[$scenario]}"
    tags="${SCENARIO_TAGS[$scenario]}"
    query_count="${SCENARIO_QUERY_COUNT[$scenario]}"
    description="${SCENARIO_DESCRIPTION[$scenario]}"
    notes="${SCENARIO_NOTES[$scenario]}"

    for clients in "${LATENCY_CLIENT_LEVELS[@]}"; do
      forgedns_key="${scenario}|forgedns|${mode}|${clients}"
      mosdns_key="${scenario}|mosdns|${mode}|${clients}"

      if [[ -z "${AGG_LATENCY[$forgedns_key]:-}" || -z "${AGG_LATENCY[$mosdns_key]:-}" ]]; then
        continue
      fi

      repeats="${AGG_REPEATS[$forgedns_key]}"

      forgedns_lat="${AGG_LATENCY[$forgedns_key]}"
      mosdns_lat="${AGG_LATENCY[$mosdns_key]}"
      lat_diff="$(pct_diff_or_na "$forgedns_lat" "$mosdns_lat")"
      lat_ratio="$(ratio_or_na "$forgedns_lat" "$mosdns_lat")"

      forgedns_lat_stddev="${AGG_LATENCY_STDDEV[$forgedns_key]}"
      mosdns_lat_stddev="${AGG_LATENCY_STDDEV[$mosdns_key]}"
      lat_stddev_diff="$(pct_diff_or_na "$forgedns_lat_stddev" "$mosdns_lat_stddev")"
      lat_stddev_ratio="$(ratio_or_na "$forgedns_lat_stddev" "$mosdns_lat_stddev")"

      forgedns_qps="${AGG_QPS[$forgedns_key]}"
      mosdns_qps="${AGG_QPS[$mosdns_key]}"
      qps_diff="$(pct_diff_or_na "$forgedns_qps" "$mosdns_qps")"
      qps_ratio="$(ratio_or_na "$forgedns_qps" "$mosdns_qps")"

      forgedns_loss="${AGG_LOSS_RATE[$forgedns_key]}"
      mosdns_loss="${AGG_LOSS_RATE[$mosdns_key]}"

      printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$scenario" \
        "$mode" \
        "$family" \
        "$tags" \
        "$clients" \
        "$clients" \
        "$query_count" \
        "$repeats" \
        "$forgedns_lat" \
        "$mosdns_lat" \
        "$lat_diff" \
        "$lat_ratio" \
        "$forgedns_lat_stddev" \
        "$mosdns_lat_stddev" \
        "$lat_stddev_diff" \
        "$lat_stddev_ratio" \
        "$forgedns_qps" \
        "$mosdns_qps" \
        "$qps_diff" \
        "$qps_ratio" \
        "$forgedns_loss" \
        "$mosdns_loss" \
        "$description" \
        "$notes" \
        >>"$PAIR_SUMMARY_FILE"
    done
  done
}

print_pair_summary_table() {
  local scenario mode family tags clients outstanding query_count repeats
  local forgedns_lat mosdns_lat lat_diff lat_ratio
  local forgedns_lat_stddev mosdns_lat_stddev lat_stddev_diff lat_stddev_ratio
  local forgedns_qps mosdns_qps qps_diff qps_ratio
  local forgedns_loss mosdns_loss description notes

  printf "\n%-24s %-4s %-5s %-9s %-9s %-10s %-9s %-9s %-9s %-9s\n" \
    "scenario" "c" "runs" "fd_ms" "mo_ms" "lat_diff%" "fd_jit" "mo_jit" "fd_loss%" "mo_loss%"
  printf "%-24s %-4s %-5s %-9s %-9s %-10s %-9s %-9s %-9s %-9s\n" \
    "--------" "-" "----" "-----" "-----" "---------" "------" "------" "--------" "--------"

  while IFS=$'\t' read -r scenario mode family tags clients outstanding query_count repeats forgedns_lat mosdns_lat lat_diff lat_ratio forgedns_lat_stddev mosdns_lat_stddev lat_stddev_diff lat_stddev_ratio forgedns_qps mosdns_qps qps_diff qps_ratio forgedns_loss mosdns_loss description notes; do
    if [[ "$scenario" == "scenario" ]]; then
      continue
    fi

    printf "%-24s %-4s %-5s %-9s %-9s %-10s %-9s %-9s %-9s %-9s\n" \
      "$scenario" \
      "$clients" \
      "$repeats" \
      "$forgedns_lat" \
      "$mosdns_lat" \
      "$lat_diff" \
      "$forgedns_lat_stddev" \
      "$mosdns_lat_stddev" \
      "$forgedns_loss" \
      "$mosdns_loss"
  done <"$PAIR_SUMMARY_FILE"
}

generate_report_markdown() {
  local key value
  local scenario mode family tags clients outstanding query_count repeats
  local forgedns_lat mosdns_lat lat_diff lat_ratio
  local forgedns_lat_stddev mosdns_lat_stddev lat_stddev_diff lat_stddev_ratio
  local forgedns_qps mosdns_qps qps_diff qps_ratio
  local forgedns_loss mosdns_loss description notes

  {
    echo "# ForgeDNS vs mosdns low-concurrency latency compare report"
    echo
    echo "This runner keeps dnsperf in a closed-loop low-concurrency profile:"
    echo "each sweep point uses the same value for client count and outstanding query count."
    echo "Latency diff is calculated against mosdns, so a negative value means ForgeDNS has lower latency."
    echo "Latency stddev diff also uses mosdns as the baseline, so a negative value means ForgeDNS has lower jitter."
    echo "QPS is kept as a secondary sanity metric instead of the main headline."
    echo
    echo "## Run parameters"
    echo
    echo "- Selectors: \`${SELECTORS[*]}\`"
    echo "- Scenario file: \`$(basename "$SCENARIO_FILE")\`"
    echo "- Warmup seconds: \`$WARMUP_SECONDS\`"
    echo "- Bench seconds: \`$BENCH_SECONDS\`"
    echo "- Repeats: \`$BENCH_REPEATS\`"
    echo "- Client levels: \`${LATENCY_CLIENT_LEVELS[*]}\`"
    echo "- dnsperf threads: \`$DNSPERF_THREADS\`"
    echo "- dnsperf timeout: \`$DNSPERF_TIMEOUT\`"
    echo "- dnsperf outstanding: \`matches client count\`"
    echo "- dnsperf max QPS: \`${DNSPERF_MAX_QPS:-unlimited}\`"
    echo
    echo "## Environment"
    echo
    while IFS='=' read -r key value; do
      echo "- ${key}: \`${value}\`"
    done <"$ENV_FILE"
    echo
    echo "## Pair summary"
    echo
    echo "| Scenario | Family | Clients | Queries | Runs | ForgeDNS avg ms | mosdns avg ms | Lat diff | ForgeDNS jitter ms | mosdns jitter ms | Jitter diff | ForgeDNS QPS | mosdns QPS | ForgeDNS loss % | mosdns loss % | Purpose |"
    echo "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |"

    while IFS=$'\t' read -r scenario mode family tags clients outstanding query_count repeats forgedns_lat mosdns_lat lat_diff lat_ratio forgedns_lat_stddev mosdns_lat_stddev lat_stddev_diff lat_stddev_ratio forgedns_qps mosdns_qps qps_diff qps_ratio forgedns_loss mosdns_loss description notes; do
      if [[ "$scenario" == "scenario" ]]; then
        continue
      fi

      printf "| %s | %s | %s | %s | %s | %s | %s | %s%% | %s | %s | %s%% | %s | %s | %s | %s | %s |\n" \
        "$scenario" \
        "$family" \
        "$clients" \
        "$query_count" \
        "$repeats" \
        "$forgedns_lat" \
        "$mosdns_lat" \
        "$lat_diff" \
        "$forgedns_lat_stddev" \
        "$mosdns_lat_stddev" \
        "$lat_stddev_diff" \
        "$forgedns_qps" \
        "$mosdns_qps" \
        "$forgedns_loss" \
        "$mosdns_loss" \
        "$description"
    done <"$PAIR_SUMMARY_FILE"

    echo
    echo "## Scenario notes"
    echo
    for scenario in "${SCENARIO_ORDER[@]}"; do
      if [[ -n "${SCENARIO_NOTES[$scenario]}" ]]; then
        echo "- \`$scenario\`: ${SCENARIO_NOTES[$scenario]}"
      fi
    done
  } >"$REPORT_FILE"
}

require_binary "$FORGEDNS_BIN"
require_binary "$MOSDNS_BIN"
require_binary "$DNSPERF_BIN"

if [[ ! -f "$SCENARIO_FILE" ]]; then
  echo "missing scenario file: $SCENARIO_FILE" >&2
  exit 1
fi

if ! is_positive_integer "$BENCH_REPEATS"; then
  echo "BENCH_REPEATS must be a positive integer: $BENCH_REPEATS" >&2
  exit 1
fi

normalize_client_levels "$LATENCY_CLIENT_LEVELS_RAW"

MOSDNS_LAUNCHER="$(detect_mosdns_launcher)"
export BENCH_PLUGIN_FLAG="${BENCH_PLUGIN_FLAG:-1}"

printf "scenario\tengine\tmode\tclients\toutstanding\trepeat\tqps\tavg_latency_ms\tlatency_stddev_ms\tcompleted\tlost\tloss_rate_pct\n" \
  >"$SUMMARY_RAW_FILE"

load_selected_scenarios
write_environment_snapshot

echo "results directory: $RESULT_DIR"
echo "mosdns launcher mode: $MOSDNS_LAUNCHER"
echo "scenario file: $SCENARIO_FILE"
echo "selectors: ${SELECTORS[*]}"
echo "bench seconds: $BENCH_SECONDS, warmup seconds: $WARMUP_SECONDS, repeats: $BENCH_REPEATS"
echo "latency client levels: ${LATENCY_CLIENT_LEVELS[*]}"
echo "dnsperf threads: $DNSPERF_THREADS, timeout: $DNSPERF_TIMEOUT, outstanding: matches client count"
echo "BENCH_PLUGIN_FLAG: $BENCH_PLUGIN_FLAG"
print_selected_scenarios

for row in "${SELECTED_ROWS[@]}"; do
  IFS='|' read -r label forgedns_config_rel mosdns_config_rel query_rel mode family warmup_query_rel tags description notes <<<"$row"

  benchmark_engine \
    "$label" \
    "$BASE_DIR/$forgedns_config_rel" \
    "$BASE_DIR/$query_rel" \
    "${SCENARIO_WARMUP_QUERY_FILE[$label]}" \
    "$mode" \
    "forgedns"

  benchmark_engine \
    "$label" \
    "$BASE_DIR/$mosdns_config_rel" \
    "$BASE_DIR/$query_rel" \
    "${SCENARIO_WARMUP_QUERY_FILE[$label]}" \
    "$mode" \
    "mosdns"
done

build_aggregated_summary
build_pair_summary
print_pair_summary_table
generate_report_markdown

echo
echo "environment saved in: $ENV_FILE"
echo "raw summary saved in: $SUMMARY_RAW_FILE"
echo "aggregated summary saved in: $SUMMARY_FILE"
echo "pair summary saved in: $PAIR_SUMMARY_FILE"
echo "markdown report saved in: $REPORT_FILE"
