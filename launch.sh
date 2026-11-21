#!/bin/bash
cd "$(dirname "$0")" || exit 1

export CONF=$PWD/jobs.conf
export RESULTS=${RESULTS:-$PWD}
export TIMEOUT=${TIMEOUT:-86400}
export SKIPCOUNT=${SKIPCOUNT:-5}
source "$CONF"

TARGETS=${TARGETS:-$TARGETS_ALL}
FUZZERS=${FUZZERS:-"aflnet stateafl fandango"}
RUNS=${RUNS:-10}
CORES=${CORES:-}
RESERVED_CORES=${RESERVED_CORES:-0}

usage() {
  cat <<EOF
Usage: [VARIABLE=value ...] ./launch.sh [--plan | --help]

  --plan   Show the core group of each run, an estimated schedule and what
           blocks a start. The estimate counts every run as TIMEOUT seconds.
           Start nothing.
  --help   Show this text.

Without an option, runs every target with every fuzzer RUNS times.

Placement:
  A run gets one core: all CPUs of one topology/thread_siblings_list.
  Cores form a core group if they have the same L3 (cache/index3/shared_cpu_list)
  and the same cpu_capacity, rounded to 10 %.
  All fuzzers of one repetition of a target run in the same core group.
  The repetitions of a target are spread over the core groups in proportion to
  their number of cores.
  A run starts as soon as a core of its core group is free.

Resuming:
  Stop all runs first (see Stopping), or they start a second time.
  Start again with the same RESULTS. RUNS, TARGETS and FUZZERS may change.
  Runs whose .tar.gz is in RESULTS are skipped.
  Keep CORES, RESERVED_CORES and the order of TARGETS_ALL. Otherwise the core
  groups of the repetitions change.

Variables (default):
  TARGETS         TARGETS_ALL of jobs.conf
  FUZZERS         aflnet stateafl fandango
  RUNS            10 (repetitions per target and fuzzer)
  TIMEOUT         86400 (seconds per run)
  RESULTS         directory of launch.sh
  SKIPCOUNT       5 (sessions per point of the coverage curve)
  CORES           empty (cores to use, by their lowest CPU, e.g. 1-7,9)
  RESERVED_CORES  core 0 (cores not to use if CORES is empty)
  The fuzzer options and TEST_TIMEOUT are set in jobs.conf.

A start requires:
  - /proc/sys/kernel/randomize_va_space is 0 (with stateafl)
  - /proc/sys/kernel/core_pattern does not start with |
  - governor performance on all CPUs of the used cores
  - the needed images built

Stopping:
  Ctrl-C stops only launch.sh. Running runs continue. To stop them too:
    pkill -f run_one.sh
    docker ps -q --filter label=pfb-campaign=1 | xargs -r docker stop

Example:
  RUNS=1 RESULTS=results/campaign-1 ./launch.sh --plan
EOF
}

MODE=run
case ${1:-} in
  "") ;;
  --plan) MODE=plan ;;
  --help|-h) usage; exit 0 ;;
  *) usage >&2; exit 1 ;;
esac

expand_numbers() {
  local part numbers=()
  for part in ${1//,/ }; do
    if [[ $part == *-* ]]; then
      numbers+=($(seq "${part%-*}" "${part#*-}"))
    else
      numbers+=("$part")
    fi
  done
  echo "${numbers[*]}"
}

result_path() {
  echo "$1/results-$2/out-$2-$3_$4.tar.gz"
}

performance_class() {
  local cpu_directory=$1 capacity
  if [ -r "$cpu_directory/cpu_capacity" ]; then
    capacity=$(<"$cpu_directory/cpu_capacity")
    echo "capacity $(( (capacity * 10 + 512) / 1024 * 10 ))%"
  elif [ -r /sys/devices/cpu_atom/cpus ]; then
    [[ " $(expand_numbers "$(</sys/devices/cpu_atom/cpus)") " == *" ${cpu_directory##*/cpu} "* ]] && echo E-core || echo P-core
  fi
}

declare -A CORE_CPUSET CORE_DOMAIN DOMAIN_L3 DOMAIN_CLASS DOMAIN_CORES
for topology in /sys/devices/system/cpu/cpu[0-9]*/topology; do
  cpu_directory=${topology%/topology}
  cpu=${cpu_directory##*/cpu}
  siblings=$(<"$topology/thread_siblings_list")
  [ "${siblings%%[,-]*}" = "$cpu" ] || continue
  class=$(performance_class "$cpu_directory")
  domain="$(<"$cpu_directory/cache/index3/shared_cpu_list")${class:+ $class}"
  CORE_CPUSET[$cpu]=$siblings
  CORE_DOMAIN[$cpu]=$domain
  l3_size=$(<"$cpu_directory/cache/index3/size")
  DOMAIN_L3[$domain]=$(( ${l3_size%K} / 1024 ))M
  DOMAIN_CLASS[$domain]=$class
done
mapfile -t DOMAINS < <(printf '%s\n' "${!DOMAIN_L3[@]}" | sort -n)

if [ -n "$CORES" ]; then
  SELECTED_CORES=$(expand_numbers "$CORES")
else
  RESERVED=" $(expand_numbers "$RESERVED_CORES") "
  SELECTED_CORES=$(for core in "${!CORE_CPUSET[@]}"; do [[ $RESERVED == *" $core "* ]] || echo "$core"; done)
fi
for core in $(printf '%s\n' $SELECTED_CORES | sort -n); do
  if [ -z "${CORE_CPUSET[$core]}" ]; then
    echo "Aborting: CPU $core is not the first CPU of a core (cores: $(printf '%s\n' "${!CORE_CPUSET[@]}" | sort -n | tr '\n' ' '))"
    exit 1
  fi
  DOMAIN_CORES[${CORE_DOMAIN[$core]}]+="$core "
done

read -ra FUZZER_LIST <<< "$FUZZERS"
USED_DOMAINS=()
USED_CORE_COUNT=0
for domain in "${DOMAINS[@]}"; do
  read -ra cores <<< "${DOMAIN_CORES[$domain]}"
  [ "${#cores[@]}" -gt 0 ] || continue
  USED_DOMAINS+=("$domain")
  USED_CORE_COUNT=$((USED_CORE_COUNT + ${#cores[@]}))
done

declare -A TARGET_INDEX FREE_CORES JOB_CORE
for target in $TARGETS_ALL $TARGETS; do
  [ -n "${TARGET_INDEX[$target]}" ] || TARGET_INDEX[$target]=${#TARGET_INDEX[@]}
done

DOMAIN_SEQUENCE=()
current_weights=()
for ((k=0; k<${#USED_DOMAINS[@]}; k++)); do current_weights[k]=0; done
for ((position=0; position<${#TARGET_INDEX[@]} + RUNS; position++)); do
  best=0
  for ((k=0; k<${#USED_DOMAINS[@]}; k++)); do
    read -ra cores <<< "${DOMAIN_CORES[${USED_DOMAINS[$k]}]}"
    current_weights[k]=$(( current_weights[k] + ${#cores[@]} ))
    [ "${current_weights[k]}" -gt "${current_weights[best]}" ] && best=$k
  done
  current_weights[best]=$(( current_weights[best] - USED_CORE_COUNT ))
  DOMAIN_SEQUENCE+=("${USED_DOMAINS[$best]}")
done

repetition_domain() {
  echo "${DOMAIN_SEQUENCE[$(( TARGET_INDEX[$1] + $2 - 1 ))]}"
}

PENDING_RUNS=()
for run in $(seq 1 "$RUNS"); do
  for target in $TARGETS; do
    rotation=$(( (TARGET_INDEX[$target] + run) % ${#FUZZER_LIST[@]} ))
    for ((k=0; k<${#FUZZER_LIST[@]}; k++)); do
      fuzzer=${FUZZER_LIST[$(( (k + rotation) % ${#FUZZER_LIST[@]} ))]}
      [ -f "$(result_path "$RESULTS" "$target" "$fuzzer" "$run")" ] || PENDING_RUNS+=("$target $fuzzer $run")
    done
  done
done

declare -A IS_STARTED
UNSTARTED_RUNS=${#PENDING_RUNS[@]}
PLAN_WAVE=() PLAN_CORE=() PLAN_DESCRIPTION=()
WAVES=0
RUNNING_JOBS=0

start_run() {
  local core=$1 target=$2 fuzzer=$3 run=$4
  if [ "$MODE" = estimate ]; then
    PLAN_WAVE+=("$WAVES") PLAN_CORE+=("$core") PLAN_DESCRIPTION+=("$target $fuzzer #$run")
    return
  fi
  (
    JOBCPU=${CORE_CPUSET[$core]} ./run_one.sh "$target" "$fuzzer" "$run"
    rc=$?
    printf '%s\t%s\t%s\t%s\tcpu=%s\tl3=%s\trun\texit=%s\n' "$(date +%FT%T)" "$target" "$fuzzer" "$run" \
      "${CORE_CPUSET[$core]}" "${DOMAIN_L3[${CORE_DOMAIN[$core]}]}" "$rc" >> "$LOG"
  ) &
  JOB_CORE[$!]=$core
  RUNNING_JOBS=$((RUNNING_JOBS + 1))
}

start_ready_runs() {
  local index target fuzzer run domain cores
  for ((index=0; index<${#PENDING_RUNS[@]}; index++)); do
    [ -z "${IS_STARTED[$index]}" ] || continue
    read -r target fuzzer run <<< "${PENDING_RUNS[$index]}"
    domain=$(repetition_domain "$target" "$run")
    read -ra cores <<< "${FREE_CORES[$domain]}"
    [ "${#cores[@]}" -gt 0 ] || continue
    start_run "${cores[0]}" "$target" "$fuzzer" "$run"
    FREE_CORES[$domain]="${cores[*]:1}"
    IS_STARTED[$index]=1
    UNSTARTED_RUNS=$((UNSTARTED_RUNS - 1))
  done
}

free_all_cores() {
  local domain
  for domain in "${USED_DOMAINS[@]}"; do FREE_CORES[$domain]=${DOMAIN_CORES[$domain]}; done
}

estimate_waves() {
  local first_entry domain core
  while [ "$UNSTARTED_RUNS" -gt 0 ]; do
    WAVES=$((WAVES + 1))
    free_all_cores
    first_entry=${#PLAN_CORE[@]}
    start_ready_runs
    if [ "$first_entry" -eq "${#PLAN_CORE[@]}" ]; then
      echo "Aborting: $UNSTARTED_RUNS runs fit in no core group"
      return 1
    fi
    for domain in "${USED_DOMAINS[@]}"; do
      for core in ${FREE_CORES[$domain]}; do
        PLAN_WAVE+=("$WAVES") PLAN_CORE+=("$core") PLAN_DESCRIPTION+=(idle)
      done
    done
  done
}

print_estimate() {
  local domain target entry run wave=0 count_runs=0 split
  for domain in "${USED_DOMAINS[@]}"; do
    echo "Core group CPUs ${domain%% *}, L3 ${DOMAIN_L3[$domain]}${DOMAIN_CLASS[$domain]:+, ${DOMAIN_CLASS[$domain]}}, cores used: ${DOMAIN_CORES[$domain]}"
  done
  echo "Core group of each repetition, the same for every fuzzer of a target:"
  for target in $TARGETS; do
    split=""
    for ((run=1; run<=RUNS; run++)); do
      domain=$(repetition_domain "$target" "$run")
      split+=" ${DOMAIN_L3[$domain]}"
    done
    printf '  %-13s%s\n' "$target" "$split"
  done
  echo "Estimate, assuming every run takes TIMEOUT:"
  for ((entry=0; entry<${#PLAN_CORE[@]}; entry++)); do
    if [ "${PLAN_WAVE[$entry]}" != "$wave" ]; then
      wave=${PLAN_WAVE[$entry]}
      echo "start after $(( (wave - 1) * TIMEOUT / 3600 )) h"
    fi
    [ "${PLAN_DESCRIPTION[$entry]}" = idle ] || count_runs=$((count_runs + 1))
    printf '  core %-3s CPUs %-7s L3 %-6s %s\n' "${PLAN_CORE[$entry]}" "${CORE_CPUSET[${PLAN_CORE[$entry]}]}" \
      "${DOMAIN_L3[${CORE_DOMAIN[${PLAN_CORE[$entry]}]}]}" "${PLAN_DESCRIPTION[$entry]}"
  done
  echo "$count_runs runs, about $(( WAVES * TIMEOUT / 3600 )) h plus the coverage measurements"
}

ESTIMATE=$(MODE=estimate; estimate_waves && print_estimate) || { echo "$ESTIMATE"; exit 1; }

MISSING_IMAGES=()
for target in $TARGETS; do
  for fuzzer in "${FUZZER_LIST[@]}"; do
    image=${IMAGE[$target,$fuzzer]}
    docker image inspect "$image" >/dev/null 2>&1 || MISSING_IMAGES+=("$image")
  done
done

HOST_PROBLEMS=()
if [[ " $FUZZERS " == *" stateafl "* ]] && [ "$(cat /proc/sys/kernel/randomize_va_space)" != "0" ]; then
  HOST_PROBLEMS+=("ASLR is enabled, which StateAFL does not take. Run: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space")
fi
if grep -q '^|' /proc/sys/kernel/core_pattern; then
  HOST_PROBLEMS+=("core_pattern pipes to an external tool. Run: echo core | sudo tee /proc/sys/kernel/core_pattern")
fi
SLOW_GOVERNOR_CPUS=()
for core in $SELECTED_CORES; do
  for cpu in $(expand_numbers "${CORE_CPUSET[$core]}"); do
    governor_path=/sys/devices/system/cpu/cpu$cpu/cpufreq/scaling_governor
    [ -r "$governor_path" ] && [ "$(<"$governor_path")" != performance ] && SLOW_GOVERNOR_CPUS+=("$cpu")
  done
done
if [ ${#SLOW_GOVERNOR_CPUS[@]} -gt 0 ]; then
  HOST_PROBLEMS+=("the CPU frequency governor of CPUs $(printf '%s\n' "${SLOW_GOVERNOR_CPUS[@]}" | sort -n | tr '\n' ' ')is not performance, so their clock follows the load of the runs. Run: sudo cpupower frequency-set -g performance")
fi
if [ ${#MISSING_IMAGES[@]} -gt 0 ]; then
  HOST_PROBLEMS+=("missing images: ${MISSING_IMAGES[*]}")
fi

if [ "$MODE" = plan ]; then
  echo "$ESTIMATE"
  for problem in "${HOST_PROBLEMS[@]}"; do echo "Not ready to start: $problem"; done
  exit 0
fi

if [ ${#HOST_PROBLEMS[@]} -gt 0 ]; then
  for problem in "${HOST_PROBLEMS[@]}"; do echo "Aborting: $problem"; done
  exit 1
fi

chmod +x run_one.sh
mkdir -p "$RESULTS"
LOG=$RESULTS/runs.log
echo "$ESTIMATE" | tee "$RESULTS/plan-$(date +%Y%m%d-%H%M%S).txt"

free_all_cores
while true; do
  start_ready_runs
  [ "$RUNNING_JOBS" -gt 0 ] || break
  wait -n -p finished_job
  finished_core=${JOB_CORE[$finished_job]}
  finished_domain=${CORE_DOMAIN[$finished_core]}
  FREE_CORES[$finished_domain]=$(printf '%s\n' ${FREE_CORES[$finished_domain]} "$finished_core" | sort -n | tr '\n' ' ')
  unset "JOB_CORE[$finished_job]"
  RUNNING_JOBS=$((RUNNING_JOBS - 1))
done
[ "$UNSTARTED_RUNS" -eq 0 ] || echo "[$(date +%FT%T)] $UNSTARTED_RUNS runs could not be placed"
echo "[$(date +%FT%T)] All jobs finished. Failed: $(grep -vc 'exit=0$' "$LOG" 2>/dev/null; true) (see $LOG)"
