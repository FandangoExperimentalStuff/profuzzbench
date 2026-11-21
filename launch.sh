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

  --plan   Print an estimated plan and what blocks a start. Start nothing.
  --help   Print this text.

Runs every target with every fuzzer RUNS times.

Placement:
  A run gets one core: all CPUs of one topology/thread_siblings_list.
  Cores form a core group if they have the same L3 (cache/index3/shared_cpu_list)
  and the same cpu_capacity, rounded to 10 %.
  All fuzzers of one target and repetition form a group. A group starts as soon
  as its core group has a free core for each of its runs.
  Repetitions of a target alternate between the core groups.
  The order of the fuzzers on the cores rotates with target and repetition.
  The estimate of --plan assumes that every run takes TIMEOUT.

Resuming:
  Start again with the same RESULTS, also with a larger RUNS.
  Runs with an archive are skipped. Earlier core groups come from RESULTS/runs.log.

Variables (default):
  TARGETS         TARGETS_ALL of jobs.conf
  FUZZERS         aflnet stateafl fandango
  RUNS            10
  TIMEOUT         86400 (seconds per run)
  RESULTS         directory of launch.sh
  CORES           empty (cores to use, by first CPU, e.g. 1-7,9)
  RESERVED_CORES  0 (cores left unused when CORES is empty)
  TEST_TIMEOUT and the fuzzer options are set in jobs.conf.

A start requires:
  - /proc/sys/kernel/randomize_va_space is 0 (with stateafl)
  - /proc/sys/kernel/core_pattern does not start with |
  - governor performance on all CPUs of the used cores
  - all images built

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
GROUP_SIZE=${#FUZZER_LIST[@]}
is_group_placeable=0
for domain in "${DOMAINS[@]}"; do
  read -ra cores <<< "${DOMAIN_CORES[$domain]}"
  [ "${#cores[@]}" -ge "$GROUP_SIZE" ] && is_group_placeable=1
done
if [ "$is_group_placeable" -eq 0 ]; then
  echo "Aborting: no core group has $GROUP_SIZE of the selected cores, one per fuzzer"
  exit 1
fi

PENDING_GROUPS=()
for run in $(seq 1 "$RUNS"); do
  for target in $TARGETS; do
    for fuzzer in "${FUZZER_LIST[@]}"; do
      if [ ! -f "$(result_path "$RESULTS" "$target" "$fuzzer" "$run")" ]; then
        PENDING_GROUPS+=("$target $run")
        break
      fi
    done
  done
done

declare -A TARGET_DOMAIN_COUNT GROUP_DOMAIN IS_PLACED TARGET_INDEX FREE_CORES JOB_CORE
if [ -f "$RESULTS/runs.log" ]; then
  while IFS=$'\t' read -r _ target _ run cpuset _ kind status; do
    [ "$kind" = run ] && [ "$status" = exit=0 ] || continue
    first_cpu=${cpuset#cpu=}
    domain=${CORE_DOMAIN[${first_cpu%%[,-]*}]}
    [ -n "$domain" ] && [ -z "${GROUP_DOMAIN[$target,$run]}" ] || continue
    GROUP_DOMAIN[$target,$run]=$domain
    TARGET_DOMAIN_COUNT[$target,$domain]=$(( ${TARGET_DOMAIN_COUNT[$target,$domain]:-0} + 1 ))
  done < "$RESULTS/runs.log"
fi
for target in $TARGETS_ALL $TARGETS; do
  [ -n "${TARGET_INDEX[$target]}" ] || TARGET_INDEX[$target]=${#TARGET_INDEX[@]}
done
UNPLACED_GROUPS=${#PENDING_GROUPS[@]}
PLAN_WAVE=() PLAN_CORE=() PLAN_DESCRIPTION=()
WAVES=0
RUNNING_JOBS=0

missing_fuzzers() {
  local target=$1 run=$2 rotation k fuzzer
  rotation=$(( (TARGET_INDEX[$target] + run) % GROUP_SIZE ))
  for ((k=0; k<GROUP_SIZE; k++)); do
    fuzzer=${FUZZER_LIST[$(( (k + rotation) % GROUP_SIZE ))]}
    [ -f "$(result_path "$RESULTS" "$target" "$fuzzer" "$run")" ] || echo "$fuzzer"
  done
}

is_group_domain() {
  local cores
  read -ra cores <<< "${DOMAIN_CORES[$1]}"
  [ "${#cores[@]}" -ge "$GROUP_SIZE" ]
}

choose_domain() {
  local target=$1 run=$2 needed=$3 domain cores count fewest_groups="" best="" best_free=0
  if [ -n "${GROUP_DOMAIN[$target,$run]}" ]; then
    read -ra cores <<< "${FREE_CORES[${GROUP_DOMAIN[$target,$run]}]}"
    [ "${#cores[@]}" -ge "$needed" ] && echo "${GROUP_DOMAIN[$target,$run]}"
    return
  fi
  for domain in "${DOMAINS[@]}"; do
    is_group_domain "$domain" || continue
    count=${TARGET_DOMAIN_COUNT[$target,$domain]:-0}
    [ -n "$fewest_groups" ] && [ "$fewest_groups" -le "$count" ] || fewest_groups=$count
  done
  for domain in "${DOMAINS[@]}"; do
    is_group_domain "$domain" || continue
    [ "${TARGET_DOMAIN_COUNT[$target,$domain]:-0}" -eq "$fewest_groups" ] || continue
    read -ra cores <<< "${FREE_CORES[$domain]}"
    if [ "${#cores[@]}" -ge "$needed" ] && [ "${#cores[@]}" -gt "$best_free" ]; then
      best=$domain best_free=${#cores[@]}
    fi
  done
  echo "$best"
}

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

start_ready_groups() {
  local group target run domain fuzzers cores k
  for ((group=0; group<${#PENDING_GROUPS[@]}; group++)); do
    [ -z "${IS_PLACED[$group]}" ] || continue
    read -r target run <<< "${PENDING_GROUPS[$group]}"
    mapfile -t fuzzers < <(missing_fuzzers "$target" "$run")
    domain=$(choose_domain "$target" "$run" "${#fuzzers[@]}")
    [ -n "$domain" ] || continue
    read -ra cores <<< "${FREE_CORES[$domain]}"
    for ((k=0; k<${#fuzzers[@]}; k++)); do
      start_run "${cores[$k]}" "$target" "${fuzzers[$k]}" "$run"
    done
    FREE_CORES[$domain]="${cores[*]:${#fuzzers[@]}}"
    if [ -z "${GROUP_DOMAIN[$target,$run]}" ]; then
      GROUP_DOMAIN[$target,$run]=$domain
      TARGET_DOMAIN_COUNT[$target,$domain]=$(( ${TARGET_DOMAIN_COUNT[$target,$domain]:-0} + 1 ))
    fi
    IS_PLACED[$group]=1
    UNPLACED_GROUPS=$((UNPLACED_GROUPS - 1))
  done
}

free_all_cores() {
  local domain
  for domain in "${DOMAINS[@]}"; do FREE_CORES[$domain]=${DOMAIN_CORES[$domain]}; done
}

estimate_waves() {
  local first_entry domain core
  while [ "$UNPLACED_GROUPS" -gt 0 ]; do
    WAVES=$((WAVES + 1))
    free_all_cores
    first_entry=${#PLAN_CORE[@]}
    start_ready_groups
    if [ "$first_entry" -eq "${#PLAN_CORE[@]}" ]; then
      echo "Aborting: the remaining groups have to run in the core group of their finished runs, which has too few of the selected cores"
      return 1
    fi
    for domain in "${DOMAINS[@]}"; do
      for core in ${FREE_CORES[$domain]}; do
        PLAN_WAVE+=("$WAVES") PLAN_CORE+=("$core") PLAN_DESCRIPTION+=(idle)
      done
    done
  done
}

print_estimate() {
  local domain entry wave=0 count_runs=0
  for domain in "${DOMAINS[@]}"; do
    echo "Core group CPUs ${domain%% *}, L3 ${DOMAIN_L3[$domain]}${DOMAIN_CLASS[$domain]:+, ${DOMAIN_CLASS[$domain]}}, cores used: ${DOMAIN_CORES[$domain]:-none}"
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
  start_ready_groups
  [ "$RUNNING_JOBS" -gt 0 ] || break
  wait -n -p finished_job
  finished_core=${JOB_CORE[$finished_job]}
  finished_domain=${CORE_DOMAIN[$finished_core]}
  FREE_CORES[$finished_domain]=$(printf '%s\n' ${FREE_CORES[$finished_domain]} "$finished_core" | sort -n | tr '\n' ' ')
  unset "JOB_CORE[$finished_job]"
  RUNNING_JOBS=$((RUNNING_JOBS - 1))
done
[ "$UNPLACED_GROUPS" -eq 0 ] || echo "[$(date +%FT%T)] $UNPLACED_GROUPS groups could not be placed"
echo "[$(date +%FT%T)] All jobs finished. Failed: $(grep -vc 'exit=0$' "$LOG" 2>/dev/null; true) (see $LOG)"
