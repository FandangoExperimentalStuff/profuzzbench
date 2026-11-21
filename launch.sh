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
CALIBRATION=${CALIBRATION:-1}

usage() {
  cat <<EOF
Usage: [VARIABLE=value ...] ./launch.sh [--plan | --help]

  --plan   Print the plan and what blocks a start. Start nothing.
  --help   Print this text.

Runs every target with every fuzzer RUNS times, in waves.

Placement:
  A run gets one core: all CPUs of one topology/thread_siblings_list.
  Cores form a core group if they have the same L3 (cache/index3/shared_cpu_list)
  and the same cpu_capacity, rounded to 10 %.
  All fuzzers of one target and repetition run in the same wave and core group.
  Repetitions of a target alternate between the core groups.
  The order of the fuzzers on the cores rotates with target and repetition.
  With CALIBRATION=1, cores left over in a wave repeat a run of the same wave
  from another core group, into RESULTS/calibration.

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
  CALIBRATION     1 (0 leaves left-over cores idle)
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

PLAN_WAVE=() PLAN_CORE=() PLAN_DOMAIN=() PLAN_TARGET=() PLAN_FUZZER=() PLAN_RUN=() PLAN_KIND=() PLAN_PARTNER=()
declare -A TARGET_DOMAIN_COUNT GROUP_DOMAIN CALIBRATED_FUZZER CALIBRATED_TARGET IS_CALIBRATED FREE_CORES IS_PLACED

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

add_to_plan() {
  PLAN_WAVE+=("$1") PLAN_CORE+=("$2") PLAN_DOMAIN+=("${CORE_DOMAIN[$2]}") PLAN_TARGET+=("$3")
  PLAN_FUZZER+=("$4") PLAN_RUN+=("$5") PLAN_KIND+=("$6") PLAN_PARTNER+=("$7")
}

choose_domain() {
  local target=$1 run=$2 domain cores free count fewest_runs="" best="" best_free=0
  if [ -n "${GROUP_DOMAIN[$target,$run]}" ]; then
    read -ra cores <<< "${FREE_CORES[${GROUP_DOMAIN[$target,$run]}]}"
    [ "${#cores[@]}" -ge "$GROUP_SIZE" ] && echo "${GROUP_DOMAIN[$target,$run]}"
    return
  fi
  for domain in "${DOMAINS[@]}"; do
    read -ra cores <<< "${DOMAIN_CORES[$domain]}"
    [ "${#cores[@]}" -ge "$GROUP_SIZE" ] || continue
    count=${TARGET_DOMAIN_COUNT[$target,$domain]:-0}
    [ -n "$fewest_runs" ] && [ "$fewest_runs" -le "$count" ] || fewest_runs=$count
  done
  for domain in "${DOMAINS[@]}"; do
    [ "${TARGET_DOMAIN_COUNT[$target,$domain]:-0}" -eq "$fewest_runs" ] || continue
    read -ra cores <<< "${FREE_CORES[$domain]}"
    free=${#cores[@]}
    if [ "$free" -ge "$GROUP_SIZE" ] && [ "$free" -gt "$best_free" ]; then
      best=$domain best_free=$free
    fi
  done
  echo "$best"
}

choose_calibration_partner() {
  local domain=$1 first_entry=$2 entry score best="" best_score=0
  for ((entry=first_entry; entry<${#PLAN_CORE[@]}; entry++)); do
    [ "${PLAN_KIND[$entry]}" = run ] || continue
    [ "${PLAN_DOMAIN[$entry]}" != "$domain" ] || continue
    [ -z "${IS_CALIBRATED[$entry]}" ] || continue
    [ -f "$(result_path "$RESULTS" "${PLAN_TARGET[$entry]}" "${PLAN_FUZZER[$entry]}" "${PLAN_RUN[$entry]}")" ] && continue
    [ -f "$(result_path "$RESULTS/calibration" "${PLAN_TARGET[$entry]}" "${PLAN_FUZZER[$entry]}" "${PLAN_RUN[$entry]}")" ] && continue
    score=$(( ${CALIBRATED_FUZZER[${PLAN_FUZZER[$entry]}]:-0} * 1000 + ${CALIBRATED_TARGET[${PLAN_TARGET[$entry]}]:-0} ))
    if [ -z "$best" ] || [ "$score" -lt "$best_score" ]; then
      best=$entry best_score=$score
    fi
  done
  echo "$best"
}

declare -A TARGET_INDEX
for target in $TARGETS_ALL $TARGETS; do
  [ -n "${TARGET_INDEX[$target]}" ] || TARGET_INDEX[$target]=${#TARGET_INDEX[@]}
done

WAVES=0
unplaced_groups=${#PENDING_GROUPS[@]}
while [ "$unplaced_groups" -gt 0 ]; do
  WAVES=$((WAVES + 1))
  first_entry=${#PLAN_CORE[@]}
  for domain in "${DOMAINS[@]}"; do FREE_CORES[$domain]=${DOMAIN_CORES[$domain]}; done
  for ((group=0; group<${#PENDING_GROUPS[@]}; group++)); do
    [ -z "${IS_PLACED[$group]}" ] || continue
    read -r target run <<< "${PENDING_GROUPS[$group]}"
    domain=$(choose_domain "$target" "$run")
    [ -n "$domain" ] || continue
    read -ra cores <<< "${FREE_CORES[$domain]}"
    rotation=$(( (TARGET_INDEX[$target] + run) % GROUP_SIZE ))
    for ((k=0; k<GROUP_SIZE; k++)); do
      fuzzer=${FUZZER_LIST[$(( (k + rotation) % GROUP_SIZE ))]}
      kind=run
      [ -f "$(result_path "$RESULTS" "$target" "$fuzzer" "$run")" ] && kind=done
      add_to_plan "$WAVES" "${cores[$k]}" "$target" "$fuzzer" "$run" "$kind" ""
    done
    FREE_CORES[$domain]="${cores[*]:GROUP_SIZE}"
    if [ -z "${GROUP_DOMAIN[$target,$run]}" ]; then
      GROUP_DOMAIN[$target,$run]=$domain
      TARGET_DOMAIN_COUNT[$target,$domain]=$(( ${TARGET_DOMAIN_COUNT[$target,$domain]:-0} + 1 ))
    fi
    IS_PLACED[$group]=1
    unplaced_groups=$((unplaced_groups - 1))
  done
  if [ "$first_entry" -eq "${#PLAN_CORE[@]}" ]; then
    echo "Aborting: the remaining groups have to run on the core group of their finished runs, which has fewer than $GROUP_SIZE of the selected cores"
    exit 1
  fi
  for domain in "${DOMAINS[@]}"; do
    for core in ${FREE_CORES[$domain]}; do
      partner=""
      [ "$CALIBRATION" = 1 ] && partner=$(choose_calibration_partner "$domain" "$first_entry")
      if [ -z "$partner" ]; then
        add_to_plan "$WAVES" "$core" - - - idle ""
        continue
      fi
      IS_CALIBRATED[$partner]=1
      CALIBRATED_FUZZER[${PLAN_FUZZER[$partner]}]=$(( ${CALIBRATED_FUZZER[${PLAN_FUZZER[$partner]}]:-0} + 1 ))
      CALIBRATED_TARGET[${PLAN_TARGET[$partner]}]=$(( ${CALIBRATED_TARGET[${PLAN_TARGET[$partner]}]:-0} + 1 ))
      add_to_plan "$WAVES" "$core" "${PLAN_TARGET[$partner]}" "${PLAN_FUZZER[$partner]}" "${PLAN_RUN[$partner]}" \
        calibration "${PLAN_CORE[$partner]}"
    done
  done
done

print_plan() {
  local domain entry count_runs=0 count_calibrations=0 wave=0 description
  for domain in "${DOMAINS[@]}"; do
    echo "Core group CPUs ${domain%% *}, L3 ${DOMAIN_L3[$domain]}${DOMAIN_CLASS[$domain]:+, ${DOMAIN_CLASS[$domain]}}, cores used: ${DOMAIN_CORES[$domain]:-none}"
  done
  for ((entry=0; entry<${#PLAN_CORE[@]}; entry++)); do
    if [ "${PLAN_WAVE[$entry]}" != "$wave" ]; then
      wave=${PLAN_WAVE[$entry]}
      echo "wave $wave"
    fi
    case ${PLAN_KIND[$entry]} in
      run) description="${PLAN_TARGET[$entry]} ${PLAN_FUZZER[$entry]} #${PLAN_RUN[$entry]}"; count_runs=$((count_runs + 1)) ;;
      calibration) description="${PLAN_TARGET[$entry]} ${PLAN_FUZZER[$entry]} #${PLAN_RUN[$entry]} calibration of core ${PLAN_PARTNER[$entry]}"
        count_calibrations=$((count_calibrations + 1)) ;;
      done) description="${PLAN_TARGET[$entry]} ${PLAN_FUZZER[$entry]} #${PLAN_RUN[$entry]} done, idle" ;;
      idle) description="idle" ;;
    esac
    printf '  core %-3s CPUs %-7s L3 %-6s %s\n' "${PLAN_CORE[$entry]}" "${CORE_CPUSET[${PLAN_CORE[$entry]}]}" \
      "${DOMAIN_L3[${PLAN_DOMAIN[$entry]}]}" "$description"
  done
  echo "$WAVES waves, $count_runs runs, $count_calibrations calibration runs, about $(( WAVES * TIMEOUT / 3600 )) h"
}

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
  print_plan
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
print_plan | tee "$RESULTS/plan-$(date +%Y%m%d-%H%M%S).txt"

for ((wave=1; wave<=WAVES; wave++)); do
  echo "[$(date +%FT%T)] wave $wave of $WAVES"
  for ((entry=0; entry<${#PLAN_CORE[@]}; entry++)); do
    [ "${PLAN_WAVE[$entry]}" = "$wave" ] && [[ ${PLAN_KIND[$entry]} == run || ${PLAN_KIND[$entry]} == calibration ]] || continue
    job_results=$RESULTS
    [ "${PLAN_KIND[$entry]}" = calibration ] && job_results=$RESULTS/calibration
    (
      cpuset=${CORE_CPUSET[${PLAN_CORE[$entry]}]}
      JOBCPU=$cpuset RESULTS=$job_results ./run_one.sh "${PLAN_TARGET[$entry]}" "${PLAN_FUZZER[$entry]}" "${PLAN_RUN[$entry]}"
      rc=$?
      printf '%s\t%s\t%s\t%s\tcpu=%s\tl3=%s\t%s\texit=%s\n' "$(date +%FT%T)" "${PLAN_TARGET[$entry]}" \
        "${PLAN_FUZZER[$entry]}" "${PLAN_RUN[$entry]}" "$cpuset" "${DOMAIN_L3[${PLAN_DOMAIN[$entry]}]}" \
        "${PLAN_KIND[$entry]}" "$rc" >> "$LOG"
    ) &
  done
  wait
done
echo "[$(date +%FT%T)] All jobs finished. Failed: $(grep -vc 'exit=0$' "$LOG" 2>/dev/null; true) (see $LOG)"
