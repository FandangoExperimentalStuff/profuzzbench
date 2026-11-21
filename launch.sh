#!/bin/bash
cd "$(dirname "$0")" || exit 1

TARGETS=${TARGETS:-"lightftp bftpd proftpd pure-ftpd exim dnsmasq live555 openssh openssl dcmtk forked-daapd"}
FUZZERS=${FUZZERS:-"aflnet stateafl fandango"}
RUNS=${RUNS:-10}
CORES=${CORES:-}
RESERVED_CORES=${RESERVED_CORES:-0}
CALIBRATION=${CALIBRATION:-1}

export CONF=$PWD/jobs.conf
export RESULTS=${RESULTS:-$PWD}
export TIMEOUT=${TIMEOUT:-86400}
export SKIPCOUNT=${SKIPCOUNT:-5}
export TEST_TIMEOUT=${TEST_TIMEOUT:-5000}

usage() {
  cat <<EOF
Usage: [VARIABLE=value ...] ./launch.sh [--plan | --help]

Runs every target x fuzzer x repetition, in waves. Each run gets one physical core
with both of its SMT threads. All fuzzers of one target and repetition run in the
same wave on cores that share one L3 cache, so they are compared on the same
hardware; repetitions of a target alternate between the L3 domains. Cores a wave
cannot fill with a whole group run calibration copies of runs of the same wave on
another L3 domain. They go to RESULTS/calibration and show how much the L3 domain
changes a result.

Start it inside tmux. Starting it again with the same RESULTS resumes the
campaign, also with a larger RUNS: runs whose archive exists are skipped, and the
placement of the finished runs in RESULTS/runs.log is kept. The missing runs of a
group run on the L3 domain of its finished runs, and a new group runs on the L3
domain its target ran on least, so RUNS=10 after RUNS=1 ends with every target
and fuzzer 5 times on each of the two L3 domains.

  --plan   print the waves and exit without starting anything
  --help   print this text

Variables (current value):
  TARGETS         $TARGETS
  FUZZERS         $FUZZERS
  RUNS            $RUNS (repetitions per target and fuzzer)
  TIMEOUT         $TIMEOUT (seconds per run)
  RESULTS         $RESULTS
  CORES           ${CORES:-all but RESERVED_CORES} (cores by their first CPU, e.g. 1-7,9)
  RESERVED_CORES  $RESERVED_CORES (left to the system when CORES is unset)
  CALIBRATION     $CALIBRATION (1: spare cores run calibration copies, 0: they stay idle)
  SKIPCOUNT, TEST_TIMEOUT, MAX_ATTEMPTS and STARTUP_GRACE go to run_one.sh.

One 24 h run per target and fuzzer:
  RUNS=1 RESULTS=\$PWD/results/campaign-1 ./launch.sh --plan
  RUNS=1 RESULTS=\$PWD/results/campaign-1 ./launch.sh

Progress: RESULTS/runs.log has one line per finished run, RESULTS/plan-<time>.txt
the plan of each start, and docker ps --filter label=pfb-campaign=1 the running runs.
Stopping: Ctrl-C ends only the launcher, the containers keep running. Stop them with
  docker ps -q --filter label=pfb-campaign=1 | xargs -r docker stop
before starting again, or their runs are started a second time.
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

declare -A CORE_CPUSET CORE_DOMAIN DOMAIN_L3 DOMAIN_CORES
for topology in /sys/devices/system/cpu/cpu[0-9]*/topology; do
  cpu_directory=${topology%/topology}
  cpu=${cpu_directory##*/cpu}
  siblings=$(<"$topology/thread_siblings_list")
  [ "${siblings%%[,-]*}" = "$cpu" ] || continue
  domain=$(<"$cpu_directory/cache/index3/shared_cpu_list")
  CORE_CPUSET[$cpu]=$siblings
  CORE_DOMAIN[$cpu]=$domain
  l3_size=$(<"$cpu_directory/cache/index3/size")
  DOMAIN_L3[$domain]=$(( ${l3_size%K} / 1024 ))M
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
  echo "Aborting: no L3 domain has $GROUP_SIZE of the selected cores, one per fuzzer"
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
    for ((k=0; k<GROUP_SIZE; k++)); do
      kind=run
      [ -f "$(result_path "$RESULTS" "$target" "${FUZZER_LIST[$k]}" "$run")" ] && kind=done
      add_to_plan "$WAVES" "${cores[$k]}" "$target" "${FUZZER_LIST[$k]}" "$run" "$kind" ""
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
    echo "Aborting: the remaining groups have to run on the L3 domain of their finished runs, which has fewer than $GROUP_SIZE of the selected cores"
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
    echo "L3 domain CPUs $domain, L3 ${DOMAIN_L3[$domain]}, cores used: ${DOMAIN_CORES[$domain]:-none}"
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

source "$CONF"
MISSING_IMAGES=()
for target in $TARGETS; do
  for fuzzer in "${FUZZER_LIST[@]}"; do
    image=${IMAGE[$target,$fuzzer]}
    docker image inspect "$image" >/dev/null 2>&1 || MISSING_IMAGES+=("$image")
  done
done

if [ "$MODE" = plan ]; then
  print_plan
  [ ${#MISSING_IMAGES[@]} -eq 0 ] || echo "Missing images: ${MISSING_IMAGES[*]}"
  exit 0
fi

if [[ " $FUZZERS " == *" stateafl "* ]] && [ "$(cat /proc/sys/kernel/randomize_va_space)" != "0" ]; then
  echo "Aborting: ASLR is enabled, which StateAFL does not take. Run: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"; exit 1
fi
if grep -q '^|' /proc/sys/kernel/core_pattern; then
  echo "Aborting: core_pattern pipes to an external tool. Run: echo core | sudo tee /proc/sys/kernel/core_pattern"; exit 1
fi
if [ ${#MISSING_IMAGES[@]} -gt 0 ]; then
  echo "Aborting: missing images: ${MISSING_IMAGES[*]}"; exit 1
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
