#!/bin/bash
# Runs the whole campaign as a job queue in plain Bash: targets x fuzzers x runs,
# at most SLOTS concurrently, each run pinned to CPU (slot-1). Start inside tmux.
# Re-running resumes the campaign: run_one.sh skips runs whose result already exists.
cd "$(dirname "$0")"

TARGETS=${TARGETS:-"lightftp bftpd proftpd pure-ftpd exim dnsmasq live555 kamailio openssh openssl tinydtls dcmtk forked-daapd"}
FUZZERS=${FUZZERS:-"aflnet stateafl"}      # add aflnwe if needed
RUNS=${RUNS:-10}
SLOTS=${SLOTS:-44}

export CONF=$PWD/jobs.conf
export RESULTS=${RESULTS:-$PWD}
export TIMEOUT=${TIMEOUT:-86400}
export SKIPCOUNT=${SKIPCOUNT:-5}
export TEST_TIMEOUT=${TEST_TIMEOUT:-5000}

chmod +x run_one.sh
mkdir -p "$RESULTS"
LOG=$RESULTS/runs.log

# Host settings required by StateAFL/AFL (containers share the host kernel)
if [ "$(cat /proc/sys/kernel/randomize_va_space)" != "0" ]; then
  echo "Aborting: ASLR is enabled. Run: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"; exit 1
fi
if grep -q '^|' /proc/sys/kernel/core_pattern; then
  echo "Aborting: core_pattern pipes to an external tool. Run: echo core | sudo tee /proc/sys/kernel/core_pattern"; exit 1
fi

# Report missing images up front instead of hours into the campaign
source "$CONF"
missing=0
for t in $TARGETS; do for f in $FUZZERS; do
  img=${IMAGE[$t,$f]}
  docker image inspect "$img" >/dev/null 2>&1 || { echo "Missing image: $img"; missing=1; }
done; done
[ $missing -eq 1 ] && { echo "Aborting: build all images first."; exit 1; }

declare -a SLOTPID   # SLOTPID[s] = PID of the job in slot s (empty = free)

free_slot() {
  for ((s=1; s<=SLOTS; s++)); do
    pid=${SLOTPID[$s]:-}
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
      SLOTPID[$s]=""; echo "$s"; return 0
    fi
  done
  return 1
}

for t in $TARGETS; do for f in $FUZZERS; do for i in $(seq 1 "$RUNS"); do
  while ! slot=$(free_slot); do wait -n 2>/dev/null || sleep 5; done
  (
    JOBSLOT=$slot ./run_one.sh "$t" "$f" "$i"
    rc=$?
    echo -e "$(date +%FT%T)\t$t\t$f\t$i\tslot=$slot\texit=$rc" >> "$LOG"
  ) &
  SLOTPID[$slot]=$!
done; done; done

wait
echo "[$(date +%FT%T)] All jobs finished. Failed: $(grep -vc 'exit=0$' "$LOG" 2>/dev/null; true) (see $LOG)"