#!/bin/bash

cd "$(dirname "$0")"

TARGETS=${TARGETS:-"lightftp bftpd proftpd pure-ftpd exim dnsmasq live555 kamailio openssh dcmtk forked-daapd"}
FUZZERS=${FUZZERS:-"aflnet stateafl"}
RUNS=${RUNS:-10}
SLOTS=${SLOTS:-44}

export CONF=$PWD/jobs.conf
export RESULTS=${RESULTS:-$PWD}
export TIMEOUT=${TIMEOUT:-86400}
export SKIPCOUNT=${SKIPCOUNT:-5}
export TEST_TIMEOUT=${TEST_TIMEOUT:-5000}

chmod +x run_one.sh
mkdir -p "$RESULTS"

source "$CONF"
missing=0
for t in $TARGETS; do for f in $FUZZERS; do
  img=${IMAGE[$t,$f]}
  docker image inspect "$img" >/dev/null 2>&1 || { echo "Image missing: $img"; missing=1; }
done; done
[ $missing -eq 1 ] && { echo "Abort: build images first."; exit 1; }

parallel -j "$SLOTS" --joblog "$RESULTS/runs.log" --resume --line-buffer \
  ./run_one.sh {1} {2} {3} \
  ::: $TARGETS ::: $FUZZERS ::: $(seq 1 "$RUNS")
