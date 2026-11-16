#!/bin/bash
# Usage: measure-queue-coverage <queue-dir> <coverage-csv> <sessions-per-sample>
# Replays every framed session file of <queue-dir> once, in the order the fuzzer saved them, against the gcov build
# described by coverage-replay.env and writes the coverage over time to <coverage-csv>, in the format of cov_script.
set -eu

QUEUE=$1
COVERAGE_CSV=$2
SESSIONS_PER_SAMPLE=$3
COVERAGE_REPLAY_ENV=${COVERAGE_REPLAY_ENV:-$WORKDIR/coverage-replay.env}
DRIVER_PYTHON=${DRIVER_PYTHON:-/home/ubuntu/driver/bin/python}

source "$COVERAGE_REPLAY_ENV"
GCOV_ROOT=$(eval echo "$GCOV_ROOT")
DRIVER_OUT=$(mktemp -d)/replay-out

cd "$WORKDIR/$GCOV_DIR"
if [ -n "$SETUP" ]; then
  ( set +e; eval "$SETUP" ) || true
fi
DRIVER_OPTIONS=(--out "$DRIVER_OUT" --endpoint "$ENDPOINT" --corpus "$QUEUE" --executor plain
  --gcov-root "$GCOV_ROOT" --gcov-every "$SESSIONS_PER_SAMPLE" -W "$FIRST_RESPONSE_MS" -w "$FOLLOW_UP_US"
  -K --kill-signal "$KILL_SIGNAL" --exit-grace-ms "$EXIT_GRACE_MS" -D "$INIT_WAIT_US")
if [ -n "$CLEANUP" ]; then
  DRIVER_OPTIONS+=(-c "$CLEANUP")
fi
if [ -n "$GCOV_COLLECT" ]; then
  DRIVER_OPTIONS+=(--gcov-collect "$GCOV_COLLECT")
fi
"$DRIVER_PYTHON" -m fandango_driver replay "${DRIVER_OPTIONS[@]}" -- sh -c "exec $SUT"
cp "$DRIVER_OUT/cov_over_time.csv" "$COVERAGE_CSV"
