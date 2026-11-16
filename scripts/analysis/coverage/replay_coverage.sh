#!/bin/bash
# Usage: replay_coverage.sh <subject> <image> <archive.tar.gz> <output-dir> [<sessions-per-sample>] [with-seeds]
#   subject: the directory below subjects/ that holds coverage-replay.env, e.g. FTP/ProFTPD
#   image: an image with the gcov build of the subject and the Fandango venv, e.g. proftpd-fandango
#   archive: a result archive of AFLNet, StateAFL or Fandango with a replayable-queue
#   with-seeds: replay the seed files of the subject first, stamped with the start time of the fuzzer
# Writes <output-dir>/cov_over_time.csv (or cov_over_time_with_seeds.csv) in the format of cov_script.
set -eu

SUBJECT=$1
IMAGE=$2
ARCHIVE=$3
OUTPUT=$4
SESSIONS_PER_SAMPLE=${5:-5}
SEED_MODE=${6:-}

PFBENCH=$(cd "$(dirname "$0")/../../.." && pwd)
DRIVER_SOURCE=$PFBENCH/../fandango-driver/src
REPLAY_ENV=$PFBENCH/subjects/$SUBJECT/coverage-replay.env

if [ ! -f "$REPLAY_ENV" ]; then
  echo "no coverage-replay.env for $SUBJECT" >&2
  exit 1
fi
if [ -n "$SEED_MODE" ] && [ "$SEED_MODE" != "with-seeds" ]; then
  echo "unknown seed mode: $SEED_MODE" >&2
  exit 1
fi
mkdir -p "$OUTPUT"

docker run --rm \
  -v "$REPLAY_ENV:/opt/coverage-replay.env:ro" \
  -v "$(realpath "$ARCHIVE"):/opt/archive.tar.gz:ro" \
  -v "$DRIVER_SOURCE:/opt/driver:ro" \
  -v "$(realpath "$OUTPUT"):/opt/output" \
  -e PYTHONPATH=/opt/driver \
  -e SESSIONS_PER_SAMPLE="$SESSIONS_PER_SAMPLE" \
  -e SEED_MODE="$SEED_MODE" \
  "$IMAGE" /bin/bash -c '
set -eu
source /opt/coverage-replay.env
GCOV_ROOT=$(eval echo "$GCOV_ROOT")
EXTRACTED=$(mktemp -d)
tar -xzf /opt/archive.tar.gz -C "$EXTRACTED" --wildcards "*/replayable-queue/*" "*/fuzzer_stats"
QUEUE=$(find "$EXTRACTED" -type d -name replayable-queue | head -1)
COVERAGE_FILE=cov_over_time.csv
if [ "$SEED_MODE" = "with-seeds" ]; then
  FUZZER_STATS=$(find "$EXTRACTED" -name fuzzer_stats | head -1)
  START_TIME=$(sed -n "s/^start_time *: *//p" "$FUZZER_STATS")
  for SEED in "$WORKDIR/$SEED_DIR"/*.raw; do
    cp "$SEED" "$QUEUE/"
    touch -d "@$START_TIME" "$QUEUE/$(basename "$SEED")"
  done
  COVERAGE_FILE=cov_over_time_with_seeds.csv
fi
cd "$WORKDIR/$GCOV_DIR"
if [ -n "$SETUP" ]; then
  ( set +e; eval "$SETUP" ) || true
fi
DRIVER_OPTIONS=(--out /tmp/replay-out --endpoint "$ENDPOINT" --corpus "$QUEUE" --executor plain
  --gcov-root "$GCOV_ROOT" --gcov-every "$SESSIONS_PER_SAMPLE" -W "$FIRST_RESPONSE_MS" -w "$FOLLOW_UP_US" -K --kill-signal "$KILL_SIGNAL"
  --exit-grace-ms "$EXIT_GRACE_MS" -D "$INIT_WAIT_US")
if [ -n "$CLEANUP" ]; then
  DRIVER_OPTIONS+=(-c "$CLEANUP")
fi
if [ -n "$GCOV_COLLECT" ]; then
  DRIVER_OPTIONS+=(--gcov-collect "$GCOV_COLLECT")
fi
/home/ubuntu/fandango/bin/python -m fandango_driver replay "${DRIVER_OPTIONS[@]}" -- sh -c "exec $SUT" > /tmp/replay.log 2>&1 || { tail -n 20 /tmp/replay.log; exit 1; }
tail -n 1 /tmp/replay.log
cp /tmp/replay-out/cov_over_time.csv "/opt/output/$COVERAGE_FILE"
'
