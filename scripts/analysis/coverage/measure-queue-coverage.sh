#!/bin/bash
# Usage: measure-queue-coverage <queue-dir> <coverage-csv> <sessions-per-sample>
# Replays every framed session file of <queue-dir> once, in the order the fuzzer saved them, against the gcov build
# described by coverage-replay.env and writes the coverage over time to <coverage-csv>, in the cov_over_time.csv format of ProFuzzBench,
# and the line coverage per file after the last session next to it, as gcovr JSON (<coverage-csv> with _lines.json for .csv)
# and as HTML report (<coverage-csv> with _html/index.html for .csv), which leaves out the files whose source is missing.
set -eu

QUEUE=$1
COVERAGE_CSV=$2
LINE_COVERAGE_JSON=${COVERAGE_CSV%.csv}_lines.json
LINE_COVERAGE_HTML=${COVERAGE_CSV%.csv}_html
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
gcovr -r "$GCOV_ROOT" --json -o "$LINE_COVERAGE_JSON"
MISSING_SOURCE_FILTERS=()
while IFS= read -r MISSING_SOURCE; do
  MISSING_SOURCE_FILTERS+=(-e "$MISSING_SOURCE")
done < <(python3 -c '
import json, os, re, sys
for entry in json.load(open(sys.argv[1]))["files"]:
    source = os.path.join(sys.argv[2], entry["file"])
    if not os.path.exists(source):
        print(re.escape(os.path.abspath(source)))
' "$LINE_COVERAGE_JSON" "$GCOV_ROOT")
mkdir -p "$LINE_COVERAGE_HTML"
gcovr -r "$GCOV_ROOT" "${MISSING_SOURCE_FILTERS[@]}" --html --html-details -o "$LINE_COVERAGE_HTML/index.html"
