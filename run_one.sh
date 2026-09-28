#!/bin/bash
# Executes a single fuzzing run, equivalent to one container of profuzzbench_exec_common.sh,
# but pinned to CPU $JOBCPU (set by launch.sh) and with results collected as soon as the run finishes.
# Usage: run_one.sh <target> <fuzzer> <run-index>
set -u

TARGET=$1
FUZZER=$2
IDX=$3

CONF=${CONF:-./jobs.conf}
TIMEOUT=${TIMEOUT:-86400}
SKIPCOUNT=${SKIPCOUNT:-5}
export TEST_TIMEOUT=${TEST_TIMEOUT:-5000}
RESULTS=${RESULTS:-.}
WORKDIR=/home/ubuntu/experiments

CPU=${JOBCPU:-0}

source "$CONF"
OPTIONS=${OPTS[$TARGET,$FUZZER]:-}
DOCIMAGE=${IMAGE[$TARGET,$FUZZER]:-}
if [ -z "$OPTIONS" ] || [ -z "$DOCIMAGE" ]; then
  echo "ERROR: no configuration for $TARGET/$FUZZER" >&2
  exit 1
fi

# Same layout as ProFuzzBench: results-<target>/out-<target>-<fuzzer>_<i>.tar.gz
OUTDIR=out-${TARGET}-${FUZZER}
SAVETO=${RESULTS}/results-${TARGET}
DEST=${SAVETO}/${OUTDIR}_${IDX}.tar.gz
mkdir -p "$SAVETO"

if [ -f "$DEST" ]; then
  echo "[$(date +%FT%T)] SKIP  $TARGET $FUZZER #$IDX (result already exists)"
  exit 0
fi

# Startup failures (e.g. AFLNet "states hashtable should always contain an entry of the initial
# state" when the server did not answer in time) happen within seconds, before any fuzzing.
# Such runs are retried; runs that end prematurely later are NOT retried, to avoid biasing results.
MAX_ATTEMPTS=${MAX_ATTEMPTS:-3}
STARTUP_GRACE=${STARTUP_GRACE:-600}   # seconds

for ((attempt=1; attempt<=MAX_ATTEMPTS; attempt++)); do
  id=$(docker run --label pfb-campaign=1 --cpuset-cpus="$CPU" -d -it "$DOCIMAGE" /bin/bash -c \
    "cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}") || exit 1
  id=${id::12}
  START=$(date +%s)
  echo "[$(date +%FT%T)] START $TARGET $FUZZER #$IDX cpu=$CPU image=$DOCIMAGE id=$id attempt=$attempt"

  docker wait "$id" >/dev/null
  ELAPSED=$(( $(date +%s) - START ))

  # Completed normally: fuzzing ran for (almost) the full TIMEOUT
  [ "$ELAPSED" -ge $(( TIMEOUT * 95 / 100 )) ] && break

  # Aborted during startup: keep the log for reference, discard the container and retry
  if [ "$ELAPSED" -lt "$STARTUP_GRACE" ] && [ "$attempt" -lt "$MAX_ATTEMPTS" ]; then
    LOGFILE=${SAVETO}/${OUTDIR}_${IDX}.attempt${attempt}.log
    docker logs "$id" > "$LOGFILE" 2>&1
    docker rm "$id" >/dev/null
    echo "[$(date +%FT%T)] RETRY $TARGET $FUZZER #$IDX (aborted after ${ELAPSED}s during startup; log: $LOGFILE)"
    sleep 5
    continue
  fi

  echo "[$(date +%FT%T)] FAIL  $TARGET $FUZZER #$IDX (ended after ${ELAPSED}s < TIMEOUT ${TIMEOUT}s, attempt $attempt; container $id kept, see: docker logs $id)" >&2
  exit 1
done

if docker cp "$id:${WORKDIR}/${OUTDIR}.tar.gz" "$DEST" >/dev/null 2>&1; then
  docker rm "$id" >/dev/null
  echo "[$(date +%FT%T)] DONE  $TARGET $FUZZER #$IDX (${ELAPSED}s, attempt $attempt)"
else
  echo "[$(date +%FT%T)] FAIL  $TARGET $FUZZER #$IDX (container $id kept for inspection, see: docker logs $id)" >&2
  exit 1
fi