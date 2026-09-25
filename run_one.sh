#!/bin/bash

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

CPU=$(( ${JOBSLOT:-1} - 1 ))

source "$CONF"
OPTIONS=${OPTS[$TARGET,$FUZZER]:-}
DOCIMAGE=${IMAGE[$TARGET,$FUZZER]:-}
if [ -z "$OPTIONS" ] || [ -z "$DOCIMAGE" ]; then
  echo "ERROR: no configuration for $TARGET/$FUZZER" >&2
  exit 1
fi

# results-<target>/out-<target>-<fuzzer>_<i>.tar.gz
OUTDIR=out-${TARGET}-${FUZZER}
SAVETO=${RESULTS}/results-${TARGET}
DEST=${SAVETO}/${OUTDIR}_${IDX}.tar.gz
mkdir -p "$SAVETO"

if [ -f "$DEST" ]; then
  echo "[$(date +%FT%T)] SKIP  $TARGET $FUZZER #$IDX (result already exists)"
  exit 0
fi

id=$(docker run --cpuset-cpus="$CPU" -d -it "$DOCIMAGE" /bin/bash -c \
  "cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}") || exit 1
id=${id::12}
echo "[$(date +%FT%T)] START $TARGET $FUZZER #$IDX cpu=$CPU image=$DOCIMAGE id=$id"

docker wait "$id" >/dev/null

if docker cp "$id:${WORKDIR}/${OUTDIR}.tar.gz" "$DEST" >/dev/null 2>&1; then
  docker rm "$id" >/dev/null
  echo "[$(date +%FT%T)] DONE  $TARGET $FUZZER #$IDX"
else
  echo "[$(date +%FT%T)] FAIL  $TARGET $FUZZER #$IDX (container $id kept for inspection, see: docker logs $id)" >&2
  exit 1
fi