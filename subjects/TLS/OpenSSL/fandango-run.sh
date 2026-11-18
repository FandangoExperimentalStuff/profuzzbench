#!/bin/bash

FUZZER=$1     #fuzzer name (e.g., aflnet) -- this name must match the name of the fuzzer folder inside the Docker container
OUTDIR=$2     #name of the output folder
OPTIONS=$3    #all configured options -- to make it flexible, we only fix some options (e.g., -i, -o, -N) in this script
TIMEOUT=$4    #time for fuzzing
SKIPCOUNT=$5  #used for calculating cov over time. e.g., SKIPCOUNT=5 means we run gcovr after every 5 test cases
#Commands for the fandango driver
if [ $FUZZER = "fandango" ]; then

  # Run fuzzer-specific commands (if any)
  if [ -e ${WORKDIR}/run-${FUZZER} ]; then
    source ${WORKDIR}/run-${FUZZER}
  fi

  TARGET_DIR=${TARGET_DIR:-"openssl"}
  INPUTS=${INPUTS:-"${WORKDIR}/in-tls"}

  #Configure the spec for this setup from the KEY=VALUE files next to it
  for SPEC_ENV in ${WORKDIR}/fan-specs/*.env; do
    if [ -e "$SPEC_ENV" ]; then set -a; source "$SPEC_ENV"; set +a; fi
  done

  #Step-1. Do Fuzzing
  #Move to fuzzing folder
  cd $WORKDIR/${TARGET_DIR}
  #s_server ends a connection at the end of its stdin; the driver starts it without one, so it reads a FIFO that stays open
  SERVER_STDIN=$(mktemp -u)
  mkfifo $SERVER_STDIN
  timeout -k 0 --preserve-status $TIMEOUT /home/ubuntu/fandango/bin/fandango-driver talk --out $OUTDIR --endpoint tcp://127.0.0.1/4433 --budget $TIMEOUT $OPTIONS -- sh -c "exec ./apps/openssl s_server -key key.pem -cert cert.pem -4 -naccept 1 -no_anti_replay 0<>$SERVER_STDIN"

  STATUS=$?

  #Step-2. Collect code coverage over time
  #Move to gcov folder
  cd $WORKDIR/openssl-gcov

  measure-queue-coverage ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/replayable-queue ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_over_time.csv ${SKIPCOUNT}

  #Coverage of the seeds of the seed-based fuzzers followed by the Fandango sessions, to compare with them
  cd $WORKDIR/openssl-gcov
  SEEDED=$(mktemp -d)
  mkdir ${SEEDED}/replayable-queue
  cp ${WORKDIR}/in-tls-replay/*.raw ${SEEDED}/replayable-queue/
  touch -d @$(sed -n 's/^start_time *: *//p' ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/fuzzer_stats) ${SEEDED}/replayable-queue/*.raw
  cp -p ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/replayable-queue/id* ${SEEDED}/replayable-queue/ 2>/dev/null
  cp -pr ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/replayable-queue-side-messages ${SEEDED}/ 2>/dev/null
  measure-queue-coverage ${SEEDED}/replayable-queue ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_over_time_with_seeds.csv ${SKIPCOUNT}
  rm -rf ${SEEDED}

  #Step-3. Save the result to the ${WORKDIR} folder
  #Tar all results to a file
  cd ${WORKDIR}/${TARGET_DIR}
  tar -zcvf ${WORKDIR}/${OUTDIR}.tar.gz ${OUTDIR}

  exit $STATUS
fi
