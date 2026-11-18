#!/bin/bash

FUZZER=$1     #fuzzer name (e.g., aflnet) -- this name must match the name of the fuzzer folder inside the Docker container
OUTDIR=$2     #name of the output folder
OPTIONS=$3    #all configured options -- to make it flexible, we only fix some options (e.g., -i, -o, -N) in this script
TIMEOUT=$4    #time for fuzzing
SKIPCOUNT=$5  #used for calculating cov over time. e.g., SKIPCOUNT=5 means we run gcovr after every 5 test cases

#Commands for the fandango driver
if [ $FUZZER = "fandango" ]; then

  TARGET_DIR=${TARGET_DIR:-"exim"}
  INPUTS=${WORKDIR}/in-smtp

  # Run fuzzer-specific commands (if any)
  if [ -e ${WORKDIR}/run-${FUZZER} ]; then
    source ${WORKDIR}/run-${FUZZER}
  fi

  #Configure the spec for this setup from the KEY=VALUE files next to it
  for SPEC_ENV in ${WORKDIR}/fan-specs/*.env; do
    if [ -e "$SPEC_ENV" ]; then set -a; source "$SPEC_ENV"; set +a; fi
  done

  #Step-1. Do Fuzzing
  #Move to fuzzing folder
  cd $WORKDIR/${TARGET_DIR}
  cp ./src/build-Linux-x86_64/exim /usr/exim/bin/exim
  timeout -k 0 --preserve-status $TIMEOUT /home/ubuntu/fandango/bin/fandango-driver talk --out $OUTDIR --endpoint tcp://127.0.0.1/25 --budget $TIMEOUT $OPTIONS -c ${WORKDIR}/clean -- exim -bd -d -oX 25 -oP /var/lock/exim.pid

  STATUS=$?

  ${WORKDIR}/clean
  killall exim 2>&1
  sleep 1

  #Step-2. Collect code coverage over time
  #Move to gcov folder
  cd $WORKDIR/exim-gcov
  cp ./src/build-Linux-x86_64/exim /usr/exim/bin/exim

  measure-queue-coverage ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/replayable-queue ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_over_time.csv ${SKIPCOUNT}

  #Coverage of the seeds of the seed-based fuzzers followed by the Fandango sessions, to compare with them
  cd $WORKDIR/exim-gcov
  SEEDED=$(mktemp -d)
  mkdir ${SEEDED}/replayable-queue
  cp ${WORKDIR}/in-smtp-replay/*.raw ${SEEDED}/replayable-queue/
  touch -d @$(sed -n 's/^start_time *: *//p' ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/fuzzer_stats) ${SEEDED}/replayable-queue/*.raw
  cp -p ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/replayable-queue/id* ${SEEDED}/replayable-queue/ 2>/dev/null
  cp -pr ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/replayable-queue-side-messages ${SEEDED}/ 2>/dev/null
  measure-queue-coverage ${SEEDED}/replayable-queue ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_over_time_with_seeds.csv ${SKIPCOUNT}
  rm -rf ${SEEDED}

  #Step-4. Save the result to the ${WORKDIR} folder
  #Tar all results to a file
  cd ${WORKDIR}/${TARGET_DIR}
  tar -zcvf ${WORKDIR}/${OUTDIR}.tar.gz ${OUTDIR}

  exit $STATUS
fi
