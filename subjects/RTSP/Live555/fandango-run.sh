#!/bin/bash

FUZZER=$1     #fuzzer name (e.g., aflnet) -- this name must match the name of the fuzzer folder inside the Docker container
OUTDIR=$2     #name of the output folder
OPTIONS=$3    #all configured options -- to make it flexible, we only fix some options (e.g., -i, -o, -N) in this script
TIMEOUT=$4    #time for fuzzing
SKIPCOUNT=$5  #used for calculating cov over time. e.g., SKIPCOUNT=5 means we run gcovr after every 5 test cases

#Commands for the fandango driver
if [ $FUZZER = "fandango" ]; then

  TARGET_DIR=${TARGET_DIR:-"live555-fandango"}
  INPUTS=${WORKDIR}/in-rtsp

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
  cd $WORKDIR/${TARGET_DIR}/testProgs
  timeout -k 0 --preserve-status $TIMEOUT /home/ubuntu/fandango/bin/fandango-driver talk --out $OUTDIR --endpoint tcp://127.0.0.1/8554 --budget $TIMEOUT $OPTIONS -- ./testOnDemandRTSPServer 8554

  STATUS=$?

  #Step-2. Collect code coverage over time
  #Move to gcov folder
  cd $WORKDIR/live555-cov/testProgs

  measure-queue-coverage ${WORKDIR}/${TARGET_DIR}/testProgs/${OUTDIR}/replayable-queue ${WORKDIR}/${TARGET_DIR}/testProgs/${OUTDIR}/cov_over_time.csv ${SKIPCOUNT}

  cd $WORKDIR/live555-cov
  #copy .hh files since gcovr could not detect them
  for f in BasicUsageEnvironment liveMedia groupsock UsageEnvironment; do
    echo $f
    cp $f/include/*.hh $f/
  done
  cd testProgs

  #Coverage of the seeds of the seed-based fuzzers followed by the Fandango sessions, to compare with them
  cd $WORKDIR/live555-cov/testProgs
  SEEDED=$(mktemp -d)
  mkdir ${SEEDED}/replayable-queue
  cp ${WORKDIR}/in-rtsp-replay/*.raw ${SEEDED}/replayable-queue/
  touch -d @$(sed -n 's/^start_time *: *//p' ${WORKDIR}/${TARGET_DIR}/testProgs/${OUTDIR}/fuzzer_stats) ${SEEDED}/replayable-queue/*.raw
  cp -p ${WORKDIR}/${TARGET_DIR}/testProgs/${OUTDIR}/replayable-queue/id* ${SEEDED}/replayable-queue/ 2>/dev/null
  cp -pr ${WORKDIR}/${TARGET_DIR}/testProgs/${OUTDIR}/replayable-queue-side-messages ${SEEDED}/ 2>/dev/null
  measure-queue-coverage ${SEEDED}/replayable-queue ${WORKDIR}/${TARGET_DIR}/testProgs/${OUTDIR}/cov_over_time_with_seeds.csv ${SKIPCOUNT}
  rm -rf ${SEEDED}

  #Step-3. Save the result to the ${WORKDIR} folder
  #Tar all results to a file
  cd ${WORKDIR}/${TARGET_DIR}/testProgs
  tar -zcvf ${WORKDIR}/${OUTDIR}.tar.gz ${OUTDIR}

  exit $STATUS
fi
