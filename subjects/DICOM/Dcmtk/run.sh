#!/bin/bash

FUZZER=$1     #fuzzer name (e.g., aflnet) -- this name must match the name of the fuzzer folder inside the Docker container
OUTDIR=$2     #name of the output folder
OPTIONS=$3    #all configured options -- to make it flexible, we only fix some options (e.g., -i, -o, -N) in this script
TIMEOUT=$4    #time for fuzzing
SKIPCOUNT=$5  #used for calculating cov over time. e.g., SKIPCOUNT=5 means we run gcovr after every 5 test cases

strstr() {
  [ "${1#*$2*}" = "$1" ] && return 1
  return 0
}

#Commands for afl-based fuzzers (e.g., aflnet, stateafl)
if $(strstr $FUZZER "afl"); then

  # Run fuzzer-specific commands (if any)
  if [ -e ${WORKDIR}/run-${FUZZER} ]; then
    source ${WORKDIR}/run-${FUZZER}
  fi

  TARGET_DIR=${TARGET_DIR:-"dcmtk"}
  INPUTS=${INPUTS:-${WORKDIR}"/in-dicom"}

  #Step-1. Do Fuzzing
  #Move to fuzzing folder
  cd $WORKDIR/${TARGET_DIR}/build/bin
  timeout -k 0 --preserve-status $TIMEOUT /home/ubuntu/${FUZZER}/afl-fuzz -d -i ${INPUTS} -o $OUTDIR -N tcp://127.0.0.1/5158 $OPTIONS -c ${WORKDIR}/clean ./dcmqrscp --single-process

  STATUS=$?

  #Step-2. Collect code coverage over time
  #Move to gcov folder
  cd $WORKDIR/dcmtk-gcov/build/bin

  measure-queue-coverage ${WORKDIR}/${TARGET_DIR}/build/bin/${OUTDIR}/replayable-queue ${WORKDIR}/${TARGET_DIR}/build/bin/${OUTDIR}/cov_over_time.csv ${SKIPCOUNT}

  gcovr -r $WORKDIR/dcmtk-gcov --html --html-details -o index.html
  mkdir ${WORKDIR}/${TARGET_DIR}/build/bin/${OUTDIR}/cov_html/
  cp *.html ${WORKDIR}/${TARGET_DIR}/build/bin/${OUTDIR}/cov_html/

  #Step-3. Save the result to the ${WORKDIR} folder
  #Tar all results to a file
  cd ${WORKDIR}/${TARGET_DIR}/build/bin
  tar -zcvf ${WORKDIR}/${OUTDIR}.tar.gz ${OUTDIR}

  exit $STATUS
fi
