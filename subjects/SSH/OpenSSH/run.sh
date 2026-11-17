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

  TARGET_DIR=${TARGET_DIR:-"openssh"}
  INPUTS=${INPUTS:-${WORKDIR}"/in-ssh"}

  #Step-1. Do Fuzzing
  #Move to fuzzing folder
  cd $WORKDIR/${TARGET_DIR}

  # Run sshd and ssh once before fuzzing
  rm -rf ~/.ssh
  ./sshd -d -e -p 22 -r -f sshd_config &
  sleep 5
  sshpass -p "ubuntu" ssh -oStrictHostKeyChecking=no ubuntu@127.0.0.1 -p 22 "exit"

  timeout -k 0 --preserve-status $TIMEOUT /home/ubuntu/${FUZZER}/afl-fuzz -d -i ${INPUTS} -x ${WORKDIR}/ssh.dict -o $OUTDIR -N tcp://127.0.0.1/22 $OPTIONS ./sshd -d -e -p 22 -r -f sshd_config

  STATUS=$?

  #Step-2. Collect code coverage over time
  #Move to gcov folder
  cd $WORKDIR/openssh-gcov

  measure-queue-coverage ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/replayable-queue ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_over_time.csv ${SKIPCOUNT}

  #Step-3. Save the result to the ${WORKDIR} folder
  #Tar all results to a file
  cd ${WORKDIR}/${TARGET_DIR}
  tar -zcvf ${WORKDIR}/${OUTDIR}.tar.gz ${OUTDIR}

  exit $STATUS
fi
