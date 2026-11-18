#!/bin/bash

FUZZER=$1     #fuzzer name (e.g., aflnet) -- this name must match the name of the fuzzer folder inside the Docker container
OUTDIR=$2     #name of the output folder
OPTIONS=$3    #all configured options -- to make it flexible, we only fix some options (e.g., -i, -o, -N) in this script
TIMEOUT=$4    #time for fuzzing
SKIPCOUNT=$5  #used for calculating cov over time. e.g., SKIPCOUNT=5 means we run gcovr after every 5 test cases

#Network deamons needed by forked-daapd
sudo /etc/init.d/dbus start
sudo /etc/init.d/avahi-daemon start

sudo /etc/init.d/dbus status
if [ $? -ne 0 ]
then
  echo "Unable to run DBUS"
  exit 1
fi

sudo /etc/init.d/avahi-daemon status
if [ $? -ne 0 ]
then
  echo "Unable to run AVAHI daemon"
  exit 1
fi

#Commands for the fandango driver
if [ $FUZZER = "fandango" ]; then

  # Run fuzzer-specific commands (if any)
  if [ -e ${WORKDIR}/run-${FUZZER} ]; then
    source ${WORKDIR}/run-${FUZZER}
  fi

  TARGET_DIR=${TARGET_DIR:-"forked-daapd-fandango"}
  INPUTS=${INPUTS:-${WORKDIR}"/in-daap"}

  #Configure the spec for this setup from the KEY=VALUE files next to it
  for SPEC_ENV in ${WORKDIR}/fan-specs/*.env; do
    if [ -e "$SPEC_ENV" ]; then set -a; source "$SPEC_ENV"; set +a; fi
  done

  #Step-1. Do Fuzzing
  #Move to fuzzing folder
  cd $WORKDIR

  timeout -k 0 --preserve-status $TIMEOUT /home/ubuntu/fandango/bin/fandango-driver talk --out $OUTDIR --endpoint tcp://127.0.0.1/3689 --budget $TIMEOUT $OPTIONS -c ${WORKDIR}/clean -- ${WORKDIR}/${TARGET_DIR}/src/forked-daapd -d 0 -c ${WORKDIR}/forked-daapd.conf -f

  STATUS=$?

  #Step-2. Collect code coverage over time
  #Move to gcov folder
  cd $WORKDIR

  measure-queue-coverage ${WORKDIR}/${OUTDIR}/replayable-queue ${WORKDIR}/${OUTDIR}/cov_over_time.csv ${SKIPCOUNT}

  cd $WORKDIR/forked-daapd-gcov

  #Coverage of the seeds of the seed-based fuzzers followed by the Fandango sessions, to compare with them
  cd $WORKDIR
  SEEDED=$(mktemp -d)
  mkdir ${SEEDED}/replayable-queue
  cp ${WORKDIR}/in-daap-replay/*.raw ${SEEDED}/replayable-queue/
  touch -d @$(sed -n 's/^start_time *: *//p' ${WORKDIR}/${OUTDIR}/fuzzer_stats) ${SEEDED}/replayable-queue/*.raw
  cp -p ${WORKDIR}/${OUTDIR}/replayable-queue/id* ${SEEDED}/replayable-queue/ 2>/dev/null
  cp -pr ${WORKDIR}/${OUTDIR}/replayable-queue-side-messages ${SEEDED}/ 2>/dev/null
  measure-queue-coverage ${SEEDED}/replayable-queue ${WORKDIR}/${OUTDIR}/cov_over_time_with_seeds.csv ${SKIPCOUNT}
  rm -rf ${SEEDED}

  #Step-3. Save the result to the ${WORKDIR} folder
  #Tar all results to a file
  cd ${WORKDIR}
  tar -zcvf ${WORKDIR}/${OUTDIR}.tar.gz ${OUTDIR}

  exit $STATUS
fi
