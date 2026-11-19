#!/bin/bash

rm -f $WORKDIR/dcmtk/build/bin/ACME_STORE/*
if [ ! -c /dev/null ]; then
  rm -f /dev/null
  mknod -m 666 /dev/null c 1 3
fi
