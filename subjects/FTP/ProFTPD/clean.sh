#!/bin/bash

#cp /home/ubuntu/ftpshare/home/ubuntu/experiments/proftpd-gcov/src/*.gcda /home/ubuntu/experiments/proftpd-gcov/src/ > /dev/null 2>&1
#cp /home/ubuntu/ftpshare/home/ubuntu/experiments/proftpd-gcov/lib/*.gcda /home/ubuntu/experiments/proftpd-gcov/lib/ > /dev/null 2>&1
#cp /home/ubuntu/ftpshare/home/ubuntu/experiments/proftpd-gcov/modules/*.gcda /home/ubuntu/experiments/proftpd-gcov/modules/ > /dev/null 2>&1
#cp /home/ubuntu/ftpshare/home/ubuntu/experiments/proftpd-gcov/utils/*.gcda /home/ubuntu/experiments/proftpd-gcov/utils/ > /dev/null 2>&1
find /home/ubuntu/ftpshare -mindepth 1 -maxdepth 1 -exec rm -rf {} +
find /home/ubuntu -mindepth 1 -maxdepth 1 \
  ! -name .bash_logout ! -name .bashrc ! -name .profile ! -name .cache \
  ! -name .tree.mvp ! -name .tree.count.mvp \
  ! -name aflnet ! -name stateafl ! -name driver ! -name fandango ! -name fandango-workspace \
  ! -name experiments ! -name ftpshare \
  ! -name 'proftpd.pid' ! -name 'proftpd.scoreboard*' \
  -exec rm -rf {} +
mkdir /home/ubuntu/test
echo test > /home/ubuntu/test.txt
echo test > /home/ubuntu/test/test.txt
chmod -R a+rwX /home/ubuntu/test /home/ubuntu/test.txt
