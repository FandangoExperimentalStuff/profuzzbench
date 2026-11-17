#!/bin/bash

#cp /home/ubuntu/ftpshare/home/ubuntu/experiments/proftpd-gcov/src/*.gcda /home/ubuntu/experiments/proftpd-gcov/src/ > /dev/null 2>&1
#cp /home/ubuntu/ftpshare/home/ubuntu/experiments/proftpd-gcov/lib/*.gcda /home/ubuntu/experiments/proftpd-gcov/lib/ > /dev/null 2>&1
#cp /home/ubuntu/ftpshare/home/ubuntu/experiments/proftpd-gcov/modules/*.gcda /home/ubuntu/experiments/proftpd-gcov/modules/ > /dev/null 2>&1
#cp /home/ubuntu/ftpshare/home/ubuntu/experiments/proftpd-gcov/utils/*.gcda /home/ubuntu/experiments/proftpd-gcov/utils/ > /dev/null 2>&1
rm -rf /home/ubuntu/ftpshare/*
rm -rf /home/ubuntu/test /home/ubuntu/test.txt
mkdir /home/ubuntu/test
echo test > /home/ubuntu/test.txt
echo test > /home/ubuntu/test/test.txt
chmod -R a+rwX /home/ubuntu/test /home/ubuntu/test.txt
