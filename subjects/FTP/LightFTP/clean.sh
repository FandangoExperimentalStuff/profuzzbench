#!/bin/bash

find /home/ubuntu/ftpshare -mindepth 1 -maxdepth 1 -exec rm -rf {} +
rm -rf /home/ubuntu/ftpshare/test /home/ubuntu/ftpshare/test.txt
mkdir /home/ubuntu/ftpshare/test
echo test > /home/ubuntu/ftpshare/test.txt
echo test > /home/ubuntu/ftpshare/test/test.txt
chmod -R a+rwX /home/ubuntu/ftpshare/test /home/ubuntu/ftpshare/test.txt

rm ~/fftplog
