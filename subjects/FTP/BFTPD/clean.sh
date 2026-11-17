#!/bin/bash

rm -rf /home/ubuntu/ftpshare/*
rm -rf /home/ubuntu/ftpshare/test /home/ubuntu/ftpshare/test.txt
mkdir /home/ubuntu/ftpshare/test
echo test > /home/ubuntu/ftpshare/test.txt
echo test > /home/ubuntu/ftpshare/test/test.txt
chmod -R a+rwX /home/ubuntu/ftpshare/test /home/ubuntu/ftpshare/test.txt
