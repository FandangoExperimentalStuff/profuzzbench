#!/bin/bash

find /home/fuzzing -mindepth 1 -maxdepth 1 -exec rm -rf {} +
rm -rf /home/fuzzing/test /home/fuzzing/test.txt
mkdir /home/fuzzing/test
echo test > /home/fuzzing/test.txt
echo test > /home/fuzzing/test/test.txt
chmod -R a+rwX /home/fuzzing/test /home/fuzzing/test.txt
