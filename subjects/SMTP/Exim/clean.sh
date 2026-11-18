#!/bin/bash

pkill -F /var/lock/exim.pid
rm -f /var/spool/exim/input/* /var/spool/exim/msglog/*
rm -f /var/spool/exim/db/* /var/mail/*
