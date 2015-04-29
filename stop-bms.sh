#!/bin/bash

killall -u wentao -9 python

sleep 2

killall -u wentao -9 ndn-repo-ng

rm /home/wentao/repo-ng/ndn_repo.db
