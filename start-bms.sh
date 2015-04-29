#!/bin/bash

rm /home/wentao/repo-ng/ndn_repo.db

ndn-repo-ng -c /home/wentao/repo-ng/repo-ng.conf &

sleep 2

cd /home/wentao/ndn-sensor/melnitz/

python publish_bacnet.py &

cd /home/wentao/ndn-sensor/strathmore/

python publish_modbus.py &
