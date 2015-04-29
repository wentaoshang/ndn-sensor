#!/bin/bash

echo "Kill all running BMS processes..."

killall -u wentao -9 python

sleep 2

killall -u wentao -9 ndn-repo-ng

#p=$(pidof ndn-repo-ng)
#if [ "x$p" = "x" ]
#then kill -9 $p
#fi

sleep 2

echo "Done"

echo "Remove old repo-ng database file"

rm /home/wentao/repo-ng/ndn_repo.db

echo "Start repo-ng..."

/usr/local/bin/ndn-repo-ng -c /home/wentao/repo-ng/repo-ng.conf &

sleep 2

echo "Done"

echo "Publish keychain info"

cd /home/wentao/ndn-sensor/keychain/

/usr/bin/python publish_keychain.py

echo "Start BACnet data collector"

cd /home/wentao/ndn-sensor/melnitz/

/usr/bin/python publish_bacnet.py &

#cd /home/wentao/ndn-sensor/strathmore/

#python publish_modbus.py &
