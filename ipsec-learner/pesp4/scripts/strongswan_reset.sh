#!/bin/bash
ssh -b 192.168.100.101 -o StrictHostKeyChecking=no root@192.168.100.201 << eeooff
/home/zdl/strongswan/IPSEC/sbin/ipsec stop
sleep 0.3
/home/zdl/strongswan/IPSEC/sbin/ipsec start
sleep 0.3
/home/zdl/strongswan/IPSEC/sbin/swanctl -q
sleep 0.3
exit
eeooff

