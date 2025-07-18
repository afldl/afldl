#!/bin/bash
ssh -b 192.168.100.101 -o StrictHostKeyChecking=no root@192.168.100.201 << eeooff
ipsec restart
sleep 1.5
rm -rf /var/log/pluto.log
exit
eeooff


