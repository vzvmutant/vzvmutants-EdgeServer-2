#!/bin/sh

tail -F /opt/var/log/kern.info | \
grep --line-buffered "IPT-" >> /opt/var/log/iptables.log