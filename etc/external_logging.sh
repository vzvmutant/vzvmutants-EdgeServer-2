#!/bin/sh
# Ensure log directory exists
mkdir -p /opt/var/log

# Kill existing syslogd/klogd
killall syslogd
killall klogd

# Start syslogd writing to /opt/var/log/
syslogd -L -s 500 -O /opt/var/log/messages -S

# Start kernel logger
klogd