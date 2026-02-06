#!/bin/sh

# Ensure log directory exists
mkdir -p /opt/var/log

# Kill existing loggers
killall syslogd
killall klogd

# Create FIFO if missing
[ -p /opt/var/log/syslog.pipe ] || {
    rm -f /opt/var/log/syslog.pipe
    mkfifo /opt/var/log/syslog.pipe
}

# Start filter module
/opt/etc/firewall/logfilter.sh &

# Start syslogd writing to FIFO instead of messages
syslogd -L -s 500 -O /opt/var/log/syslog.pipe

# Start kernel logger
klogd