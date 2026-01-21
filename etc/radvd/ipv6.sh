#!/bin/sh

RADVD_DIR="/opt/etc/radvd"
RADVD_CONF="${RADVD_DIR}/radvd.conf"
RADVD_TEMPLATE="${RADVD_DIR}/radvd.conf.template.sh"

# Wait for USB + Optware + network
sleep 10

# Generate config
sh "${RADVD_TEMPLATE}" > "${RADVD_CONF}"

# Restart radvd
killall radvd 2>/dev/null
sleep 1
radvd -C "${RADVD_CONF}"