#!/bin/sh
# radvd.sh — unified RADVD launcher for DD‑WRT BusyBox
# Location: /opt/etc/radvd/radvd.sh

RADVD_DIR="/opt/etc/radvd"
VARS="$RADVD_DIR/radvd.conf.vars"
TEMPLATE="$RADVD_DIR/radvd.conf.template.sh"
CONF_OUT="/opt/etc/radvd/radvd.conf"
PIDFILE="/var/run/radvd.pid"

log() {
    echo "[radvd] $1"
}

# Ensure /opt is mounted
if [ ! -d /opt ]; then
    log "/opt not mounted — aborting"
    exit 1
fi

# Ensure required files exist
if [ ! -f "$VARS" ]; then
    log "Missing vars file: $VARS"
    exit 1
fi

if [ ! -f "$TEMPLATE" ]; then
    log "Missing template generator: $TEMPLATE"
    exit 1
fi

# Stop any running radvd
if [ -f "$PIDFILE" ]; then
    PID="$(cat $PIDFILE 2>/dev/null)"
    if [ ! -z "$PID" ]; then
        kill "$PID" 2>/dev/null
        sleep 1
    fi
fi

# Generate fresh radvd.conf
log "Generating radvd.conf..."
. "$TEMPLATE" > "$CONF_OUT"

if [ $? -ne 0 ]; then
    log "Template generation failed"
    exit 1
fi

# Start radvd
log "Starting radvd..."
radvd -C "$CONF_OUT" -p "$PIDFILE"

if [ $? -ne 0 ]; then
    log "radvd failed to start"
    exit 1
fi

log "radvd running with config: $CONF_OUT"
exit 0