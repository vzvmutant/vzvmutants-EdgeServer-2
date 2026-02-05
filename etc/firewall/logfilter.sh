#!/bin/sh

# FIFO for intercepting syslog stream
FIFO="/opt/var/log/syslog.pipe"
OUT="/opt/var/log/messages"

# Ensure FIFO exists
[ -p "$FIFO" ] || {
    rm -f "$FIFO"
    mkfifo "$FIFO"
}

# Main filter loop
while read -r line; do

    # ------------------------------------------------------------------
    #  FILTER RULE 1:
    #  Drop "br0: received packet on vlan3 with own address as source address"
    # ------------------------------------------------------------------
    echo "$line" | grep -q "received packet on vlan3 with own address as source address"
    if [ $? -eq 0 ]; then
        # Drop silently
        continue
    fi

    # If not filtered, write to real log
    echo "$line" >> "$OUT"

done < "$FIFO"