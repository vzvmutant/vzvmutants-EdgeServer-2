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
        continue
    fi

    # ------------------------------------------------------------------
    #  FILTER RULE 2:
    #  Drop OpenVPN noise
    # ------------------------------------------------------------------
    echo "$line" | grep -q "openvpn" && {
        echo "$line" | grep -q "VERIFY OK" && continue
        echo "$line" | grep -q "WARNING: 'link-mtu' is used inconsistently" && continue
        echo "$line" | grep -q "WARNING: 'auth' is used inconsistently" && continue
        echo "$line" | grep -q "WARNING: 'keysize' is used inconsistently" && continue
        echo "$line" | grep -q "Outgoing Data Channel: Cipher" && continue
        echo "$line" | grep -q "Incoming Data Channel: Cipher" && continue
        echo "$line" | grep -q "Control Channel: TLSv1.3" && continue
    }

    # ------------------------------------------------------------------
    #  FILTER RULE 3:
    #  Drop ntpclient chatter
    # ------------------------------------------------------------------
    echo "$line" | grep -q "ntpclient" && {
        echo "$line" | grep -q "Connecting to" && continue
        echo "$line" | grep -q "Timed out waiting for" && continue
        echo "$line" | grep -q "Time set from" && continue
    }

    # ------------------------------------------------------------------
    #  FILTER RULE 4:
    #  Drop process_monitor NTP success spam
    # ------------------------------------------------------------------
    echo "$line" | grep -q "process_monitor" && {
        echo "$line" | grep -q "cyclic NTP Update success" && continue
    }

    # ------------------------------------------------------------------
    #  FILTER RULE 5:
    #  Drop dnscrypt-proxy certificate rotation noise
    # ------------------------------------------------------------------
    echo "$line" | grep -q "dnscrypt-proxy" && {
        echo "$line" | grep -q "Refetching server certificates" && continue
        echo "$line" | grep -q "Server certificate with serial" && continue
        echo "$line" | grep -q "This certificate is valid" && continue
        echo "$line" | grep -q "Chosen certificate" && continue
        echo "$line" | grep -q "key rotation period" && continue
    }

    # ------------------------------------------------------------------
    #  FILTER RULE 6:
    #  Drop dnsmasq startup chatter
    # ------------------------------------------------------------------
    echo "$line" | grep -q "dnsmasq" && {
        echo "$line" | grep -q "DNSSEC validation enabled" && continue
        echo "$line" | grep -q "configured with trust anchor for <root>" && continue
        echo "$line" | grep -q "ignoring resolv-file flag" && continue
        echo "$line" | grep -q "using only locally-known addresses for domain test" && continue
        echo "$line" | grep -q "using only locally-known addresses for domain onion" && continue
        echo "$line" | grep -q "using only locally-known addresses for domain localhost" && continue
        echo "$line" | grep -q "using only locally-known addresses for domain local" && continue
        echo "$line" | grep -q "using only locally-known addresses for domain invalid" && continue
        echo "$line" | grep -q "using only locally-known addresses for domain bind" && continue
        echo "$line" | grep -q "using nameserver 127.0.0.1#30" && continue
        echo "$line" | grep -q "read /etc/hosts" && continue
        echo "$line" | grep -q "read /tmp/blocking_hosts/hosts05" && continue
        echo "$line" | grep -q "read /tmp/blocking_hosts/hosts02" && continue
    }

    # If not filtered, write to real log
    echo "$line" >> "$OUT"

done < "$FIFO"