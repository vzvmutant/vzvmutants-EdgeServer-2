#!/bin/sh

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
    # FILTER RULE 1: vlan3 self-address noise
    # ------------------------------------------------------------------
    case "$line" in
        *"received packet on vlan3 with own address as source address"*)
            continue
        ;;
    esac

    # ------------------------------------------------------------------
    # FILTER RULE 2: OpenVPN noise
    # ------------------------------------------------------------------
    case "$line" in
        *openvpn*)
            case "$line" in
                *"VERIFY OK"* ) continue ;;
                *"WARNING: 'link-mtu' is used inconsistently"* ) continue ;;
                *"WARNING: 'auth' is used inconsistently"* ) continue ;;
                *"WARNING: 'keysize' is used inconsistently"* ) continue ;;
                *"Outgoing Data Channel: Cipher"* ) continue ;;
                *"Incoming Data Channel: Cipher"* ) continue ;;
                *"Control Channel: TLSv1.3"* ) continue ;;
            esac
        ;;
    esac

    # ------------------------------------------------------------------
    # FILTER RULE 3: ntpclient chatter
    # ------------------------------------------------------------------
    case "$line" in
        *ntpclient*)
            case "$line" in
                *"Connecting to"* ) continue ;;
                *"Timed out waiting for"* ) continue ;;
                *"Time set from"* ) continue ;;
            esac
        ;;
    esac

    # ------------------------------------------------------------------
    # FILTER RULE 4: process_monitor NTP spam
    # ------------------------------------------------------------------
    case "$line" in
        *process_monitor*)
            case "$line" in
                *"cyclic NTP Update success"* ) continue ;;
            esac
        ;;
    esac

    # ------------------------------------------------------------------
    # FILTER RULE 5: dnscrypt-proxy certificate rotation noise
    # ------------------------------------------------------------------
    case "$line" in
        *dnscrypt-proxy*)
            case "$line" in
                *"Refetching server certificates"* ) continue ;;
                *"Server certificate with serial"* ) continue ;;
                *"This certificate is valid"* ) continue ;;
                *"Chosen certificate"* ) continue ;;
                *"key rotation period"* ) continue ;;
            esac
        ;;
    esac

    # ------------------------------------------------------------------
    # FILTER RULE 6: dnsmasq startup/shutdown chatter
    # ------------------------------------------------------------------
    case "$line" in
        *dnsmasq*)
            case "$line" in
                *"exiting on receipt of SIGTERM"* ) continue ;;
                *"started, version"* ) continue ;;
                *"compile time options:"* ) continue ;;
                *"DNSSEC validation enabled"* ) continue ;;
                *"configured with trust anchor for <root>"* ) continue ;;
                *"ignoring resolv-file flag"* ) continue ;;
                *"using only locally-known addresses for domain test"* ) continue ;;
                *"using only locally-known addresses for domain onion"* ) continue ;;
                *"using only locally-known addresses for domain localhost"* ) continue ;;
                *"using only locally-known addresses for domain local"* ) continue ;;
                *"using only locally-known addresses for domain invalid"* ) continue ;;
                *"using only locally-known addresses for domain bind"* ) continue ;;
                *"using nameserver 127.0.0.1#30"* ) continue ;;
                *"read /etc/hosts"* ) continue ;;
                *"read /tmp/blocking_hosts/hosts05"* ) continue ;;
                *"read /tmp/blocking_hosts/hosts02"* ) continue ;;
            esac
        ;;
    esac

    # ------------------------------------------------------------------
    # Write unfiltered line to log
    # ------------------------------------------------------------------
    echo "$line" >> "$OUT"

done < "$FIFO"