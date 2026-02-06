#!/bin/sh

### Modular iptables/ip6tables Firewall for DD-WRT ###
### Router: Edgie_McEdgeface | Host: Singularities_edge | Domain: vzvmutants.damnserver.com ###

ROUTER_NAME="Edgie_McEdgeface"
HOSTNAME="Singularities_edge"
DOMAIN="vzvmutants.damnserver.com"

## Wait for /opt to be available
i=0
while [ ! -d /opt ] && [ $i -lt 30 ]; do
    sleep 1
    i=$((i+1))
done

# Capture WAN interface safely
WAN="$(get_wanface)"
while [ -z "$WAN" ]; do
    sleep 2
    WAN="$(get_wanface)"
done

### Flush existing rules ###
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X

ip6tables -F
ip6tables -X

### Default policies ###
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT ACCEPT

### Noise filter ###
iptables -N NOISE_DROP 2>/dev/null

iptables -I INPUT -j NOISE_DROP
iptables -I FORWARD -j NOISE_DROP

### IP sets ###
ipset create badactors hash:ip maxelem 10000 -exist
ipset create benign_teardown hash:net -exist

### Base allowances ###

# Loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT -i lo -j ACCEPT

# Established/related
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Drop invalid packets                                              PT
iptables -A INPUT -m state --state INVALID -j DROP
ip6tables -A INPUT -m state --state INVALID -j DROP

### Suppress IGMP (protocol 2) ###
iptables -A INPUT -p 2 -j DROP
iptables -A FORWARD -p 2 -j DROP

### IP set handling ###
iptables -A INPUT -m set --match-set badactors src \
    -m limit --limit 1/min \
    -j LOG --log-prefix "$ROUTER_NAME IPSET DROP: " --log-level 4

iptables -A INPUT -m set --match-set badactors src -j DROP
                                                            PT
### LAN → Router (management, DNS, DHCP) ###
iptables -A INPUT -i br0 -p udp --dport 67:68 \
    -m comment --comment "DHCP to $HOSTNAME.$DOMAIN" -j ACCEPT

iptables -A INPUT -i br0 -p udp --dport 53 \
    -m comment --comment "DNS (UDP) to $HOSTNAME.$DOMAIN" -j ACCEPT

iptables -A INPUT -i br0 -p tcp --dport 53 \
    -m comment --comment "DNS (TCP) to $HOSTNAME.$DOMAIN" -j ACCEPT

iptables -A INPUT -i br0 -p tcp --dport 443 \
    -m comment --comment "HTTPS admin to $ROUTER_NAME" -j ACCEPT

iptables -A INPUT -i br0 -p tcp --dport 2222 \
    -m comment --comment "SSH to $ROUTER_NAME" -j ACCEPT

### IPv6 LAN → Router (ULA fd10:42:0:1::/64) ###
ip6tables -A INPUT -i br0 -s fd10:42:0:1::/64 \
    -m comment --comment "IPv6 LAN ULA to $HOSTNAME.$DOMAIN" -j ACCEPT

# IPv6 DNS
ip6tables -A INPUT -i br0 -p udp --dport 53 \
    -m comment --comment "IPv6 DNS (UDP) to $HOSTNAME.$DOMAIN" -j ACCEPT

ip6tables -A INPUT -i br0 -p tcp --dport 53 \
    -m comment --comment "IPv6 DNS (TCP) to $HOSTNAME.$DOMAIN" -j ACCEPT

# IPv6 HTTPS + SSH
ip6tables -A INPUT -i br0 -p tcp --dport 443 \
    -m comment --comment "IPv6 HTTPS admin to $ROUTER_NAME" -j ACCEPT

ip6tables -A INPUT -i br0 -p tcp --dport 2222 \
    -m comment --comment "IPv6 SSH to $ROUTER_NAME" -j ACCEPT

### LAN → WAN forwarding + NAT ###
iptables -A FORWARD -i br0 -o "$WAN" \
    -m comment --comment "LAN → WAN forwarding" -j ACCEPT

iptables -t nat -A POSTROUTING -o "$WAN" \
    -m comment --comment "NAT masquerade" -j MASQUERADE

### MTU / MSS Clamping ###
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
    -o "$WAN" -j TCPMSS --clamp-mss-to-pmtu

iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
    -i "$WAN" -j TCPMSS --clamp-mss-to-pmtu

ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
    -o "$WAN" -j TCPMSS --clamp-mss-to-pmtu

ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
    -i "$WAN" -j TCPMSS --clamp-mss-to-pmtu

### Inbound scan/drop controls ###
iptables -N SYN_SCAN_DROP 2>/dev/null
iptables -N LOGGING 2>/dev/null
iptables -N UDP_NOISE 2>/dev/null

# Rate-limit noisy UDP
iptables -A INPUT -i "$WAN" -p udp -m conntrack --ctstate NEW \
    -m recent --set --name udpnoise --rsource

iptables -A INPUT -i "$WAN" -p udp -m recent --update \
    --seconds 300 --hitcount 5 --name udpnoise --rsource -j DROP

# SYN scan handling
iptables -A INPUT -i "$WAN" -p tcp --syn -m state --state NEW -j SYN_SCAN_DROP
iptables -A SYN_SCAN_DROP -j CONNMARK --set-mark 0x1
iptables -A SYN_SCAN_DROP -j DROP

# Log/drop inbound 443 traffic
iptables -A INPUT -i "$WAN" -p tcp --sport 443 \
    -j LOGGING

iptables -A INPUT -i "$WAN" -p udp --sport 443 \
    -j LOGGING

iptables -A LOGGING -m limit --limit 2/min --limit-burst 5 \
    -j LOG --log-prefix "$ROUTER_NAME DROP: " --log-level 4

iptables -A LOGGING -j DROP

### ICMP controls ###

# WAN: allow essential ICMP types
iptables -A INPUT -i "$WAN" -p icmp --icmp-type destination-unreachable -j ACCEPT
iptables -A INPUT -i "$WAN" -p icmp --icmp-type time-exceeded -j ACCEPT
iptables -A INPUT -i "$WAN" -p icmp --icmp-type parameter-problem -j ACCEPT
iptables -A INPUT -i "$WAN" -p icmp --icmp-type fragmentation-needed -j ACCEPT

# WAN: drop echo-requests (external pings)
iptables -A INPUT -i "$WAN" -p icmp --icmp-type echo-request -j DROP

# LAN: allow limited echo-requests
iptables -A INPUT -i br0 -p icmp --icmp-type echo-request \
    -m limit --limit 5/second --limit-burst 10 -j ACCEPT

iptables -A INPUT -i br0 -p icmp --icmp-type echo-request -j DROP

# IPv6: allow ICMPv6 (ND, RA, PMTU discovery)
ip6tables -A INPUT -p ipv6-icmp -j ACCEPT

### Catch-all logging ###
iptables -A INPUT -m limit --limit 5/min \
    -j LOG --log-prefix "$ROUTER_NAME IPv4 DROP: " --log-level 4