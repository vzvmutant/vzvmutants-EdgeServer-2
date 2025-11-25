# Flush existing rules
iptables -F
iptables -t nat -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow LAN access
iptables -A INPUT -i br0 -j ACCEPT
iptables -A FORWARD -i br0 -o vlan2 -j ACCEPT
iptables -A FORWARD -i vlan2 -o br0 -m state --state ESTABLISHED,RELATED -j ACCEPT

# NAT masquerade
iptables -t nat -A POSTROUTING -o vlan2 -j MASQUERADE

# Optional: allow router admin from LAN only
iptables -A INPUT -i br0 -p tcp --dport 22 -j ACCEPT   # SSH
iptables -A INPUT -i br0 -p tcp --dport 80 -j ACCEPT   # WebUI