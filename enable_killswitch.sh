#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "Error: must be run as root" >&2
   exit 1
fi

# Use dedicated user to prevent ordinary user apps from bypassing the firewall
PROXY_USER="${PROXY_USER:-_proxyrotator}"
if ! id -u "$PROXY_USER" >/dev/null 2>&1; then
    useradd -r -s /bin/false "$PROXY_USER" 2>/dev/null || true
fi

# Flush existing rules
iptables -F
iptables -X

# Drop everything by default
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Loopback access (for apps connecting to 127.0.0.1:9050)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established/related incoming connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Only the proxy daemon user can make outbound internet connections
iptables -A OUTPUT -m owner --uid-owner "$PROXY_USER" -j ACCEPT

# Prevent lockout: keep SSH open
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT

echo "Kill switch active for proxy user '$PROXY_USER'."
echo "Outbound traffic is restricted to loopback (127.0.0.1:9050)."
