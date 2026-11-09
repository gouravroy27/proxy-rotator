#!/usr/bin/env bash
# disable_killswitch.sh
#
# RESTORES NORMAL NETWORK ACCESS.

set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "Restoring firewall to default (ALLOW ALL)..."

iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -X

echo "Kill switch DISABLED. Normal network access restored."
