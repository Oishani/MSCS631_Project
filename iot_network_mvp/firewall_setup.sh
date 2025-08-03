#!/bin/bash
# Usage: sudo ./firewall_setup.sh <GATEWAY_IP> <CLOUD_IP>
# Applies minimal iptables rules allowing only TLS traffic from gateway to cloud and back.

if [ "$#" -ne 2 ]; then
  echo "Usage: sudo $0 <GATEWAY_IP> <CLOUD_IP>"
  exit 1
fi

GATEWAY_IP="$1"
CLOUD_IP="$2"

echo "[*] Flushing existing rules..."
iptables -F
iptables -X

echo "[*] Setting default policies..."
iptables -P FORWARD DROP
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT

echo "[*] Allowing gateway -> cloud TLS (port 8443) and established responses..."
iptables -A FORWARD -s "$GATEWAY_IP" -d "$CLOUD_IP" -p tcp --dport 8443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s "$CLOUD_IP" -d "$GATEWAY_IP" -p tcp --sport 8443 -m state --state ESTABLISHED -j ACCEPT

echo "[+] Firewall rules applied."
