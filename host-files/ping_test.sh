#!/bin/bash
# ping_test.sh — send ICMP pings to suricata container
TARGET=192.168.100.10
COUNT=30
echo "[*] Pinging $TARGET ($COUNT packets)..."
ping -c "$COUNT" "$TARGET"
