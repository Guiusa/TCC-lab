#!/bin/bash
# ping_test.sh — send ICMP pings to suricata container
TARGET=192.168.100.10
COUNT=10
#echo "[*] Pinging $TARGET ($COUNT packets)..."
#ping -c "$COUNT" "$TARGET"

for i in {0..10}
do
	RND=$(( $RANDOM % $COUNT ))
	echo $RND
	sleep $RND

	ping -c1 "$TARGET"
done
