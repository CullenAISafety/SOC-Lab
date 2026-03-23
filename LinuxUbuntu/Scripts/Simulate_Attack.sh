#!/bin/bash

# ==========================================
# SOC LAB - ATTACK SIMULATION SCRIPT
# Simulates high-confidence SOC alerts
# Run as root: sudo ./simulate_attack.sh
# ==========================================

AUTH_LOG="/var/log/auth.log"
SYS_LOG="/var/log/syslog"

ATTACKER_IP="192.168.56.50"

echo "[!] Starting attack simulation..."

# ------------------------------------------
# 1. SSH BRUTE FORCE ATTACK
# ------------------------------------------
echo "[!] Simulating SSH brute-force attack..."

for i in {1..10}; do
    echo "$(date) sshd[$RANDOM]: Failed password for root from $ATTACKER_IP port $((RANDOM%65535)) ssh2" >> $AUTH_LOG
done

# ------------------------------------------
# 2. PRIVILEGE ESCALATION ATTEMPT
# ------------------------------------------
echo "[!] Simulating privilege escalation..."

echo "$(date) sudo: hacker : TTY=pts/1 ; PWD=/home/hacker ; USER=root ; COMMAND=/bin/bash" >> $AUTH_LOG

# ------------------------------------------
# 3. FILE TAMPERING (RANSOMWARE-LIKE)
# ------------------------------------------
echo "[!] Simulating file tampering..."

TARGET_DIR="/tmp/target_files"
mkdir -p $TARGET_DIR

# Create files
for i in {1..5}; do
    echo "sensitive data" > $TARGET_DIR/file$i.txt
done

# Rename files (simulate encryption)
for file in $TARGET_DIR/*.txt; do
    mv "$file" "$file.encrypted"
done

echo "$(date) kernel: File modification spike detected in $TARGET_DIR" >> $SYS_LOG

# ------------------------------------------
# 4. SIMULATED COMMAND & CONTROL (C2)
# ------------------------------------------
echo "[!] Simulating outbound C2 communication..."

echo "$(date) bash[$$]: wget http://malicious-c2-server.test/beacon -O /dev/null" >> $SYS_LOG

# ------------------------------------------
# 5. LOG TAMPERING ATTEMPT
# ------------------------------------------
echo "[!] Simulating log tampering..."

echo "$(date) bash[$$]: history -c && unset HISTFILE" >> $SYS_LOG

echo "[!] Attack simulation complete."
