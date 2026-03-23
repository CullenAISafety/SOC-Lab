#!/bin/bash

# ==========================================
# SOC LAB - LINUX LOG EXPORT SCRIPT
# Copies logs to shared SOC directory
# ==========================================

DESTINATION="/mnt/soc-logs/linux"

echo "[+] Exporting Linux logs to SOC directory..."

# Create destination if it doesn't exist
mkdir -p $DESTINATION

# Copy logs
cp /var/log/auth.log $DESTINATION/auth.log
cp /var/log/syslog $DESTINATION/syslog.log

echo "[+] Logs exported to $DESTINATION"
