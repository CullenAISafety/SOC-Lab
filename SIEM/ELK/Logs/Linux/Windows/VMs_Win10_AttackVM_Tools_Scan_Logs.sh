#!/bin/bash

# ==========================================
# SOC LAB - NETWORK LOG EXPORT SCRIPT
# Sends Nmap scan results to SIEM logs folder
# ==========================================

SOURCE_DIR="./scan_logs"
DESTINATION="/mnt/soc-logs/network"

echo "[+] Exporting Nmap scan logs..."

# Create destination if it doesn't exist
mkdir -p $DESTINATION

# Copy all scan results
cp $SOURCE_DIR/*.txt $DESTINATION/ 2>/dev/null

echo "[+] Network logs exported to $DESTINATION"
