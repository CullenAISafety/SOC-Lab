#!/bin/bash

# ==========================================
# SOC LAB - NMAP SCAN SCRIPT
# Simulates attacker reconnaissance activity
# Output logs can be ingested into SIEM
# ==========================================

# Targets (edit to match your lab IPs)
TARGETS=("192.168.56.101" "192.168.56.102")

# Output directory
OUTPUT_DIR="./scan_logs"
mkdir -p $OUTPUT_DIR

TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

echo "[+] Starting Nmap reconnaissance at $TIMESTAMP"

# ------------------------------------------
# 1. HOST DISCOVERY (Ping Sweep)
# ------------------------------------------
echo "[+] Running host discovery..."
nmap -sn 192.168.56.0/24 -oN $OUTPUT_DIR/host_discovery_$TIMESTAMP.txt

# ------------------------------------------
# 2. TCP SYN SCAN (Stealth Scan)
# ------------------------------------------
echo "[+] Running SYN scan on targets..."
for TARGET in "${TARGETS[@]}"; do
    nmap -sS -Pn -T4 $TARGET -oN $OUTPUT_DIR/syn_scan_${TARGET}_$TIMESTAMP.txt
done

# ------------------------------------------
# 3. SERVICE & VERSION DETECTION
# ------------------------------------------
echo "[+] Running service/version detection..."
for TARGET in "${TARGETS[@]}"; do
    nmap -sV -Pn $TARGET -oN $OUTPUT_DIR/service_scan_${TARGET}_$TIMESTAMP.txt
done

# ------------------------------------------
# 4. COMMON PORT SCAN (Focused)
# ------------------------------------------
COMMON_PORTS="22,21,80,443,3389"
echo "[+] Scanning common ports: $COMMON_PORTS"
for TARGET in "${TARGETS[@]}"; do
    nmap -p $COMMON_PORTS -Pn $TARGET -oN $OUTPUT_DIR/common_ports_${TARGET}_$TIMESTAMP.txt
done

# ------------------------------------------
# 5. AGGRESSIVE SCAN (HIGH SIGNAL)
# ------------------------------------------
echo "[!] Running aggressive scan (high alert likelihood)..."
for TARGET in "${TARGETS[@]}"; do
    nmap -A -Pn $TARGET -oN $OUTPUT_DIR/aggressive_${TARGET}_$TIMESTAMP.txt
done

echo "[+] All scans completed."
echo "[+] Results saved in $OUTPUT_DIR/"
