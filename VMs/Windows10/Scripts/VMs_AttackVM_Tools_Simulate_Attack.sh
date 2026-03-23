#!/bin/bash
# Simulate attack-like behavior for SOC lab
# Safe and lab-contained

# Generate ICMP flood (local lab only)
TARGETS=("192.168.56.101" "192.168.56.102")
for TARGET in "${TARGETS[@]}"; do
  ping -c 5 $TARGET > /dev/null
done

# Generate port scan logs
for TARGET in "${TARGETS[@]}"; do
  nmap -Pn -p 22,80,443 $TARGET >> attack_scan_results.txt
done
