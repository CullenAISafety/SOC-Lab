#!/bin/bash
# Safe network scan simulation
# Target IPs: Windows and Linux VMs

TARGETS=("192.168.56.101" "192.168.56.102")

for TARGET in "${TARGETS[@]}"; do
  echo "Scanning $TARGET..."
  nmap -Pn -sS -T4 $TARGET >> scan_results.txt
done
echo "Scan complete. Results saved in scan_results.txt"
