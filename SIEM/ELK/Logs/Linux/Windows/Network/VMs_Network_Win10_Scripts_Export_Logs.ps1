# ==========================================
# SOC LAB - WINDOWS LOG EXPORT
# Exports event logs to shared SOC folder
# ==========================================

$destination = "Z:\windows"

Write-Host "[+] Exporting Windows logs..."

New-Item -ItemType Directory -Path $destination -Force

# Export Security logs
wevtutil epl Security "$destination\Security.evtx"

Write-Host "[+] Logs exported to $destination"
