# Simulate a brute-force login attempt
# Warning: Safe simulation using event logs only

$ip = "192.168.56.10"
for ($i=1; $i -le 5; $i++) {
    Write-EventLog -LogName Security -Source "Microsoft-Windows-Security-Auditing" -EntryType FailureAudit -EventId 4625 -Message "Failed login attempt from $ip"
}

# Simulate ransomware-like file rename (safe)
$folder = "$env:USERPROFILE\Documents\TestFiles"
New-Item -ItemType Directory -Path $folder -Force
1..5 | ForEach-Object { New-Item -Path "$folder\file$_.txt" -ItemType File }
Get-ChildItem $folder | Rename-Item -NewName { "encrypted_$($_.Name)" }
