# Generate normal and suspicious Windows logs
# Run as Administrator

# Normal user login events
for ($i=0; $i -lt 5; $i++) {
    Write-EventLog -LogName Security -Source "Microsoft-Windows-Security-Auditing" -EntryType Information -EventId 4624 -Message "User login simulated"
}

# Normal process creation events
for ($i=0; $i -lt 3; $i++) {
    Write-EventLog -LogName Security -Source "Microsoft-Windows-Security-Auditing" -EntryType Information -EventId 4688 -Message "Process created: notepad.exe"
}

# Suspicious process (simulated malware)
Write-EventLog -LogName Security -Source "Microsoft-Windows-Security-Auditing" -EntryType Warning -EventId 4688 -Message "Suspicious process creation: powershell.exe -Command 'Invoke-WebRequest http://malicious.test'"
