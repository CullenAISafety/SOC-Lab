# SOC Exercises

This document contains hands-on exercises for Security Operations Center (SOC) training. Each exercise is designed to build skills in threat detection, investigation, and response.

---

## 1. Windows Event Monitoring

**Objective:** Detect suspicious activities on Windows hosts.  

**Exercise Steps:**
1. Open `windows_alerts.json`.
2. Identify alerts with severity **High**.
3. Investigate PowerShell scripts flagged in alerts.
4. Document the IOC (Indicators of Compromise) and recommend mitigation.

**Expected Outcome:**  
- Understand how to interpret Windows logs.  
- Recognize malware and brute force attack patterns.

---

## 2. Linux Threat Hunting

**Objective:** Monitor Linux servers for anomalies.  

**Exercise Steps:**
1. Open `linux_alerts.json`.
2. Look for privilege escalation or suspicious processes.
3. Check which users triggered alerts.
4. Create a report highlighting potential intrusions.

**Expected Outcome:**  
- Gain familiarity with Linux security monitoring.  
- Identify suspicious commands and processes.

---

## 3. Network Traffic Analysis

**Objective:** Detect network-based attacks.  

**Exercise Steps:**
1. Open `network_alerts.json`.
2. Identify patterns such as DDoS, port scanning, or data exfiltration.
3. Correlate source and destination IPs with alert types.
4. Recommend firewall or IDS/IPS rules to mitigate threats.

**Expected Outcome:**  
- Learn to analyze network traffic alerts.  
- Understand common attack vectors on the network.

---

## 4. Incident Response Drill

**Objective:** Conduct a full investigation and remediation.  

**Exercise Steps:**
1. Select an alert from any of the JSON files.
2. Perform log analysis to trace the attack path.
3. Contain the affected system (real or simulated).
4. Document your findings in an incident report.

**Expected Outcome:**  
- Hands-on experience with SOC workflows.  
- Produce a concise incident response report.

---

## 5. Continuous Monitoring Practice

**Objective:** Build skills for automated alert handling.  

**Exercise Steps:**
1. Set up a Python or PowerShell script to parse alert JSON files.
2. Filter and categorize alerts by severity and type.
3. Generate summary reports for SOC analysts.
4. Optionally, simulate sending alerts to Slack or Teams.

**Expected Outcome:**  
- Practice automation of SOC alert triage.  
- Develop basic scripting for monitoring and reporting.
