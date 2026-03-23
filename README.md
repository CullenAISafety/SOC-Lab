# SOC Lab - Security Operations Center Lab Environment

## Overview
This SOC Lab is a ready-to-run, plug-and-play Security Operations Center environment designed for cybersecurity learning, threat hunting, and incident response practice. It simulates a multi-VM network environment with:

- **Windows 10 endpoint**  
- **Linux (Ubuntu) server**  
- **Attack VM (Kali Linux)**  
- **SIEM VM (ELK Stack or Wazuh)**  

The lab allows you to:

- Generate and collect Windows/Linux logs
- Simulate attacks and malicious activity
- Detect suspicious behavior using a SIEM
- Practice SOC workflows, alert investigation, and incident response

---

## Lab Architecture
[Windows 10 VM] ----+
|
[Ubuntu Server VM] --+---- [SIEM VM (ELK/Wazuh)]
|
[Attack VM (Kali)] -+

- All VMs are connected via **host-only networking** to isolate lab traffic.
- Windows/Linux VMs generate normal and suspicious logs.
- Attack VM generates network-based events.
- SIEM VM collects, parses, and visualizes logs and generates alerts.

---

## Folder Structure

SOC-Lab/
├── README.md
├── VMs/
│ ├── Windows10/
│ │ └── scripts/
│ │ ├── generate_logs.ps1
│ │ └── simulate_attack.ps1
│ ├── LinuxUbuntu/
│ │ └── scripts/
│ │ ├── generate_logs.sh
│ │ └── simulate_attack.sh
│ └── AttackVM/
│ └── tools/
│ └── nmap_scan.sh
├── SIEM/
│ ├── ELK/
│ │ ├── docker-compose.yml
│ │ ├── logstash.conf
│ │ └── kibana_dashboards/
│ └── wazuh/
│ ├── wazuh-docker-compose.yml
│ └── rules/
├── network/
│ └── lab_topology.drawio
├── alerts/
│ ├── windows_alerts.json
│ ├── linux_alerts.json
│ └── network_alerts.json
└── docs/
├── LabSetupGuide.md
├── SOC_Exercises.md
└── ReferenceTools.md

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/SOC-Lab.git
cd SOC-Lab

2. Provision VMs
Use VirtualBox or VMware Workstation.
Configure VMs according to the VM Configuration in this repo:
Windows 10 VM: 4GB RAM, 2 CPU cores, host-only network
Ubuntu Server VM: 2GB RAM, 1 CPU core, host-only network
Attack VM (Kali Linux): 2GB RAM, 1 CPU core, host-only network
SIEM VM: 4GB RAM, 2 CPU cores, host-only network
3. SIEM Configuration
ELK Stack:
Use docker-compose.yml to deploy Elasticsearch, Logstash, and Kibana
Configure logstash.conf to collect Windows and Linux logs
Wazuh:
Use wazuh-docker-compose.yml
Install agents on Windows and Linux VMs
Load rules from rules/ folder
4. Run Log Generation Scripts
Windows: scripts\generate_logs.ps1
Linux: scripts/generate_logs.sh
Attack VM: tools/nmap_scan.sh
5. View Logs & Alerts
Access Kibana or Wazuh dashboard on SIEM VM
Check alerts/ folder for sample alert templates
Verify detection of suspicious activity from Windows/Linux VMs and Attack VM
SOC Exercises
Monitor login events, file changes, and network activity
Detect brute-force attacks and suspicious processes
Investigate network scans from Attack VM
Document findings in docs/SOC_Exercises.md
Reference Tools
Sysinternals Suite (Windows monitoring)
Wireshark / tcpdump (network monitoring)
Velociraptor (endpoint visibility)
Nmap / Metasploit (attack simulation)
Notes
All simulated attacks are safe and lab-contained
Network is isolated from the host internet
Designed for learning SOC operations and incident response

License

All rights reserved. No institution or organization was effected. 
