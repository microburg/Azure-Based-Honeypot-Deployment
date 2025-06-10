# Azure-Based Honeypot Deployment

## 📌 Project Overview
This project involved deploying a cloud-based honeypot using Microsoft Azure to simulate a vulnerable environment for observing and analyzing cyberattack behaviors. It focused on collecting real-time threat intelligence, detecting brute-force attempts, and visualizing attack patterns using Microsoft Sentinel and Log Analytics.

---

## 🎯 Objectives
Deploy a high-interaction honeypot to attract and monitor cyber threats.
Collect and analyze logs from the honeypot system.
Detect malicious activity using KQL queries in Microsoft Sentinel.
Build dashboards for visualizing attack trends and indicators of compromise (IOCs).

---

## 🏗️ Architecture & Tools Used
Azure Resources
Virtual Machine: Windows 10 Pro VM (B-series size)
Virtual Network (VNet): Custom virtual network with internet access
Network Security Group (NSG): All inbound and outbound ports allowed (intentionally misconfigured to attract attacks)
Log Analytics Workspace: For centralized logging and data ingestion
Microsoft Sentinel: SIEM solution connected to the workspace for analysis, rule creation, and visualization

---

## 🔧 Setup Steps
### VM Deployment
- Deployed a Windows 10 VM from Azure Marketplace.
- Assigned a public IP to allow unrestricted internet access.


### Networking
- Created a dedicated Virtual Network and Subnet.
- Associated a custom Network Security Group (NSG) with rules (Any protocol, any port, any source):
  - Inbound: Allow All 
  - Outbound: Allow All


### Honeypot Configuration
- Windows Firewall Disabled: To remove local defense mechanisms and allow unrestricted access.


### Log Analytics & Sentinel
- Created a Log Analytics Workspace and connected the VM.
- Enabled data collection for:
  - Security events
  - Audit logs
  - Network traffic
- Integrated Microsoft Sentinel with the workspace.
- Enabled default analytics rules and created custom KQL queries for brute-force detection.

---

## 🧪 Threat Detection & Analysis

### KQL Query Used:
```kql
SecurityEvent
| where Task == 12544
| where EventID in (4624, 4625, 4768, 4769, 4776)
| extend LoginStatus = iff(EventID == 4624 or EventID == 4769 or EventID == 4776, "Success", "Failure")
| summarize
    TotalAttempts = count(),
    SuccessfulLogins = countif(LoginStatus == "Success"),
    FailedLogins = countif(LoginStatus == "Failure"),
    UniqueAccountsAttempted = dcount(Account),
    AccountsAttempted = make_set(Account),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IP = IpAddress
| extend SuccessRate = todouble(SuccessfulLogins) / todouble(TotalAttempts) * 100
| project
    IP,
    TotalAttempts,
    SuccessfulLogins,
    FailedLogins,
    SuccessRate = round(SuccessRate, 2),
    UniqueAccountsAttempted,
    AccountsAttempted,
    FirstAttempt,
    LastAttempt
| sort by TotalAttempts desc
```
### MITRE ATT&CK Mapping
- Techniques Detected:
  - T1110 - Brute Force
  - T1078 - Valid Accounts
  - T1133 - External Remote Services
---

## 📊 Dashboards Built
- Top Attacking IPs
- Failed Login Attempts Over Time

---

## 📈 Results
- Detected frequent brute-force login attempts from international IPs.
- Identified trends in attacker behavior, including:
  - Time-of-day attack patterns
  - Preferred usernames (e.g., admin, test, adminstartor)

---

## 📝 Conclusion
This honeypot project successfully demonstrated how to deploy a vulnerable Azure environment, monitor real-world cyberattacks, and extract valuable threat intelligence using Microsoft Sentinel. It strengthened practical skills in cloud security monitoring, incident analysis, and SIEM operations.
