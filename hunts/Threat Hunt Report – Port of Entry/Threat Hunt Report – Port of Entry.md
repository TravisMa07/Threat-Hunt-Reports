# Threat Hunt Report – Port of Entry

---

## Executive Summary

Competitor undercut long-term shipping contract by exactly 3%. Threat intelligence gather that the supplier contracts and pricing data appeared on underground forums. It was identified that between November 19-20, 2025, a threat actor gained unauthorized access to an IT admin workstation (AZUKI-SL) from the company Azuki Import/Export Trading Co.

The attacker was able to leverage stolen credentials to authenticate via RDP gaining inital access. After gaining inital access, the attacker conducted network reconnaisance and established a malware staging directory for payload deployment and defense evasion. Persistence was achieved via scheduled tasks while outbound encrypted C2 traffic was observed. Credential theft was executed to harvest authentication artifacts, followed by data staging, exfilitration, and anti-forensic log tampering. Finally, lateral movement was attempted toward an additional internal host and a persistence account was provisioned. 

The following report outlines the cyber kill chain, mapping it to MITRE ATT&CK, timeline, indicators, recommendations, and lesson learned.

---

## Scope & Environment

- **Environment:** Windows Endpoint on Azuki Import/Export Trading Co. Network
- **Data Sources:** DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceEvents
- **Timeframe:** 11/19/2025 - 11/20/2025

---

## Table of Contents

- [MITRE ATT&CK Summary](#mitre-attck-summary)
- [Analysis](#analysis)
  - [Flag 1](#flag-1)
  - [Flag 2](#flag-2)
  - [Flag 3](#flag-3)
  - [Flag 4](#flag-4)
  - [Flag 5](#flag-5)
  - [Flag 6](#flag-6)
  - [Flag 7](#flag-7)
  - [Flag 8](#flag-8)
  - [Flag 9](#flag-9)
  - [Flag 10](#flag-10)
  - [Flag 11](#flag-11)
  - [Flag 12](#flag-12)
  - [Flag 13](#flag-13)
  - [Flag 14](#flag-14)
  - [Flag 15](#flag-15)
  - [Flag 16](#flag-16)
  - [Flag 17](#flag-17)
  - [Flag 18](#flag-18)
  - [Flag 19](#flag-19)
  - [Flag 20](#flag-20)
- [Detection Gaps & Recommendations](#detection-gaps--recommendations)
- [Final Assessment](#final-assessment)
- [Analyst Notes](#analyst-notes)

---


## MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Tactic |
|-----:|-------------------|----------|----------|
| 1 | Remote Services (Remote Desktop Protocol) | T1021.001 | Initial Access |
| 2 | Valid Accounts | T1078 | Initial Access |
| 3 | System Network Configuration Discovery | T1016 | Discovery |
| 4 | Data Staged: Local Data Staging | T1074.001 | Collection |
| 5 | Impair Defenses: Disable or Modify Tools | T1562.001 | Defense Evasion |
| 6 | Impair Defenses: Disable or Modify Tools | T1562.001 | Defense Evasion |
| 7 | Impair Defenses: Disable or Modify Tools | T1562.001 | Defense Evasion |
| 8 | Scheduled Task/Job: Scheduled Task | T1053.005 | Persistence |
| 9 | Scheduled Task/Job: Scheduled Task | T1053.005 | Persistence |
| 10 | Application Layer Protocol: Web Protocols | T1071.001 | Command and Control |
| 11 | Application Layer Protocol: Web Protocols | T1071.001 | Command and Control |
| 12 | OS Credential Dumping: LSASS Memory | T1003.001 | Credential Access |
| 12 | OS Credential Dumping: LSASS Memory | T1003.001 | Credential Access |
| 14 | Archive Collected Data: Archive via Utility | T1560.001 | Collection |
| 15 | Exfiltration Over Web Service | T1567 | Exfiltration |
| 16 | Indicator Removal: Clear Windows Event Logs | T1070.001 | Defense Evasion |
| 17 | Create Account: Local Account | T1136.001 | Persistence |
| 18 | Command and Scripting Interpreter: PowerShell | T1059.001 | Execution |
| 19 | Use Alternate Authentication Material | T1550 | Lateral Movement |
| 20 | Remote Services: Remote Desktop Protocol | T1021.001 | Lateral Movement |

---

## Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="flag-1"><strong>Flag 1: INITIAL ACCESS - Remote Access Source</strong></summary>

### Objective
Identifying inital access point of the adversary via Remote Desktop Protocol (RDP) connection.

### Finding
Unauthorize logon via RDP from source IP address `88.97.178.12`.

### KQL Query
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| where isnotempty(RemoteIP)
| project TimeGenerated, AccountDomain, AccountName, ActionType, DeviceName, LogonType, Protocol, RemoteIP
```

### Evidence
<img width="608" height="97" alt="image" src="https://github.com/user-attachments/assets/ccabb9fd-a1be-45dd-af22-2d21ce152060" />


### Why it Matters
RDP connections leave network traces that identify the source of the unauthorized access and the device compromised. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

</details>

---

<details>
<summary id="flag-2"><strong>Flag 2: INITIAL ACCESS - Compromised User Account</strong></summary>

### Objective
Identify the credentials and account that was compromised.

### Finding
The account that was compromised during inital access is `kenji.sato`.

### KQL Query
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteIP == "88.97.178.12"
| order by TimeGenerated asc
```

### Evidence
<img width="608" height="97" alt="image" src="https://github.com/user-attachments/assets/ccabb9fd-a1be-45dd-af22-2d21ce152060" />

### Why it Matters
The compromised account/credentials has been found and the scope of the unauthorized access can further help guide the remediation efforts including password resets and privilege reviews.

</details>

---
<details>
<summary id="flag-3"><strong>Flag 3: DISCOVERY - Network Reconnaissance</strong></summary>

### Objective
After threat actor gain access to the compromised account, the objective is to find any potential sign of lateral movement opportunities taken by the adversary via reconnaissance.

### Finding
While searching the DeviceProcessEvents logs, `ARP.EXE -a` was ran for network enumeration by the compromised account.

### KQL Query
```kql
DeviceProcessEvents 
| where TimeGenerated >= todatetime('2025-11-19T00:57:13.0087357Z') 
| where AccountName == "kenji.sato" 
| project TimeGenerated, AccountName, ProcessCommandLine
| where ProcessCommandLine contains "arp"
```

### Evidence
<img width="494" height="135" alt="image" src="https://github.com/user-attachments/assets/10d47935-3509-4bdc-a409-44753d96792c" />


### Why it Matters
Attackers enumerate network topology to identify other computers, devices, and the associated MAC addresses nearby. By doing this, attackers conduct discovery to identify any lateral movement opportunities and high-value targets. This is also a key indicator of the start of an advanced persistent threats (APT).

</details>

---
<details>
<summary id="flag-4"><strong>Flag 4: DEFENCE EVASION - Malware Staging Directory<Technique Name></strong></summary>

### Objective
Identifying the primary staging location where the threat actor is organizing their tools, executables, and stolen data. 

### Finding
While searching the DeviceProcessEvents log for the creation of directories, `"attrib.exe" +h +s C:\ProgramData\WindowsCache` was ran. The command contains `attrib.exe`, which is a tool used to view and modify file and folder attributes. The directory `C:\ProgramData\WindowsCache` was created with the purpose to hide it (+h), label it as system critical (+s), and use it throughout the attack for multiple malicious tasks.

### KQL Query
```kql
DeviceProcessEvents 
| where TimeGenerated >= todatetime('2025-11-19T00:57:13.0087357Z') 
| where AccountName == "kenji.sato" 
| where ProcessCommandLine contains "attrib"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
```

### Evidence
<img width="514" height="71" alt="image" src="https://github.com/user-attachments/assets/fce2c51c-1d68-48d7-b03b-fa0235d003e6" />


### Why it Matters
Threat actors generate lots of temporary folders during an intrusion, but typically only one folder is used as their main working area. The primary staging directory is the folder that they intentionally create, hide, and use throughout an attack to store malware, stolen data, tools, C2, and many more malicious activites. 

</details>

---
<details>
<summary id="flag-5"><strong>Flag 5: DEFENCE EVASION - File Extension Exclusions</strong></summary>

### Objective
After inital access and beginning to stage their attack, attackers implement multiple defence evasion methodology. One of the method is for attackers to add file extension exclusions to Windows Defender to prevent scanning of malicious activites. 

### Finding
While searching the DeviceRegistryEvents logs, `3 file extension exclusion` can be found via modification/setting registry values at `"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"`. These file extension exclusions are `.exe`, `.ps1`, `.bat`.

### KQL Query
```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey contains @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
| where DeviceName contains "azuki"
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName
```

### Evidence
<img width="515" height="47" alt="image" src="https://github.com/user-attachments/assets/e6a86c86-1280-42e0-9e65-5b591bd171b8" />


### Why it Matters
Attackers are modifying Windows Defender exclusions so defender does not scan for certain file extensions during their AV scan. IF defender ignores those extensions, malware with those file types can be run freely.

</details>

---
<details>
<summary id="flag-6"><strong>Flag 6: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query
<KQL query use>

### Evidence
<screenshot of logs>

### Why it Matters
<impact of the attack and its context with defender relevance>

</details>

---
<details>
<summary id="flag-7"><strong>Flag 7: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query
<KQL query use>

### Evidence
<screenshot of logs>

### Why it Matters
<impact of the attack and its context with defender relevance>

</details>

---
<details>
<summary id="flag-8"><strong>Flag 8: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query
<KQL query use>

### Evidence
<screenshot of logs>

### Why it Matters
<impact of the attack and its context with defender relevance>

</details>

---
<details>
<summary id="flag-9"><strong>Flag 9: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query
<KQL query use>

### Evidence
<screenshot of logs>

### Why it Matters
<impact of the attack and its context with defender relevance>

</details>

---
<details>
<summary id="flag-10"><strong>Flag 10: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query
<KQL query use>

### Evidence
<screenshot of logs>

### Why it Matters
<impact of the attack and its context with defender relevance>

</details>

---
<details>
<summary id="flag-11"><strong>Flag 11: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query
<KQL query use>

### Evidence
<screenshot of logs>

### Why it Matters
<impact of the attack and its context with defender relevance>

</details>

---
<details>
<summary id="flag-12"><strong>Flag 12: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query
<KQL query use>

### Evidence
<screenshot of logs>

### Why it Matters
<impact of the attack and its context with defender relevance>

</details>

---
<details>
<summary id="flag-13"><strong>Flag 13: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query
<KQL query use>

### Evidence
<screenshot of logs>

### Why it Matters
<impact of the attack and its context with defender relevance>

</details>

---
<details>
<summary id="flag-14"><strong>Flag 14: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query
<KQL query use>

### Evidence
<screenshot of logs>

### Why it Matters
<impact of the attack and its context with defender relevance>

</details>

---
<details>
<summary id="flag-15"><strong>Flag 15: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query
<KQL query use>

### Evidence
<screenshot of logs>

### Why it Matters
<impact of the attack and its context with defender relevance>

</details>

---
<details>
<summary id="flag-16"><strong>Flag 16: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query
<KQL query use>

### Evidence
<screenshot of logs>

### Why it Matters
<impact of the attack and its context with defender relevance>

</details>

---
<details>
<summary id="flag-17"><strong>Flag 17: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query
<KQL query use>

### Evidence
<screenshot of logs>

### Why it Matters
<impact of the attack and its context with defender relevance>

</details>

---
<details>
<summary id="flag-18"><strong>Flag 18: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query
<KQL query use>

### Evidence
<screenshot of logs>

### Why it Matters
<impact of the attack and its context with defender relevance>

</details>

---
<details>
<summary id="flag-19"><strong>Flag 19: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query
<KQL query use>

### Evidence
<screenshot of logs>

### Why it Matters
<impact of the attack and its context with defender relevance>

</details>

---
<details>
<summary id="flag-20"><strong>Flag 20: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query
<KQL query use>

### Evidence
<screenshot of logs>

### Why it Matters
<impact of the attack and its context with defender relevance>

</details>

---

---

## Detection Gaps & Recommendations

### Observed Gaps
- <Placeholder>
- <Placeholder>
- <Placeholder>

### Recommendations
- <Placeholder>
- <Placeholder>
- <Placeholder>

---

## Final Assessment

<Concise executive-style conclusion summarizing risk, attacker sophistication, and defensive posture.>

---

## Analyst Notes

- Report structured for interview and portfolio review  
- Evidence reproducible via advanced hunting  
- Techniques mapped directly to MITRE ATT&CK  

---
