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
<summary id="flag-6"><strong>Flag 6: DEFENCE EVASION - Temporary Folder Exclusion<Technique Name></strong></summary>

### Objective
After inital access and beginning to stage their attack, attackers implement multiple defence evasion methodology. Attackers add folder path exclusions to Windows Defender to prevent scanning of directories.

### Finding
While searching DeviceRegistryEvents logs, temporary folders/directories can be found excluded in the registry path `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Path`. These temporary folder path exclusions are `C:\Users\KENJI~1.SAT\AppData\Local\Temp`.

### KQL Query
```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey contains @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Path"
| where DeviceName contains "azuki"
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName
```

### Evidence
<img width="509" height="80" alt="image" src="https://github.com/user-attachments/assets/40b0407f-1388-43bc-8e95-16a190ea17aa" />

### Why it Matters
Windows Defender typically scans files inside temporary folders which is bad for attackers due to malware often getting downloaded or unpacked in temporary folders. The attackers add a folder exclusion for temporary folder thus making it a perfect hiding spot of malware, scripts, tools, exfilitration, etc.

</details>

---
<details>
<summary id="flag-7"><strong>Flag 7: DEFENCE EVASION - Download Utility Abuse</strong></summary>

### Objective
Identify the attacker tool use to download files.

### Finding
The threat actor leveraged `certutil.exe` to download malware into the staging directory. Certutil is a native Windows binary capable of performing downloads and is a common LOLBIN.

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "http" and ProcessCommandLine contains "WindowsCache"
| project TimeGenerated, AccountName, DeviceName, ActionType, FileName, ProcessCommandLine
```

### Evidence
<img width="901" height="193" alt="image" src="https://github.com/user-attachments/assets/73864799-bc34-4e7c-80eb-a4751210aaaa" />


### Why it Matters
LOLBIN abuse allows attackers to download payloads without introducing obvious tooling into the environment that may be detected by the organization defensive measures. Certutil misuse is commonly associated with post-compromise staging for credential dumping or C2 implants.

</details>

---
<details>
<summary id="flag-8"><strong>Flag 8: PERSISTENCE - Scheduled Task Name</strong></summary>

### Objective
Detect persistence mechanisms that allow malware to consistently execute after reboot or on time-based triggers.

### Finding
Threat actor created a schedulded task named `Windows Update Check` to achieve persistence, blending in with real Windows maintenance processes.

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "schtasks.exe"
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```

### Evidence
<img width="902" height="142" alt="image" src="https://github.com/user-attachments/assets/f3af6341-3464-49b5-ab55-30abb254fc08" />

### Why it Matters
Schedulded tasks are a low-noise persistence mehanism that blend easily with routine administrative operations. The naming choice suggests the attackers inteded to avoid analyst detection and align with Windows update processes.

</details>

---
<details>
<summary id="flag-9"><strong>Flag 9: PERSISTENCE - Scheduled Task Target</strong></summary>

### Objective
Identify the malware artifact executed by the persistence mechanism.

### Finding
The schedulded task was configured to execute `C:\ProgramData\WindowsCache\svchost.exe`, aligning with the established malware staging directory.

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "schtasks.exe"
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```

### Evidence
<img width="902" height="142" alt="image" src="https://github.com/user-attachments/assets/f3af6341-3464-49b5-ab55-30abb254fc08" />

### Why it Matters
Linknig persistence directly to an executable inside the hidden staging directory confirms operational use of that directory and connects the evasion, staging, and persistence phases into a cohesive cyber kill-chain narrative.

</details>

---
<details>
<summary id="flag-10"><strong>Flag 10: COMMAND & CONTROL - C2 Server Address</strong></summary>

### Objective
Identify outbound connections supporting post-exploitation command and control.

### Finding
Outbound connections were observed to `78.141.196.6` over HTTPS (TCP/443), indicative of encrypted C2 traffic.

### KQL Query
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki"
| where InitiatingProcessCommandLine contains "svchost.exe"
| where InitiatingProcessFolderPath contains @"C:\ProgramData\WindowsCache\svchost.exe"
```

### Evidence
<img width="900" height="73" alt="image" src="https://github.com/user-attachments/assets/b32f8ed4-7bf2-4b37-b97a-17c1fca135df" />

### Why it Matters
Encrypted web protocols signifcantly reduce detection visibility and logistics. Identifying C2 infrastructure supports threat attribution, blocking, and external reporting.

</details>

---
<details>
<summary id="flag-11"><strong>Flag 11: COMMAND & CONTROL - C2 Communication Port</strong></summary>

### Objective
Determine the protocol and port used to tunnel C2 traffic.

### Finding
The remote port used for C2 communication was `443`, indicating HTTPS-based communication

### KQL Query
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki"
| where InitiatingProcessCommandLine contains "svchost.exe"
| where InitiatingProcessFolderPath contains @"C:\ProgramData\WindowsCache\svchost.exe"
```

### Evidence
<img width="900" height="73" alt="image" src="https://github.com/user-attachments/assets/b32f8ed4-7bf2-4b37-b97a-17c1fca135df" />

### Why it Matters
8443, 443, and 4443 are common ports for C2 frameworks disguised as encrypted traffic. This has operational implications for proxy detection, TLS inspection, and firewall telemetry.

</details>

---
<details>
<summary id="flag-12"><strong>Flag 12:  CREDENTIAL ACCESS - Credential Theft Tool</strong></summary>

### Objective
Determine what tooling was leveraged to extract authentication artifacts.

### Finding
Credential dumping was performed using `mm.exe` inside the staging directory, likely a renamed Mimikatz binary.

### KQL Query
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki"
| where InitiatingProcessFolderPath contains @"C:\ProgramData\WindowsCache"
| project TimeGenerated, ActionType, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName
```

### Evidence
<img width="841" height="222" alt="image" src="https://github.com/user-attachments/assets/a6487fd3-3c28-4aef-b1fc-d621f4c7c873" />

### Why it Matters
Renaming offensive tooling is a known signature of evasion techniques. Credential dumping represents a pivot point in the attack, increasing post-compromise access and scope.

</details>

---
<details>
<summary id="flag-13"><strong>Flag 13: CREDENTIAL ACCESS - Memory Extraction Module</strong></summary>

### Objective
Identify what internal module was invoked to extract logon credentials.

### Finding
The attacker executed `sekurlsa::logonpasswords` against LSASS.

### KQL Query
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki"
| where InitiatingProcessFolderPath contains @"C:\ProgramData\WindowsCache"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine ,InitiatingProcessFileName, InitiatingProcessFolderPath, FileName
```

### Evidence
<img width="931" height="157" alt="image" src="https://github.com/user-attachments/assets/4d72fffb-a7c2-4b3f-b67f-6d6fd6c7c0f6" />

### Why it Matters
This action indicates direct credential harvesting and preparation for lateral movement or privilege escalation.

</details>

---
<details>
<summary id="flag-14"><strong>Flag 14: COLLECTION - Data Staging Archive</strong></summary>

### Objective
Determine how the attacker packaged data prior to exfiltration.

### Finding
Stolen data was compressed into `export-data.zip` inside the staging directory.

### KQL Query
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki"
| where FolderPath contains @"C:\ProgramData\WindowsCache"
| where FileName endswith ".zip"
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath
```

### Evidence
<img width="939" height="69" alt="image" src="https://github.com/user-attachments/assets/c6df4c82-84bc-462c-beaf-170ad20de175" />

### Why it Matters
Data archiving indicates a methodical approach to data theft and minimizes transfer size. Compression also obscures file structre from basic content inspection.

</details>

---
<details>
<summary id="flag-15"><strong>Flag 15: EXFILTRATION - Exfiltration Channel</strong></summary>

### Objective
Identify cloud services abused for outbound data exfiltration.

### Finding
Outbound transfer of staged data occured over `Discord`, a common dual-use platform abused for malware C2 and data exfiltration.

### KQL Query
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine contains "WindowsCache"
| where RemotePort == "443"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
```

### Evidence
<img width="936" height="40" alt="image" src="https://github.com/user-attachments/assets/90f751aa-5a45-4f6c-9722-24eda98ba898" />

### Why it Matters
Exfiltration via legitimate SaaS platforms complicates response, blending with normal traffic and often bypassing egress controls.

</details>

---
<details>
<summary id="flag-16"><strong>Flag 16: ANTI-FORENSICS - Log Tampering</strong></summary>

### Objective
Identify attempts to remove foresnic artifacts post-compromise.

### Finding
The attacker cleared the `Security` event log first via `wevtutil.exe`, indicating a conscious effort for destruction of evidence. Other clearing of logs include System and Application logs.

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-11-19T19:09:21.4234133Z')
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "wevtutil.exe"
| order by Timestamp asc
| project TimeGenerated, DeviceName, ActionType, FileName, ProcessCommandLine
```

### Evidence
<img width="934" height="148" alt="image" src="https://github.com/user-attachments/assets/63046711-908a-4126-b982-95c38e15ac3c" />

### Why it Matters
Anti-forensics actions hinder detection, incident reconstruction, and post-breach investigation. This is a sign of APT and elevated attacker maturity.

</details>

---
<details>
<summary id="flag-17"><strong>Flag 17: IMPACT - Persistence Account/strong></summary>

### Objective
Determine whether long-term persistent access was provisioned.

### Finding
A hidden administrator account `support` was created to maintain post-removal access.

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-11-19T19:09:21.4234133Z')
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "/add"
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```

### Evidence
<img width="930" height="107" alt="image" src="https://github.com/user-attachments/assets/cbdcd433-a26b-4b33-858e-d53935cb78c8" />

### Why it Matters
Local administrative accounts create durable footholds with no external dependencies and bypass centralized authentication controls

</details>

---
<details>
<summary id="flag-18"><strong>Flag 18: EXECUTION - Malicious Script</strong></summary>

### Objective
Identify inital scripted execution mechanisms.

### Finding
The attacker executed `wupdate.ps1`, a PowerShell script automating payload download, persistence, and credential dumping.

### KQL Query
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki"
| where FileName endswith ".ps1"
| where FolderPath contains "temp"
| where ActionType == "FileCreated"
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
```

### Evidence
<img width="942" height="63" alt="image" src="https://github.com/user-attachments/assets/c1524ad3-3571-43e4-9bc1-432c919d37b5" />

### Why it Matters
PowerShell provides a rich post-exploitation environment and is heavily abused due to its native execution and administrative capabiltiies.

</details>

---
<details>
<summary id="flag-19"><strong>Flag 19: LATERAL MOVEMENT - Secondary Target</strong></summary>

### Objective
Identify systems the threat actor attempted to pivot into.

### Finding
The attacker targeted `10.1.0.188` for lateral movement, likely a domain-connected internal host.

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-11-19T18:37:41.1147957Z')
| where DeviceName  contains "azuki"
| where ProcessCommandLine contains "cmdkey" or ProcessCommandLine contains "mstsc"
| order by TimeGenerated asc
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

### Evidence
<img width="936" height="240" alt="image" src="https://github.com/user-attachments/assets/0a46a16a-1ee5-4b11-994c-40db5c2602dc" />

### Why it Matters
Lateral movement indicates attackers were exploring privilege expansion or access to additional data sources.

</details>

---
<details>
<summary id="flag-20"><strong>Flag 20: LATERAL MOVEMENT - Remote Access Tool</strong></summary>

### Objective
Determine tooling leveraged for later stages of remote system access.

### Finding
The attacker utilized `mstsc.exe` for lateral movement over RDP.

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-11-19T18:37:41.1147957Z')
| where DeviceName  contains "azuki"
| where ProcessCommandLine contains "10.1.0.188"
| order by TimeGenerated asc
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

### Evidence
<img width="921" height="125" alt="image" src="https://github.com/user-attachments/assets/346ca990-72e1-43dc-9a51-efc462ab4e2a" />

### Why it Matters
Native RDP usage blends with IT administrative baselines, resulting in low detection noise and reduced operational footprint.

</details>

---

---

## Detection Gaps & Recommendations

### Observed Gaps
- Lack of outbound TLS inspection limited visiblity into encrypted C2 and exfiltration traffic
- Defender exclusions were not centrally audited or blocked, enabling AV evasion
- PowerShell execution lacked script block logging for forensic recovery

### Recommendations
- Implement TLS inspection for egress to detect cloud service abuse
- Harden Defender configuration and enforce exclusion approval workflows
- Enable PowerShell Script Block logging + AMSI logging
- Deploy network-level egress filtering to restrict outbound SaasS abuse
- Implement privileged access management to reduce credential reuse exposure

---

## Final Assessment

The intrusion demonstrated a coherent kill chain involving credential theft, encrypted C2, AV evasion, and targeted exfiltration. The attacker exhibited intermediate sophiscation, leveraging LOLBINs, staging directories, schedulded tasks, and anti-forensic techniques. Defensive controls were insufficent in credential handling, AV configuration, and outbound service abuse monitoring. The adversary achieved their operational objective: data theft impacting competitive negotiations.

---
