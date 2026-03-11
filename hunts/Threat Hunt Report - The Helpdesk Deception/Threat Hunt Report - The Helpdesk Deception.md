# Threat Hunt Report – The Helpdesk Deception

---

## Executive Summary

During the first half of October 2025, multiple intern-operated machines began spawning processes originating from their Downloads directories containing suspicious keywords such as “support,” “help,” and “tool.” Investigation identified the host gab-intern-vm as the most anomalous system exhibiting a chain of suspicious activity disguised as a support troubleshooting session.

Telemetry revealed the execution of a PowerShell support tool followed by a series of reconnaissance actions including clipboard inspection, session discovery, privilege enumeration, and runtime process inventory. The activity progressed into connectivity validation, artifact staging, simulated outbound data transfer attempts, and persistence creation through scheduled tasks and autorun registry entries.

The final stage of the activity involved planting a support chat log artifact, likely intended to justify the suspicious actions as legitimate IT assistance. The sequence of events indicates a deliberately staged narrative designed to mask reconnaissance and persistence mechanisms, highlighting the importance of correlating process behavior, network telemetry, and artifact timing rather than trusting contextual explanations.

---

## Scope & Environment

- **Environment:** Windows Endpoint – Intern Workstation
- **Device Investigated:** gab-intern-vm
- **Data Sources:** DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents
- **Timeframe:** 2025-10-01 → 2025-10-15

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
- [Detection Gaps & Recommendations](#detection-gaps--recommendations)
- [Final Assessment](#final-assessment)

---

## MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Tactic |
|-----:|-------------------|----------|----------|
| 1 | Command and Scripting Interpreter: PowerShell | T1059.001 | Execution |
| 2 | Impair Defenses | T1562 | Defense Evasion |
| 3 | Clipboard Data | T1115 | Collection |
| 4 | Remote System Discovery | T1018 | Discovery |
| 5 | System Information Discovery | T1082 | Discovery |
| 6 | Network Service Discovery | T1046 | Discovery |
| 7 | System Owner/User Discovery | T1033 | Discovery |
| 8 | Process Discovery | T1057 | Discovery |
| 9 | Account Discovery | T1087 | Discovery |
| 10 | Application Layer Protocol: Web Protocols | T1071.001 | Command and Control |
| 11 | Data Staged: Local Data Staging | T1074.001 | Collection |
| 12 | Exfiltration Over Web Service: Exfiltration Over Webhook | T1567.004 | Exfiltration |
| 13 | Scheduled Task/Job: Scheduled Task | T1053.005 | Persistence |
| 14 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 |  Persistence |
| 15 | Masquerading | T1036 | Defense Evasion |

---

## Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="flag-1"><strong>Flag 1: INITIAL EXECUTION – Suspicious PowerShell Tool</strong></summary>

### Objective
Identify the earliest execution event associated with the suspicious support tool.

### Finding
Execution telemetry revealed a PowerShell command invoking a script with the parameter: "-ExecutionPolicy". This parameter allows scripts to run while bypassing normal PowerShell execution policy restrictions.

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| order by TimeGenerated asc
| project ProcessCommandLine
```

### Why it matters
Attackers frequently abuse PowerShell execution policy bypass flags to execute scripts without administrator approval. This activity represents the initial suspicious execution event anchoring the investigation timeline.

</details>

---

<details>
<summary id="flag-2"><strong>Flag 2: DEFENSE EVASION – Defender Tamper Artifact</strong></summary>

### Objective
Identify artifacts suggesting attempts to tamper with security tooling.

### Finding
A file named: "DefenderTamperArtifact.lnk" was manually accessed on the host.

### KQL Query
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where FileName contains "tamper"
```

### Why it matters
Even if no actual security configuration changes occur, artifacts referencing defender tampering may indicate intent to disable security controls or simulate tampering behavior.

</details>

---

<details>
<summary id="flag-3"><strong>Flag 3: COLLECTION – Clipboard Data Probe</strong></summary>

### Objective
Detect attempts to quickly access user data stored in volatile memory sources.

### Finding
The following PowerShell command was executed: "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "clip"
| project ProcessCommandLine
```

### Why it matters
Clipboard harvesting is often used to quickly retrieve sensitive data such as passwords, tokens, or copied confidential information.

</details>

---

<details>
<summary id="flag-4"><strong>Flag 4: DISCOVERY – Host Session Reconnaissance</strong></summary>

### Objective
Identify reconnaissance actions targeting host session context.

### Finding
The command "qwinsta" was executed to enumerate active Remote Desktop sessions. Last Recnom Timestamp: "2025-10-09T12:51:44.3425653Z"

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "qwi"
| order by TimeGenerated desc
| project TimeGenerated, ProcessCommandLine
```

### Why it matters
Session enumeration reveals active user sessions and login contexts, which attackers can leverage to determine when to execute malicious activity.

</details>

---

<details>
<summary id="flag-5"><strong>Flag 5: DISCOVERY – Storage Surface Mapping</strong></summary>

### Objective
Identify enumeration of storage volumes.

### Finding
The following command was executed: "cmd.exe /c wmic logicaldisk get name,freespace,size"

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "wmic"
| order by TimeGenerated desc
```

### Why it matters
Disk enumeration allows attackers to determine available storage capacity and potential data locations for collection.

</details>

---

<details>
<summary id="flag-6"><strong>Flag 6: DISCOVERY – Connectivity Validation</strong></summary>

### Objective
Detect validation of outbound connectivity.

### Finding
The parent process initiating connectivity checks was: "RuntimeBroker.exe"

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("nslookup", "ping")
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, InitiatingProcessParentFileName, ProcessCommandLine
```

### Why it matters
Actors commonly validate DNS resolution and outbound connectivity before attempting data transfer.

</details>

---

<details>
<summary id="flag-7"><strong>Flag 7: DISCOVERY – Interactive Session Enumeration</strong></summary>

### Objective
Identify attempts to enumerate active user sessions.

### Finding
Initiating Process Unique ID: "2533274790397065".

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("query", "qwinsta")
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, FileName, InitiatingProcessUniqueId, ProcessCommandLine
```

### Why it matters
Enumerating active sessions allows attackers to determine which users are logged in and whether privileged sessions exist.

</details>

---

<details>
<summary id="flag-8"><strong>Flag 8: DISCOVERY – Runtime Process Enumeration</strong></summary>

### Objective
Detect enumeration of running applications.

### Finding
The command used was: "tasklist.exe".

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("tasklist")
| order by TimeGenerated desc
```

### Why it matters
Process enumeration allows attackers to identify security tools, monitoring agents, and sensitive applications.

</details>

---

<details>
<summary id="flag-9"><strong>Flag 9: DISCOVERY – Privilege Enumeration</strong></summary>

### Objective
Identify attempts to determine user privileges.

### Finding
First privilege check occurred at: "2025-10-09T12:52:14.3135459Z"

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("whoami", "who", "net user", "net localgroup", "icacls")
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, ProcessCommandLine
```

### Why it matters
Commands like "whoami /groups" or "whoami /priv" allow actors to determine privilege level and escalation opportunities.

</details>

---

<details>
<summary id="flag-10"><strong>Flag 10: C2 / EGRESS VALIDATION</strong></summary>

### Objective
Detect outbound connectivity tests.

### Finding
First external destination contacted: "www.msftconnecttest.com".

### KQL Query
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where RemotePort == "443" or RemotePort == "80"
| where RemoteUrl has_any ("msftconnecttest")
```

### Why it matters
Windows uses this endpoint for internet connectivity testing, making it a stealthy method to verify outbound access.

</details>

---

<details>
<summary id="flag-11"><strong>Flag 11: COLLECTION – Artifact Staging</strong></summary>

### Objective
Identify where collected artifacts were consolidated.

### Finding
Artifacts were staged at: "C:\Users\Public\ReconArtifacts.zip".

### KQL Query
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessUniqueId == 2533274790397065
```

### Why it matters
Data staging is a preparatory step prior to exfiltration attempts.

</details>

---

<details>
<summary id="flag-12"><strong>Flag 12: EXFILTRATION ATTEMPT</strong></summary>

### Objective
Detect outbound transfer attempts.

### Finding
Last outbound connection IP: "100.29.147.161" associated with: "httpbin.org".

### KQL Query
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessUniqueId == 2533274790397065
```

### Why it matters
Testing uploads to external web services often precedes actual data exfiltration.

</details>

---

<details>
<summary id="flag-13"><strong>Flag 13: PERSISTENCE – Scheduled Task</strong></summary>

### Objective
Detect scheduled persistence mechanisms.

### Finding
Task Name: "SupportToolUpdater". Command Observed: ""schtasks.exe" /Create /SC ONLOGON /TN SupportToolUpdater /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\g4bri3lintern\Downloads\SupportTool.ps1"" /RL LIMITED /F".

### KQL Query
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessUniqueId == 2533274790397065
| distinct ProcessCommandLine
```

### Why it matters
Scheduled tasks allow automatic re-execution when users log in, providing persistence.

</details>

---

<details>
<summary id="flag-14"><strong>Flag 14: PERSISTENCE – Registry Run Key</strong></summary>

### Objective
Detect fallback persistence mechanisms.

### Finding
Registry value created: "RemoteAssistUpdater".

### KQL Query
```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessUniqueId == 2533274790397065
```

### Why it matters
Registry run keys ensure scripts execute whenever a user logs in, providing a secondary persistence mechanism.

</details>

---

<details>
<summary id="flag-15"><strong>Flag 15: DEFENSE EVASION – Planted Narrative Artifact</strong></summary>

### Objective
Identify deceptive artifacts used to justify suspicious activity.

### Finding
File discovered: "SupportChat_log.lnk". 

### KQL Query
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ActionType  == "FileCreated" or ActionType == "FileModified"
| where FileName contains "SupportChat"
```

### Why it matters
Attackers sometimes leave artifacts designed to explain or disguise suspicious activity, such as fake helpdesk logs.

</details>

---

## Detection Gaps & Recommendations

### Observed Gaps
- Download directory executions were not restricted or monitored
- PowerShell script execution lacked sufficient logging controls
- Persistence mechanisms (scheduled tasks and registry run keys) were not centrally audited
- Outbound connectivity checks were allowed without anomaly detection

### Recommendations
- Enable PowerShell Script Block Logging and AMSI integration
- Monitor Downloads directory execution events
- Implement scheduled task and registry persistence monitoring
- Deploy egress filtering and network anomaly detection
- Create detections for common reconnaissance commands (tasklist, whoami, qwinsta, wmic)

---

## Final Assessment

The activity observed on gab-intern-vm demonstrates a structured sequence of reconnaissance, connectivity validation, artifact staging, persistence establishment, and narrative manipulation designed to resemble a legitimate support session. The operations indicate deliberate attempts to gather system intelligence, validate exfiltration paths, and maintain access through scheduled tasks and registry-based persistence.

Although some actions appear simulated or staged, the behavioral pattern closely resembles early-stage intrusion tradecraft used by threat actors performing host reconnaissance and persistence preparation. The investigation highlights the importance of correlating system telemetry and behavioral indicators rather than relying on contextual explanations provided by artifacts left behind.


---
