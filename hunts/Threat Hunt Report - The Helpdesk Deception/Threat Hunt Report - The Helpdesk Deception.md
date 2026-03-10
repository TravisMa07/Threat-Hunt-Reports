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
| 2 | Impair Defenses | T1562 | Defense Evasion
 |
| 3 | Clipboard Data | T1115 | Collection |
| 4 | Remote System Discovery | T1018 | Discovery |
| 5 | System Information Discovery | T1082 | Discovery |
| 6 | Network Service Discovery | T1046 | Discovery |
| 7 | System Owner/User Discovery | T1033 | Discovery |
| 8 | Process Discovery
 | T1057 | Discovery |
| 9 | Account Discovery | T1087 | Discovery |
| 10 | Application Layer Protocol: Web Protocols | T1071.001 | Command and Control |
| 11 | Data Staged: Local Data Staging | T1074.001 | Collection |
| 12 | Exfiltration Over Web Service: Exfiltration Over Webhook | T1567.004 | Exfiltration |
| 13 | <Placeholder> | <Placeholder> | <Placeholder> |
| 14 | <Placeholder> | <Placeholder> | <Placeholder> |
| 15 | <Placeholder> | <Placeholder> | <Placeholder> |
| 16 | <Placeholder> | <Placeholder> | <Placeholder> |
| 17 | <Placeholder> | <Placeholder> | <Placeholder> |
| 18 | <Placeholder> | <Placeholder> | <Placeholder> |
| 19 | <Placeholder> | <Placeholder> | <Placeholder> |
| 20 | <Placeholder> | <Placeholder> | <Placeholder> |

---

## Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="flag-1"><strong>Flag 1: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### KQL Query

### Evidence

### Why it matters
<Explain impact, risk, and relevance>

</details>

---

<!-- Duplicate Flag 1 section for Flags 2–20 -->

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
