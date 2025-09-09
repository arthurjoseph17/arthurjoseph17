# Threat Hunting Scenario: Sudden Network Slowdowns

This scenario investigates a **sudden slowdown in network performance**. The threat hunt revealed suspicious failed connections, a discovered PowerShell-based port scan, and abnormal execution context (SYSTEM). The host was subsequently isolated and scheduled for reimaging.

---

## 📖 Timeline Summary & Findings

### 🚩 Connection Failures
We began by analyzing failed connection requests to identify suspicious network activity:

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```

image 1

**Observation**: windows-target-1 was failing connections against itself and another host.

🔎 **Sequential Port Scanning**

After isolating events for our suspected host 10.0.0.5, we observed a sequential order of ports, indicating port scanning activity:

```kql
let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```

**Finding**: Multiple port scans originating from windows-target-1.

🖥️ **Process Analysis**

We pivoted to DeviceProcessEvents to examine process execution during the suspected scanning timeframe:

```kql
let VMName = "windows-target-1";
let specificTime = datetime(2025-09-08T00:39:10.2943347Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

**Finding**: A suspicious PowerShell script portscan.ps1 executed at **2025-09-08T00:39:23Z**.

Script launched under **SYSTEM account** — not expected or admin-approved behavior.

image 2


🛡️ Response Actions

Isolated the affected host from the network.

Ran a full malware scan (no detections found).

Submitted a ticket for device reimage/rebuild.

🎯 MITRE ATT&CK Mapping

TA0043 — Reconnaissance

T1046: Network Service Scanning

TA0002 — Execution

T1059.001: Command and Scripting Interpreter: PowerShell

TA0004 — Privilege Escalation

T1078.003: Valid Accounts: Local Accounts

TA0005 — Defense Evasion

T1027: Obfuscated Files or Information

TA0007 — Discovery

T1021: Remote Services

TA0008 — Lateral Movement (Potential Future Phase)

T1021: Remote Services

📊 Findings Summary

Root Cause: Unauthorized PowerShell script execution (portscan.ps1).

Impact: Host windows-target-1 initiated multiple port scans, causing slowdowns.

Outcome: No malware discovered, but persistence of SYSTEM-level script execution warranted device rebuild.
