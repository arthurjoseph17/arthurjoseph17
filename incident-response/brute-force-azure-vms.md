🚨 Incident Report: Brute Force Attempts Against Azure VMs
📖 Summary

On September 17, 2025, Microsoft Sentinel and MDE detected multiple brute force attempts targeting three different virtual machines. The attempts originated from three distinct public IP addresses on the internet. Despite a high number of failed logon attempts, no successful logins were observed.

🔎 Detection & Analysis

Query executed in Log Analytics to detect repeated logon failures:

DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 50


Findings:

VM: keith-cyber-win

IP: 95.214.55.202

Failures: 94

VM: linux-target-1.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net

IP: 68.183.227.100

Failures: 74

VM: blless-win10

IP: 27.45.40.209

Failures: 82

Verification query was run to determine if brute force attempts were successful:

DeviceLogonEvents
| where RemoteIP in ("95.214.55.202", "68.183.227.100", "27.45.40.209")
| where ActionType != "LogonFailed"


Result: ✅ No successful logons detected from these IP addresses.

🛡️ Containment Actions

Device Isolation: All three affected VMs were isolated in Microsoft Defender for Endpoint (MDE).

Malware Scan: Full antivirus scans executed on all three devices via MDE.

Network Hardening:

Updated NSG rules to block public RDP access.

Proposed corporate policy to enforce this restriction across all VMs using Azure Policy.

📊 Screenshots & Evidence

Detection in Sentinel Queries:


Analytics Rule Configuration:


Sentinel Active Rule:


Incident Investigation Map:


Follow-up Verification Query:


📌 MITRE ATT&CK Mapping

T1110 - Brute Force

Multiple failed logon attempts from external IPs targeting Azure VMs.

T1078 - Valid Accounts (Prevented)

No evidence of successful logons using valid credentials.

TA0001 - Initial Access

Attempts align with external actors probing VM logon surfaces.

✅ Conclusion

The incident involved unsuccessful brute force attempts against three Azure VMs. No compromise was detected, but the event highlighted gaps in NSG configurations. Containment measures were successfully applied, and a preventive corporate policy has been proposed to enforce secure RDP access controls across the environment.
