# Defending Against Lateral Movement in a SOC Environment

### Overview

This project demonstrates how to defend against lateral movement within a network, a critical phase in the cyber kill chain, where an adversary who has gained a foothold begins moving laterally across systems. This project focuses on the key responsibilities of a Blue SOC team to reduce the adversary’s dwell time by employing detection, response, and mitigation strategies.

### Objectives

- Detect and respond to lateral movement early to reduce the dwell time of attackers.
- Implement monitoring for key signs of network reconnaissance and credential harvesting.
- Use PowerShell and Command Line detection scripts to identify suspicious activity.
- Provide playbooks to investigate and respond to incidents involving Active Directory (AD) reconnaissance and unauthorised access to sensitive areas of the network.

### Tools

- IPS/IDS Systems: To detect suspicious lateral movement.
- EDR Solutions (CrowdStrike, Sentinel, Rapid7): For advanced behavioural analysis and monitoring endpoint activity.
- Threat Intelligence Platforms (MITRE ATT&CK): Leveraging MITRE ATT&CK techniques for lateral movement detection.
- Custom detection rules or analytic rules that alert when these reconnaissance commands are executed: For detecting network recon, credential harvesting, and Active Directory querying.
  

### Key Features
### 1. Network Reconnaissance Detection

Monitor for commands that indicate reconnaissance attempts: hostname, whoami, ipconfig or systeminfo

a) The hostname command is used by attackers to identify the name of the machine they have compromised.

```
DeviceProcessEvents
| where FileName == "hostname.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine

```
This query looks for the execution of hostname.exe on any endpoint.

b) The whoami command is often used by attackers to identify the current user and their privileges on the compromised machine.

```
DeviceProcessEvents
| where FileName == "whoami.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine

```
This query tracks executions of whoami.exe, which attackers use to discover the user context they are operating under.

c) Detecting ipconfig Command Execution

The ipconfig command is used to gather network configuration details like IP addresses, DNS settings, and gateways, helping attackers map out the network.

```
DeviceProcessEvents
| where FileName == "ipconfig.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine

```
This query monitors for executions of ipconfig.exe which can indicate network reconnaissance.

d) Detecting systeminfo Command Execution
The systeminfo command provides detailed information about the machine, such as OS version, hardware, and patch levels, often used by attackers to determine if a system is vulnerable.
```
DeviceProcessEvents
| where FileName == "systeminfo.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine
```
This query captures the use of systeminfo.exe, which gives attackers key information about the system environment.

### 2. Credential Harvesting

To detect credential harvesting attempts, such as in-memory credential extraction using malicious tools (e.g., Mimikatz) or suspicious behaviour (e.g., killing antivirus processes)

a) Attackers often try to disable antivirus software to evade detection before extracting credentials. This query looks for process termination attempts (especially those targeting security tools).

```
DeviceProcessEvents
| where FileName == "taskkill.exe" or FileName == "powershell.exe"  // Common tools used to kill processes
| extend CommandLineLower = tolower(CommandLine)
| where CommandLineLower contains "antivirus" or CommandLineLower contains "security"
| where CommandLineLower contains "/f" or CommandLineLower contains "kill"  // Forced termination
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine
```
This query tracks commands attempting to kill processes related to antivirus or security software using taskkill, PowerShell, or similar tools.


b) Detecting Mimikatz-Like Behaviour

Mimikatz is a widely known tool used to extract credentials from memory. It often uses certain signature commands and functions, such as sekurlsa::logonpasswords and lsadump::sam, or attempts to manipulate LSASS.exe.

```
DeviceProcessEvents
| where FileName in ("mimikatz.exe", "powershell.exe")  // Mimikatz or PowerShell being used to load similar functions
| extend CommandLineLower = tolower(CommandLine)
| where CommandLineLower contains "sekurlsa::logonpasswords" or CommandLineLower contains "lsadump::sam"
or CommandLineLower contains "lsass"  // LSASS process manipulation
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine
```

c) Detecting Suspicious PowerShell Commands
PowerShell is often used in memory attacks to run malicious scripts for credential harvesting without writing binaries to disk.

```
DeviceProcessEvents
| where FileName == "powershell.exe"
| extend CommandLineLower = tolower(CommandLine)
| where CommandLineLower contains "invoke-mimikatz" or CommandLineLower contains "get-credential"
or CommandLineLower contains "dumpcreds" or CommandLineLower contains "memory"  // Common Mimikatz-like activity
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine
```
This query tracks PowerShell commands related to credential harvesting attempts.

### 3. Active Directory Reconnaissance

Monitor for Active Directory Reconnaissance activities such as querying for Domain Controllers, Domain Admins, and other privileged information. Below are queries to track key commands like Net GROUP "Domain Admins", Computername /DCLIST, NetSess.exe.

a) Detecting Net GROUP "Domain Admins" Command Execution
This command is used by attackers to list all domain admins, which can provide valuable targets for privilege escalation.

```
  DeviceProcessEvents
| where FileName == "net.exe"
| extend CommandLineLower = tolower(CommandLine)
| where CommandLineLower contains "group" and CommandLineLower contains "domain admins"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine
```

This query identifies the execution of net.exe with the group and domain admins parameters to detect attempts to enumerate domain admins.

b) Detecting Computername /DCLIST Command Execution
The Computername /DCLIST command is used to list Domain Controllers (DCs) in the network, a critical piece of information for an attacker during lateral movement.

```
DeviceProcessEvents
| where FileName == "computername.exe"
| extend CommandLineLower = tolower(CommandLine)
| where CommandLineLower contains "/dclist"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine
```
This query captures the use of Computername.exe /DCLIST to detect reconnaissance for Domain Controllers.

c) Detecting NetSess.exe Command Execution

The NetSess.exe tool is often used by attackers to enumerate live sessions and identify active privileged accounts.

```
DeviceProcessEvents
| where FileName == "netsess.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine

```
This query monitors for the execution of NetSess.exe, which is used to gather session data on domain controllers or other privileged systems.

d) Detecting Tools that Gather Privileged Account Information

You can monitor for suspicious activity involving tools like PowerShell, BloodHound, or other AD recon tools that are commonly used to gather information about privileged accounts.
```
DeviceProcessEvents
| where FileName in ("powershell.exe", "sharp.exe", "bloodhound.exe")
| extend CommandLineLower = tolower(CommandLine)
| where CommandLineLower contains "invoke-bloodhound" or CommandLineLower contains "get-domainadmin" or CommandLineLower contains "get-dc"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine
```
This query tracks the use of PowerShell and other tools like SharpHound (the BloodHound ingestor) for querying domain information such as domain admins, DCs, or other AD objects.


### 4. SSH/RDP/SMB Detection
Monitor abnormal SSH, RDP, and SMB file share access logs, especially from non-trusted sources.

a) Monitoring SSH Access

SSH access, especially from unknown or suspicious IP addresses, can be an indicator of malicious activity. For this, you'll monitor successful SSH logins and filter for non-trusted or unusual IPs.

```
DeviceNetworkEvents
| where RemotePort == 22  // SSH port
| where ActionType == "InboundConnectionAccepted" or ActionType == "LogonSuccess"
| where RemoteIPCountry != "trusted_country"  // Replace with your trusted countries or IP ranges
| project Timestamp, DeviceName, RemoteIP, InitiatingProcessAccountName, RemotePort, ActionType, Protocol

```
This query monitors SSH connections and flags them if they originate from non-trusted sources based on the country or specific IP ranges.


b) Monitoring RDP Access

RDP (Remote Desktop Protocol) access from non-trusted sources or abnormal users can indicate a potential breach.

```
DeviceNetworkEvents
| where RemotePort == 3389  // RDP port
| where ActionType == "InboundConnectionAccepted" or ActionType == "LogonSuccess"
| where RemoteIPCountry != "trusted_country"  // Replace with trusted countries or IP ranges
| project Timestamp, DeviceName, RemoteIP, InitiatingProcessAccountName, RemotePort, ActionType, Protocol

```

c)  Monitoring SMB File Share Access

SMB (Server Message Block) file share access, especially from unusual or non-trusted IPs, can indicate reconnaissance or lateral movement.

```
DeviceNetworkEvents
| where RemotePort == 445  // SMB port
| where ActionType == "FileAccessed" or ActionType == "FileShared"
| where RemoteIPCountry != "trusted_country"  // Replace with trusted countries or IP ranges
| project Timestamp, DeviceName, RemoteIP, InitiatingProcessAccountName, FileName, ActionType, RemotePort
```
This query tracks SMB file share access and flags it if the access comes from non-trusted sources.


### 5. Ransomware/Destructware Identification

- Watch for indicators of ransomware deployment following lateral movement, with key emphasis on payload installation in critical systems.

### 6. Command-line Investigation

These are the Kusto Query Language (KQL) to create queries in Azure Sentinel or Microsoft Defender for Endpoints for detecting malicious command-line executions for

- Klist (Kerberos tickets hijacking).
- Cmdkey /l (looking for cached credentials).
- Net user “user” /domain (to check for unauthorised users probing the domain).

a) Detecting klist Command Execution

The klist command can be used by attackers to view Kerberos tickets, allowing them to hijack sessions or maintain persistence

```
DeviceProcessEvents
| where FileName == "klist.exe"
| extend CommandLineLower = tolower(CommandLine)
| where CommandLineLower contains "klist"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine

```
This query searches for the execution of klist.exe and logs the device name, user, and the full command-line arguments.

b)  Detecting cmdkey /l (Cached Credentials)

Attackers may use cmdkey /l to view stored credentials, which can be leveraged for lateral movement.

```
DeviceProcessEvents
| where FileName == "cmdkey.exe"
| extend CommandLineLower = tolower(CommandLine)
| where CommandLineLower contains "/l"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine

```
This query specifically looks for the cmdkey /l command, which lists stored credentials. It will help identify if an attacker is probing for cached credentials on the system.


c) Detecting net user "user" /domain (Domain User Enumeration)

This command is used by attackers to query domain user information, often as part of reconnaissance before lateral movement.

```
DeviceProcessEvents
| where FileName == "net.exe"
| extend CommandLineLower = tolower(CommandLine)
| where CommandLineLower contains "net user" and CommandLineLower contains "/domain"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine

```
This query checks for the net user "user" /domain command being run on a machine, which is commonly used to gather domain information.


## Analytical rules

This query will check for the execution of any of the listed suspicious commands (klist, cmdkey /l, net user /domain) and trigger an alert if any are detected.

### Steps to Create an Analytic Rule in Azure Sentinel:

1. Open Azure Sentinel and go to the Analytics blade.
2. Click + Create and select Scheduled query rule.

- Detect multiple network reconnaissance

```
DeviceProcessEvents
| where FileName in ("hostname.exe", "whoami.exe", "ipconfig.exe", "systeminfo.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine

```

- Detect Credential Harvesting reconnaissance

```
// Detect multiple reconnaissance and credential harvesting commands
DeviceProcessEvents
| where FileName in ("klist.exe", "cmdkey.exe", "net.exe")
| extend CommandLineLower = tolower(CommandLine)
// Detection logic for klist command
| where (FileName == "klist.exe" and CommandLineLower contains "klist")
// Detection logic for cmdkey /l command
or (FileName == "cmdkey.exe" and CommandLineLower contains "/l")
// Detection logic for net user /domain command
or (FileName == "net.exe" and CommandLineLower contains "net user" and CommandLineLower contains "/domain")
// Project relevant information for investigation
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine

```

- Detect Credential AD reconnaissance

```
DeviceProcessEvents
| where FileName in ("net.exe", "computername.exe", "netsess.exe", "powershell.exe", "sharp.exe", "bloodhound.exe")
| extend CommandLineLower = tolower(CommandLine)
// Detection for Net GROUP "Domain Admins"
| where (FileName == "net.exe" and CommandLineLower contains "group" and CommandLineLower contains "domain admins")
// Detection for Computername /DCLIST
or (FileName == "computername.exe" and CommandLineLower contains "/dclist")
// Detection for NetSess.exe
or (FileName == "netsess.exe")
// Detection for AD tools like BloodHound, SharpHound, and PowerShell Recon
or (FileName in ("powershell.exe", "sharp.exe", "bloodhound.exe") and CommandLineLower contains "invoke-bloodhound")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine

```

- Detect  SSH, RDP, and SMB Access Monitoring

```
DeviceNetworkEvents
| where RemotePort in (22, 3389, 445)  // SSH, RDP, SMB ports
| where ActionType in ("InboundConnectionAccepted", "LogonSuccess", "FileAccessed", "FileShared")
| where RemoteIPCountry != "trusted_country"  // Replace with trusted countries or IP ranges
| project Timestamp, DeviceName, RemoteIP, InitiatingProcessAccountName, FileName, RemotePort, ActionType, Protocol

```

- Detect Credential Monitoring

```
DeviceProcessEvents
| where FileName in ("taskkill.exe", "powershell.exe", "mimikatz.exe")
| extend CommandLineLower = tolower(CommandLine)
// Detect attempts to kill antivirus
| where (FileName == "taskkill.exe" or FileName == "powershell.exe") 
and (CommandLineLower contains "antivirus" or CommandLineLower contains "security")
and (CommandLineLower contains "/f" or CommandLineLower contains "kill")
// Detect Mimikatz usage or LSASS manipulation
or (FileName == "mimikatz.exe" and (CommandLineLower contains "sekurlsa::logonpasswords" or CommandLineLower contains "lsadump::sam" or CommandLineLower contains "lsass"))
// Detect suspicious PowerShell behaviour
or (FileName == "powershell.exe" and (CommandLineLower contains "invoke-mimikatz" or CommandLineLower contains "get-credential" or CommandLineLower contains "dumpcreds" or CommandLineLower contains "memory"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine

```










### References
- MITRE ATT&CK Framework: Lateral Movement Tactics.
- Microsoft Active Directory Security Best Practices.
- Common Adversary Tools for Reconnaissance and Credential Harvesting.

