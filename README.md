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

- Watch for in-memory credential extraction (ps “antivirus” | kill or using Mimikatz-like behaviour).
- Monitor for domain admin credentials harvesting with PowerShell and cmd-based tools.

### 3. Active Directory Reconnaissance

Monitor for Active Directory Reconnaissance activities such as querying for Domain Controllers, Domain Admins, and other privileged information. Below are queries to track key commands like Net GROUP "Domain Admins", Computername /DCLIST, NetSess.exe.

a) Detecting Net GROUP "Domain Admins" Command Execution
- This command is used by attackers to list all domain admins, which can provide valuable targets for privilege escalation.

```
  DeviceProcessEvents
| where FileName == "net.exe"
| extend CommandLineLower = tolower(CommandLine)
| where CommandLineLower contains "group" and CommandLineLower contains "domain admins"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine
```

This query identifies the execution of net.exe with the group and domain admins parameters to detect attempts to enumerate domain admins.

b) Detecting Computername /DCLIST Command Execution
- The Computername /DCLIST command is used to list Domain Controllers (DCs) in the network, a critical piece of information for an attacker during lateral movement.

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

- You can monitor for suspicious activity involving tools like PowerShell, BloodHound, or other AD recon tools that are commonly used to gather information about privileged accounts.
```
DeviceProcessEvents
| where FileName in ("powershell.exe", "sharp.exe", "bloodhound.exe")
| extend CommandLineLower = tolower(CommandLine)
| where CommandLineLower contains "invoke-bloodhound" or CommandLineLower contains "get-domainadmin" or CommandLineLower contains "get-dc"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, CommandLine
```
This query tracks the use of PowerShell and other tools like SharpHound (the BloodHound ingestor) for querying domain information such as domain admins, DCs, or other AD objects.


### 4.SSH/RDP/SMB Detection
- Monitor abnormal SSH, RDP, and SMB file share access logs, especially from non-trusted sources.

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


### References
- MITRE ATT&CK Framework: Lateral Movement Tactics.
- Microsoft Active Directory Security Best Practices.
- Common Adversary Tools for Reconnaissance and Credential Harvesting.

