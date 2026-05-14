<img width="705" height="726" alt="image" src="https://github.com/user-attachments/assets/c5465d56-5daf-4a3c-9178-efcd794c8ecf" />

# The-Buyer-Incident-Response-Center(Cont Of "The Broker" Threat Hunt) (WIP)

# Threat Hunt Report — The Buyer

## Hunt Metadata

| Field | Details |
|---|---|
| **Scenario** | The Buyer — Incident Response Centre |
| **Devices in Scope** | `as-pc1`, `as-pc2`, `as-srv` |
| **Threat Actor** | Akira Ransomware Group |
| **Hunt Period** | 2026-01-01 to 2026-02-01 |
| **Compromised Hosts** | `as-pc2`, `as-srv` |
| **Compromised User** | `david.mitchell` |

---

## Executive Summary

This investigation covers a full ransomware attack chain carried out by the **Akira** ransomware group. The attacker gained initial access via a malicious PDF dropper, established persistence using AnyDesk, deployed a custom C2 beacon (`wsync.exe`), performed credential theft targeting LSASS, moved laterally via WMI remote execution, exfiltrated data using a custom staging tool, and ultimately deployed ransomware (`updater.exe`) across the environment. Security controls were actively disabled via a batch script (`kill.bat`) and Volume Shadow Copies were deleted to prevent recovery.

---

## Section 1 — Ransom Note Analysis

### Q1 — Threat Actor

**Flag:** Identify the ransomware group from the ransom note.

**Answer:** `Akira`

**What This Reveals:** The ransom note (`akira_readme.txt`) confirms the threat actor is the Akira ransomware group, a double-extortion operation that both encrypts files and exfiltrates data threatening public release.

**MITRE ATT&CK:** T1486 — Data Encrypted for Impact

---

### Q2 — Negotiation Portal

**Flag:** The ransom note provides a contact method.

**Answer:** `akira12iz6a7qgd3ayp316yub7xx2uep76idk3u2ko11pj5z3z636bad.onion`

**What This Reveals:** Akira operates a TOR-based negotiation portal where victims contact the group. The `.onion` address is hosted on the Tor network to anonymize attacker infrastructure.

**MITRE ATT&CK:** T1090.003 — Proxy: Multi-hop Proxy

---

### Q3 — Victim ID

**Flag:** Each victim receives a unique identifier for negotiations.

**Answer:** `813R-QWJM-XKIJ`

**What This Reveals:** Akira assigns each victim a unique negotiation ID embedded in the ransom note. This ID is used to identify the victim on their TOR portal and track ransom payment status.

**MITRE ATT&CK:** T1486 — Data Encrypted for Impact

---

### Q4 — Encrypted Extension

**Flag:** Encrypted files have a new extension appended.

**Answer:** `.akira`

**What This Reveals:** All encrypted files have `.akira` appended to the original extension. This is Akira's standard file marker, confirming ransomware execution reached the file system level.

**MITRE ATT&CK:** T1486 — Data Encrypted for Impact

---

## Section 2 — Infrastructure

### Q5 — Payload Domain

**Flag:** Tools were downloaded from an external domain.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-03-01T00:00:00))
| where DeviceName == "as-pc2"
| where ProcessCommandLine has_any ("curl", "Invoke-WebRequest", "certutil")
```

**Answer:** `sync.cloud-endpoint.net`

**What This Reveals:** The attacker hosted malicious payloads on `sync.cloud-endpoint.net`. Tools including `scan.exe` and `wsync.exe` were downloaded from this domain. The domain name is crafted to blend in as a legitimate cloud sync service.

**MITRE ATT&CK:** T1105 — Ingress Tool Transfer

---

### Q6 — Ransomware Staging

**Flag:** The payload established outbound connections.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, ActionType, InitiatingProcessFileName, RemoteUrl
```

**Answer:** `cdn.cloud-endpoint.net`

**What This Reveals:** The initial dropper (`daniel_richardson_cv.pdf.exe`) beaconed out to `cdn.cloud-endpoint.net` after execution, establishing C2 communications and staging ransomware components.

**MITRE ATT&CK:** T1071.001 — Application Layer Protocol: Web Protocols

---

### Q7 — C2 IP Addresses

**Flag:** The C2 infrastructure resolved to multiple IPs.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, ActionType, InitiatingProcessFileName, RemoteUrl, RemoteIP
```

**Answer:** `104.21.30.237, 172.67.174.46`

**What This Reveals:** The C2 domain resolved to two Cloudflare IP addresses, indicating the attacker used Cloudflare as a relay/proxy layer to mask their true infrastructure. This is a common attacker technique to make C2 takedowns harder.

**MITRE ATT&CK:** T1090.002 — Proxy: External Proxy

---

### Q8 — Remote Tool Relay

**Flag:** A remote tool routes through relay servers.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where RemoteUrl contains "anydesk"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName, RemoteUrl, RemoteIP
```

**Answer:** `relay-0b975d23.net.anydesk.com`

**What This Reveals:** AnyDesk traffic was routed through AnyDesk's relay infrastructure. The specific relay node `relay-0b975d23.net.anydesk.com` was observed on `as-srv`, indicating the attacker maintained remote access to the server through AnyDesk's relay network.

**MITRE ATT&CK:** T1219 — Remote Access Software

---

## Section 3 — Defense Evasion

### Q9 — Evasion Script

**Flag:** A script was used to disable security controls.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName =~ "reg.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, FileName
```

**Answer:** `kill.bat`

**What This Reveals:** A batch script named `kill.bat` located at `C:\ProgramData\kill.bat` was executed via `cmd.exe /c "C:\ProgramData\kill.bat"` on `as-pc2`. The script used `reg.exe` to disable Windows Defender via registry modification.

**MITRE ATT&CK:** T1562.001 — Impair Defenses: Disable or Modify Tools

---

### Q10 — Evasion Hash

**Flag:** Identify the hash of the evasion script.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName contains "kill.bat"
| project TimeGenerated, FileName, SHA256
```

**Answer:** `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c`

**What This Reveals:** The SHA256 hash uniquely identifies the `kill.bat` script. This hash can be used for threat intelligence lookups and to identify the same script deployed in other environments.

**MITRE ATT&CK:** T1562.001 — Impair Defenses: Disable or Modify Tools

---

### Q11 — Registry Tampering

**Flag:** Windows Defender was disabled via registry modification.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName =~ "reg.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, FileName, SHA256
```

**Answer:** `DisableAntiSpyware`

**What This Reveals:** `kill.bat` set `DisableAntiSpyware = 1` under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`, fully disabling Windows Defender antispyware capabilities. A second key `DisableRealtimeMonitoring = 1` disabled real-time protection.

**MITRE ATT&CK:** T1562.001 — Impair Defenses: Disable or Modify Tools

---

### Q12 — Registry Timestamp

**Flag:** Determine when the registry was modified.

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc2")
| where ActionType == "RegistryValueSet"
| where RegistryKey contains "Windows Defender"
| project TimeGenerated, InitiatingProcessCommandLine
```

**Answer:** `2026-01-27T21:03:42Z`

**What This Reveals:** The registry was modified at 21:03 UTC on January 27, 2026, providing a precise timestamp for when Defender was disabled — a key anchor point in the attack timeline.

**MITRE ATT&CK:** T1562.001 — Impair Defenses: Disable or Modify Tools

---

## Section 4 — Credential Access

### Q13 — Process Hunt

**Flag:** The attacker enumerated running processes to locate a target for credential theft.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine has_any ("lsass")
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, FileName, SHA256
| sort by TimeGenerated asc
```

**Answer:** `tasklist | findstr lsass`

**What This Reveals:** The attacker ran `tasklist | findstr lsass` from `wsync.exe` on `as-pc2` at 21:11 UTC to locate the `lsass.exe` process ID before credential dumping. This is a standard precursor step to LSASS memory dumping.

**MITRE ATT&CK:** T1057 — Process Discovery

---

### Q14 — Credential Pipe

**Flag:** A named pipe was accessed during credential theft activity.

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc2")
| where ActionType contains "NamedPipeEvent"
| project TimeGenerated, DeviceName, AdditionalFields, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Answer:** `\Device\NamedPipe\lsass`

**What This Reveals:** A named pipe to `lsass` was accessed at 20:18 UTC on `as-pc2`, indicating a credential dumping tool interacted directly with the LSASS process via its named pipe interface — consistent with tools like Mimikatz or a custom dumper.

**MITRE ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory

---

## Section 5 — Initial Access

### Q15 — Remote Access Tool

**Flag:** A remote access tool was pre-staged from the previous attack.

**Answer:** `AnyDesk`

**What This Reveals:** AnyDesk was pre-staged on the environment from a prior compromise ("The Broker"). The attacker reused this existing remote access foothold to regain entry into the environment without needing to re-exploit initial access.

**MITRE ATT&CK:** T1219 — Remote Access Software

---

### Q16 — Suspicious Execution Path

**Flag:** The remote access tool was running from an unusual location on AS-PC2.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc2")
| where FileName contains "anydesk"
| project TimeGenerated, ActionType, FileName, FolderPath
```

**Answer:** `C:\Users\Public`

**What This Reveals:** `AnyDesk.exe` was executed from `C:\Users\Public\` rather than a legitimate install path. This world-writable directory requires no admin rights to write to, and its use indicates the attacker dropped and ran AnyDesk without performing a standard installation.

**MITRE ATT&CK:** T1036.005 — Masquerading: Match Legitimate Name or Location

---

### Q17 — Attacker IP

**Flag:** Identify the attacker's external IP address.

**Answer:** `88.97.164.155`

**What This Reveals:** The attacker connected directly to AnyDesk on `as-pc2` over port 7070 (AnyDesk's direct connection port) from IP `88.97.164.155`. This IP appeared multiple times across ports 44207, 43904, and 7070, distinguishing it from AnyDesk relay infrastructure IPs.

**MITRE ATT&CK:** T1219 — Remote Access Software

---

### Q18 — Compromised User

**Flag:** Identify the user account that was compromised.

**Answer:** `david.mitchell`

**What This Reveals:** The account `david.mitchell` on `as-pc2` was compromised. The attacker operated under this identity to download tools, run scanners, and execute commands throughout the attack chain.

**MITRE ATT&CK:** T1078 — Valid Accounts

---

## Section 6 — Command & Control

### Q19 — Primary Beacon

**Flag:** A pre-staged beacon failed to maintain stable communications. A new beacon was deployed.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FolderPath has_any ("Public", "ProgramData", "Temp", "AppData")
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Answer:** `wsync.exe`

**What This Reveals:** A new C2 beacon named `wsync.exe` was deployed to `as-pc2` at 20:44 UTC. The name mimics a legitimate Windows sync service. It spawned all subsequent attacker commands including process enumeration, shadow copy deletion, and firewall disabling.

**MITRE ATT&CK:** T1105 — Ingress Tool Transfer | T1071 — Application Layer Protocol

---

### Q20 — Beacon Location

**Flag:** Identify where the beacon was deployed.

**Answer:** `C:\ProgramData\`

**What This Reveals:** `wsync.exe` was deployed to `C:\ProgramData\`, a common attacker staging directory that does not require high privileges to write to but is less scrutinized than `C:\Windows\System32`.

**MITRE ATT&CK:** T1036.005 — Masquerading: Match Legitimate Name or Location

---

### Q21 — Beacon Hash

**Flag:** The first beacon deployment on AS-PC2 was later replaced. Identify the hash of the original beacon.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-01-28T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName =~ "wsync.exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Answer:** `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b`

**What This Reveals:** The original `wsync.exe` was modified/replaced during the attack. The first version's hash confirms a distinct binary was used initially before the attacker swapped it out for an updated version.

**MITRE ATT&CK:** T1027 — Obfuscated Files or Information

---

### Q22 — Beacon Creation

**Flag:** A second version of the beacon was deployed after the first failed.

**Answer:** `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654`

**What This Reveals:** A replacement beacon with a different SHA256 hash was deployed to `as-pc2` at 20:22 UTC, indicating the attacker actively managed their implant and swapped it out when the initial version experienced instability.

**MITRE ATT&CK:** T1105 — Ingress Tool Transfer

---

## Section 7 — Discovery

### Q23 — Scanner Tool

**Flag:** A network scanner was deployed.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00) .. datetime(2026-01-28T00:00:00))
| where DeviceName == "as-pc2"
| project TimeGenerated, FileName, SHA256, InitiatingProcessAccountName, ProcessCommandLine, ActionType, InitiatingProcessCommandLine
| where InitiatingProcessAccountName == "david.mitchell"
```

**Answer:** `scan.exe`

**What This Reveals:** A custom network scanner `scan.exe` was deployed and executed on `as-pc2` under `david.mitchell` at 20:17 UTC. This tool was used to discover live hosts and open ports across the internal network prior to lateral movement.

**MITRE ATT&CK:** T1046 — Network Service Discovery

---

### Q24 — Scanner Hash

**Flag:** Identify the hash of the scanner.

**Answer:** `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b`

**What This Reveals:** The SHA256 hash of `scan.exe` provides a unique identifier for the custom scanning tool used by the attacker.

**MITRE ATT&CK:** T1046 — Network Service Discovery

---

### Q25 — Scanner Execution

**Flag:** The network scanner was executed with specific arguments revealing the attacker's intent.

**Answer:** `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us`

**What This Reveals:** Advanced IP Scanner was run in portable mode from `david.mitchell`'s Downloads folder. Portable mode requires no installation, making it easy to deploy and remove without leaving registry artifacts.

**MITRE ATT&CK:** T1046 — Network Service Discovery

---

### Q26 — Network Enumeration

**Flag:** The attacker enumerated network shares on specific hosts.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00) .. datetime(2026-01-28T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine contains "view"
| project TimeGenerated, DeviceName, SHA256, InitiatingProcessAccountName, ProcessCommandLine, ActionType, InitiatingProcessCommandLine
```

**Answer:** `10.1.0.183`, `10.1.0.154`

**What This Reveals:** The attacker ran `net.exe view` against two internal IPs from `as-srv` to enumerate network shares. This identified shared folders (Backups, Clients, Compliance, Contractors, Payroll) that were subsequently targeted for encryption.

**MITRE ATT&CK:** T1135 — Network Share Discovery

---

## Section 8 — Lateral Movement

### Q27 — Lateral Account

**Flag:** An account was used to access AS-SRV.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00) .. datetime(2026-01-28T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine contains "view"
| project TimeGenerated, DeviceName, SHA256, InitiatingProcessAccountName, ProcessCommandLine, ActionType, InitiatingProcessCommandLine
```

**Answer:** `as.srv.administrator`

**What This Reveals:** The attacker used the `as.srv.administrator` account — likely obtained through LSASS credential dumping — to authenticate to `as-srv`. This account provided elevated privileges enabling the attacker to deploy ransomware and staging tools on the server.

**MITRE ATT&CK:** T1078.002 — Valid Accounts: Domain Accounts

---

## Section 9 — Tool Transfer

### Q28 — Download Method

**Flag:** A living-off-the-land binary was used first but had issues.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T19:00:00) .. datetime(2026-01-28T22:00:00))
| where DeviceName == "as-pc2"
| where FileName == "bitsadmin.exe"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Answer:** `bitsadmin.exe`

**What This Reveals:** `bitsadmin.exe` was the first tool used to download payloads, observed between 20:14 and 20:50 UTC. The download command contained a malformed path (`C:ProgramDatakill.bat` missing backslashes), causing it to fail — prompting the attacker to switch methods.

**MITRE ATT&CK:** T1197 — BITS Jobs

---

### Q29 — Fallback Method

**Flag:** After the first tool failed, another method was used.

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-27T20:15:00Z) .. datetime(2026-01-27T20:25:00Z))
| where DeviceName == "as-pc2"
| where ActionType == "PowerShellCommand"
| project TimeGenerated, AdditionalFields, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Answer:** `Invoke-WebRequest`

**What This Reveals:** After `bitsadmin` failed, the attacker switched to `Invoke-WebRequest` in PowerShell to download tools. This cmdlet was used to download both `scan.exe` and `wsync.exe` from `sync.cloud-endpoint.net`. Note: this appeared in `DeviceEvents` with `ActionType == "PowerShellCommand"` rather than `DeviceProcessEvents` because it runs inside a PowerShell session rather than spawning a new process.

**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell

---

## Section 10 — Exfiltration

### Q30 — Staging Tool

**Flag:** A tool was used to compress data for exfiltration.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T22:00:00) .. datetime(2026-01-27T23:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName == "exfil_data.zip"
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Answer:** `st.exe`

**What This Reveals:** A custom staging tool `st.exe` located in `C:\ProgramData\` was used to compress stolen data into `exfil_data.zip` on `as-srv`. The tool handled compression internally rather than relying on common utilities like 7-Zip, making it harder to detect via standard LOLBin hunting.

**MITRE ATT&CK:** T1560.001 — Archive Collected Data: Archive via Utility

---

### Q31 — Staging Hash

**Flag:** Identify the hash of the staging tool.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T22:00:00) .. datetime(2026-01-27T23:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName == "st.exe"
| project TimeGenerated, ActionType, SHA256, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Answer:** `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015`

**What This Reveals:** The SHA256 hash of `st.exe` uniquely identifies this custom exfiltration staging tool for threat intelligence purposes and cross-environment detection.

**MITRE ATT&CK:** T1560.001 — Archive Collected Data: Archive via Utility

---

### Q32 — Exfil Archive

**Flag:** Identify the archive created for exfiltration.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T19:00:00) .. datetime(2026-01-28T23:59:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName endswith ".zip"
```

**Answer:** `exfil_data.zip`

**What This Reveals:** `exfil_data.zip` was created at 22:24 UTC on `as-srv` at `C:\Users\Public\exfil_data.zip`. The archive was subsequently exfiltrated to the attacker's server via an HTTP POST request using `Invoke-WebRequest`.

**MITRE ATT&CK:** T1048 — Exfiltration Over Alternative Protocol

---

## Section 11 — Ransomware Deployment

### Q33 — Ransomware Filename

**Flag:** The ransomware was disguised as a legitimate process.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T22:00:00) .. datetime(2026-01-27T23:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName == "akira_readme.txt"
| project TimeGenerated, ActionType, SHA256, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Answer:** `updater.exe`

**What This Reveals:** The Akira ransomware binary was named `updater.exe` to masquerade as a legitimate software updater process. It was responsible for encrypting files and dropping the ransom note.

**MITRE ATT&CK:** T1036.005 — Masquerading: Match Legitimate Name or Location

---

### Q34 — Ransomware Hash

**Flag:** Identify the hash of the ransomware.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15T22:00:00) .. datetime(2026-01-27T23:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName == "updater.exe"
| project TimeGenerated, ActionType, SHA256, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Answer:** `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b`

**What This Reveals:** The SHA256 hash uniquely identifies the Akira ransomware binary. This hash can be submitted to threat intelligence platforms for enrichment and used to create detection signatures.

**MITRE ATT&CK:** T1486 — Data Encrypted for Impact

---

### Q35 — Ransomware Staging

**Flag:** The ransomware was dropped onto AS-SRV before execution.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15T22:00:00) .. datetime(2026-01-27T23:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName == "updater.exe"
| project TimeGenerated, ActionType, SHA256, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Answer:** `powershell.exe`

**What This Reveals:** PowerShell was used to stage `updater.exe` onto `as-srv` prior to execution. This is consistent with the attacker's broader pattern of using PowerShell for tool deployment throughout the attack chain.

**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell

---

### Q36 — Recovery Prevention

**Flag:** The attacker deleted backup copies to prevent file recovery.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine has_any ("shadowcopy")
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, FileName, SHA256
| sort by TimeGenerated asc
```

**Answer:** `wmic shadowcopy delete`

**What This Reveals:** `wsync.exe` executed a series of recovery-prevention commands at 21:09 UTC including `wmic shadowcopy delete`, `vssadmin delete shadows /all /quiet`, `bcdedit /set {default} recoveryenabled No`, `sc stop VSS`, and `sc stop wbengine`. Together these commands eliminated all Volume Shadow Copy backups and disabled Windows recovery mechanisms.

**MITRE ATT&CK:** T1490 — Inhibit System Recovery

---

### Q37 — Ransom Note Origin

**Flag:** A ransom note was dropped after encryption began.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00) .. datetime(2026-01-28T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName == "akira_readme.txt"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Answer:** `updater.exe`

**What This Reveals:** The ransomware binary `updater.exe` dropped `akira_readme.txt` after completing file encryption. The ransom note was written to multiple directories across the affected hosts to ensure visibility to victims.

**MITRE ATT&CK:** T1486 — Data Encrypted for Impact

---

### Q38 — Encryption Start

**Flag:** Determine when encryption began.

**Answer:** `2026-01-27T22:18:33Z`

**What This Reveals:** The first ransom note was dropped at 22:18 UTC on January 27, 2026, marking the start of the encryption phase. This timestamp anchors the ransomware deployment in the overall attack timeline.

**MITRE ATT&CK:** T1486 — Data Encrypted for Impact

---

### Q39 — Cleanup Script

**Flag:** The ransomware binary was deleted after execution.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00) .. datetime(2026-01-28T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName == "updater.exe"
| where ActionType == "FileDeleted"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Answer:** `clean.bat`

**What This Reveals:** A cleanup script `clean.bat` deleted `updater.exe` after ransomware execution completed. This is an anti-forensics technique to remove evidence of the ransomware binary from disk after the damage is done.

**MITRE ATT&CK:** T1070.004 — Indicator Removal: File Deletion

---

### Q40 — Affected Hosts

**Flag:** Determine the scope of the compromise.

**Answer:** `as-srv, as-pc2`

**What This Reveals:** Two hosts were confirmed compromised. `as-pc2` was the initial beachhead where the attacker gained hands-on access via AnyDesk and deployed the C2 beacon. `as-srv` was the lateral movement target where ransomware was ultimately deployed and data was exfiltrated from the shared drives.

**MITRE ATT&CK:** T1570 — Lateral Tool Transfer

---

## Attack Timeline

| Time (UTC) | Host | Event |
|---|---|---|
| 2026-01-15 04:18 | as-pc1 | WMIC lateral movement to as-pc2, AnyDesk downloaded via certutil |
| 2026-01-15 04:41 | as-pc2 | AnyDesk executed from C:\Users\Public\ |
| 2026-01-15 04:53 | as-pc2 | WMIC lateral movement to 10.1.0.203, RuntimeBroker.exe dropped |
| 2026-01-27 20:14 | as-pc2 | bitsadmin download attempts begin (failed) |
| 2026-01-27 20:17 | as-pc2 | scan.exe executed, network discovery begins |
| 2026-01-27 20:22 | as-pc2 | Invoke-WebRequest downloads wsync.exe and scan.exe |
| 2026-01-27 20:18 | as-pc2 | Named pipe \Device\NamedPipe\lsass accessed (credential theft) |
| 2026-01-27 20:44 | as-pc2 | wsync.exe first executed (C2 beacon active) |
| 2026-01-27 21:03 | as-pc2 | Registry modified — Windows Defender disabled |
| 2026-01-27 21:06 | as-pc2 | kill.bat executed — Defender real-time protection disabled |
| 2026-01-27 21:09 | as-pc2 | Shadow copies deleted, firewall disabled, recovery prevented |
| 2026-01-27 21:11 | as-pc2 | tasklist \| findstr lsass executed |
| 2026-01-27 22:08 | as-srv | AnyDesk relay connection observed |
| 2026-01-27 22:17 | as-srv | net view enumeration of internal shares |
| 2026-01-27 22:18 | as-srv | updater.exe deployed, encryption begins, ransom note dropped |
| 2026-01-27 22:24 | as-srv | exfil_data.zip created by st.exe |
| 2026-01-27 22:24 | as-srv | exfil_data.zip exfiltrated via HTTP POST to sync.cloud-endpoint.net |
| 2026-01-27 22:xx | as-srv | clean.bat executes, updater.exe deleted |

---

## IOC Summary

| Type | Value |
|---|---|
| Ransomware Group | Akira |
| TOR Address | akira12iz6a7qgd3ayp316yub7xx2uep76idk3u2ko11pj5z3z636bad.onion |
| Victim ID | 813R-QWJM-XKIJ |
| Attacker IP | 88.97.164.155 |
| C2 Domain | cdn.cloud-endpoint.net |
| Payload Domain | sync.cloud-endpoint.net |
| C2 IPs | 104.21.30.237, 172.67.174.46 |
| AnyDesk Relay | relay-0b975d23.net.anydesk.com |
| Ransomware Binary | updater.exe |
| Ransomware Hash | e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b |
| C2 Beacon | wsync.exe |
| Beacon Hash (v1) | 66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b |
| Beacon Hash (v2) | 0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654 |
| Evasion Script | kill.bat |
| Evasion Script Hash | 0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c |
| Staging Tool | st.exe |
| Staging Tool Hash | 512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015 |
| Scanner Tool | scan.exe |
| Scanner Hash | 26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b |
| Exfil Archive | exfil_data.zip |
| Compromised User | david.mitchell |
| Lateral Movement Account | as.srv.administrator |
| Encrypted Extension | .akira |






























