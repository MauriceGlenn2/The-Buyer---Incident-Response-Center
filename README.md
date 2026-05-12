<img width="705" height="726" alt="image" src="https://github.com/user-attachments/assets/c5465d56-5daf-4a3c-9178-efcd794c8ecf" />

# The-Buyer---Incident-Response-Center(Cont Of "The Broker" Threat Hunt) (WIP)

The Buyer - Incident Response Centre 

SECTION 1: RANSOM NOTE ANALYSIS [Moderate] 
🚩 Q1 - Threat Actor 
Identify the ransomware group from the ransom note.
Format: Group name
What ransomware group is responsible?*akira

🚩 Q2 - Negotiation Portal 
The ransom note provides a contact method.
Format: onion address (without http://)
What is the TOR negotiation address?
*http://akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion 
🚩 Q3 - Victim ID
Each victim receives a unique identifier for negotiations.
Format: ID string
What is the company's unique ID?*813R-QWJM-XKIJ
🚩 Q4 - Encrypted Extension
Encrypted files have a new extension appended.
Format: Extension
What file extension is added to encrypted files?*.akira
SECTION 2: INFRASTRUCTURE [Moderate] 
🚩 Q5 - Payload Domain
Tools were downloaded from an external domain.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-03-01T00:00:00))
| where DeviceName == "as-pc2"
| where ProcessCommandLine has_any ("curl", "Invoke-WebRequest", "certutil")
What domain hosted the payloads?*sync.cloud-endpoint.net 2026-01-15T04:52:22.9618142Z
🚩  Q6 - Ransomware Staging
The payload established outbound connections.
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated,ActionType,InitiatingProcessFileName, RemoteUrl
What domain staged the ransomware?*cdn.cloud-endpoint.net
🚩 Q7 - C2 IP Addresses
The C2 infrastructure resolved to multiple IPs.
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated,ActionType,InitiatingProcessFileName, RemoteUrl, RemoteIP
What are the two C2 IP addresses?*104.21.30.237, 172.67.174.46
🚩 Q8 - Remote Tool Relay
A  Remote Tool route through relay servers.
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv") 
| where RemoteUrl contains "anydesk"
| project TimeGenerated, DeviceName, ActionType,InitiatingProcessFileName, RemoteUrl, RemoteIP
What is the remote tool relay domain the was used?*relay-0b975d23.net.anydesk.com 2026-01-27T22:08:15.8349181Z as-srv
SECTION 3: DEFENSE EVASION [Hard] 
🚩Q9 - Evasion Script
A script was used to disable security controls.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv") 
| where FileName =~ "reg.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, FileName


What script disabled security?*kill.bat cmd.exe /c ""C:\ProgramData\kill.bat"" as-pc2 2026-01-27T21:06:58.2839839Z
🚩 Q10 - Evasion Hash
Identify the hash of the evasion script.
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv") 
| where FileName contains "kill.bat"
| project TimeGenerated, FileName, SHA256
What is the SHA256 of the script?
*0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c kill.bat as-pc2
🚩 Q11 - Registry Tampering
Windows Defender was disabled via registry modification.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv") 
| where FileName =~ "reg.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, FileName, SHA256
What registry value disabled Windows Defender?*DisableAntiSpyware


🚩 Q12 - Registry Timestamp
Determine when the registry was modified.
DeviceRegistryEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc2")
| where ActionType == "RegistryValueSet"
| where RegistryKey contains "Windows Defender"
| project TimeGenerated, InitiatingProcessCommandLine


What time was the registry modified?
*2026-01-27T21:03:42.39698Z
SECTION 4: CREDENTIAL ACCESS [Advanced] 





























