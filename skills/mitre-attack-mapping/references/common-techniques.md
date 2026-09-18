# Frequently seen ATT&CK techniques: quick reference

Source: MITRE ATT&CK Enterprise, **v17 (April 2025)**, https://attack.mitre.org. Technique
IDs are stable across releases; names occasionally change and sub-techniques get added or
merged (noted below where it matters). If your team pins a different release in
`environment.md`, verify names against that release before publishing a mapping. This file
lists techniques that show up in the large majority of intrusions a SOC handles; it is a
starting point, not the whole framework (which has around 200 techniques and 400+
sub-techniques).

Columns: **Evidence** is the ATT&CK data source plus the concrete telemetry a mapper usually
cites (Windows Security event IDs, Sysmon event IDs, cloud audit logs). **Do not map
when** lists the benign look-alike that causes over-mapping.

Contents: Reconnaissance and Resource Development | Initial Access | Execution | Persistence
| Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement
| Collection | Command and Control | Exfiltration | Impact | Cloud-specific

## Reconnaissance (TA0043) and Resource Development (TA0042)

Usually mapped from threat intel, not from your own telemetry. Map these only when the
report states them; do not infer "they must have scanned us".

| ID | Name | Evidence | Do not map when |
|---|---|---|---|
| T1595.002 | Active Scanning: Vulnerability Scanning | Network Traffic; perimeter/WAF logs | Generic internet background noise; that is not an intrusion phase |
| T1598 | Phishing for Information | Email gateway; user reports | The email also delivered a payload (that is T1566) |
| T1583.001 | Acquire Infrastructure: Domains | Intel report, WHOIS/passive DNS | You only have the domain, not evidence the actor registered it |
| T1588.002 | Obtain Capabilities: Tool | Intel report | The tool is a built-in OS binary (that is not "obtaining") |
| T1608 | Stage Capabilities | Intel report; URL scanning | -- |

## Initial Access (TA0001)

| ID | Name | Evidence | Do not map when |
|---|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Email gateway attachment logs; user report; EDR parent-child (Outlook -> payload) | Attachment was benign; then it is spam, not phishing |
| T1566.002 | Phishing: Spearphishing Link | Email gateway URL rewrite/click logs; proxy | -- |
| T1566.004 | Phishing: Spearphishing Voice | Call records; user report (callback / TOAD lures) | -- |
| T1190 | Exploit Public-Facing Application | Web/WAF logs; appliance logs; unexpected child of web server process | A scanner probed and got a 404 |
| T1133 | External Remote Services | VPN / Citrix / RDP gateway logon logs (4624 type 10 on the gateway) | Employee's own VPN logon from their usual location |
| T1078.002 | Valid Accounts: Domain Accounts | 4624/4625 on the target; sign-in logs | You have not established the logon was by the adversary |
| T1078.004 | Valid Accounts: Cloud Accounts | Entra ID SigninLogs / Okta system log / CloudTrail ConsoleLogin | Same as above |
| T1189 | Drive-by Compromise | Proxy/browser history; EDR browser child processes | The user clicked a link in an email (that is T1566.002) |
| T1195 | Supply Chain Compromise | Vendor advisory; software inventory | -- |
| T1199 | Trusted Relationship | Partner VPN / MSP account activity | -- |
| T1091 | Replication Through Removable Media | Sysmon 1 with a removable drive parent path; USB device events | -- |

## Execution (TA0002)

| ID | Name | Evidence | Do not map when |
|---|---|---|---|
| T1059.001 | Command and Scripting Interpreter: PowerShell | 4104 script block; 4103; Sysmon 1 / 4688 with command line | Admin tooling (SCCM, Intune, monitoring agents) running signed scripts on schedule |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Sysmon 1 / 4688 | cmd.exe in general; map when the *adversary's* commands ran |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | auditd execve; EDR process events | -- |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | wscript/cscript child of Office; AMSI | -- |
| T1059.006 | Command and Scripting Interpreter: Python | Process events | Python is the app's runtime |
| T1059.007 | Command and Scripting Interpreter: JavaScript | wscript with .js; browser-adjacent process events | -- |
| T1204.001 | User Execution: Malicious Link | Proxy click; browser -> download -> execution chain | -- |
| T1204.002 | User Execution: Malicious File | explorer.exe / Outlook / archiver spawning the payload (Sysmon 1) | The file was executed by a scheduled task or another process, not a person |
| T1047 | Windows Management Instrumentation | WmiPrvSE.exe spawning processes (Sysmon 1); 5861 WMI-Activity | SCCM / monitoring agents that use WMI legitimately |
| T1053.005 | Scheduled Task/Job: Scheduled Task | 4698 (created), 4702 (updated); Sysmon 1 schtasks.exe | Installer- or GPO-created tasks |
| T1053.003 | Scheduled Task/Job: Cron | crontab file changes; auditd | -- |
| T1569.002 | System Services: Service Execution | 7045 (System log) / 4697 (Security) service install; services.exe children | -- |
| T1203 | Exploitation for Client Execution | Office / browser / reader spawning an unexpected child | The child is a legitimate helper (splwow64, updater) |
| T1106 | Native API | EDR API telemetry only | You are inferring it from "the malware must call APIs" |
| T1651 | Cloud Administration Command | AWS SSM SendCommand; Azure RunCommand; GCP OS Login audit | Routine automation from a known pipeline identity |

## Persistence (TA0003)

| ID | Name | Evidence | Do not map when |
|---|---|---|---|
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Sysmon 13 on `...\CurrentVersion\Run*`; Sysmon 11 in Startup folder | Installer writing its own updater key |
| T1053.005 | Scheduled Task/Job: Scheduled Task | 4698; task XML in `C:\Windows\System32\Tasks` | See above |
| T1543.003 | Create or Modify System Process: Windows Service | 7045; 4697; Sysmon 13 on `HKLM\SYSTEM\CurrentControlSet\Services` | Software installs |
| T1136.001 / .002 / .003 | Create Account: Local / Domain / Cloud Account | 4720; AuditLogs "Add user"; CloudTrail CreateUser | HR-driven provisioning via the IdP connector |
| T1505.003 | Server Software Component: Web Shell | w3wp.exe / httpd / tomcat spawning cmd or PowerShell; new files in webroot | -- |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | CloudTrail CreateAccessKey; AuditLogs "Add service principal credentials" | Key rotation by the owning team |
| T1098.003 | Account Manipulation: Additional Cloud Roles | AuditLogs "Add member to role"; CloudTrail AttachUserPolicy | Approved access request |
| T1098.005 | Account Manipulation: Device Registration | AuditLogs "Register device" / "Add registered owner" | Employee enrolling a new laptop through the normal flow |
| T1546.003 | Event Triggered Execution: Windows Management Instrumentation Event Subscription | Sysmon 19/20/21 | -- |
| T1574 | Hijack Execution Flow (DLL search-order hijacking, side-loading and similar) | Sysmon 7 image load of an unsigned DLL from an unusual path by a signed binary | The DLL is the vendor's own; sub-technique numbering under T1574 was restructured in v17, so cite the sub-technique from the release you pin |
| T1078 | Valid Accounts (as persistence) | Repeated logons with a compromised account after the initial entry | -- |
| T1133 | External Remote Services (as persistence) | New VPN certificate or account used across sessions | -- |
| T1197 | BITS Jobs | bitsadmin / PowerShell BITS cmdlets; Microsoft-Windows-Bits-Client log | Windows Update's own jobs |

## Privilege Escalation (TA0004)

| ID | Name | Evidence | Do not map when |
|---|---|---|---|
| T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | Sysmon 1 with known auto-elevate binaries spawning unexpected children; Sysmon 13 on `HKCU\Software\Classes\ms-settings` or `mscfile` | -- |
| T1068 | Exploitation for Privilege Escalation | Crash dumps; EDR exploit detections; sudden SYSTEM-level child of a user process | You only know a vulnerable driver *exists* on the host |
| T1055 | Process Injection | Sysmon 8 (CreateRemoteThread), Sysmon 10 (process access with write rights); EDR injection alerts | The injecting process is an EDR/AV/accessibility tool |
| T1134 | Access Token Manipulation | 4624 logon type 9; EDR | -- |
| T1078.003 | Valid Accounts: Local Accounts | 4624 with a local admin account | -- |

## Defense Evasion (TA0005)

| ID | Name | Evidence | Do not map when |
|---|---|---|---|
| T1027 | Obfuscated Files or Information | 4104 with encoded/obfuscated content; packed binaries (entropy) | Minified JavaScript in a web app; `-enc` used by a known admin tool |
| T1140 | Deobfuscate/Decode Files or Information | certutil -decode; PowerShell FromBase64String in 4104 | -- |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | 1102 (Security cleared), 104 (System cleared); wevtutil cl | Log rotation by policy |
| T1070.004 | Indicator Removal: File Deletion | Sysmon 23/26; del / rm of tooling right after use | Temp file cleanup by installers |
| T1562.001 | Impair Defenses: Disable or Modify Tools | EDR tamper alerts; Sysmon 13 on Defender keys; 5001 Defender RTP disabled | Change-managed exclusion added by the endpoint team |
| T1562.004 | Impair Defenses: Disable or Modify System Firewall | netsh advfirewall; 4946-4950 firewall rule changes | -- |
| T1036 | Masquerading | Process name/path mismatch (svchost outside System32); renamed tools; Sysmon 1 OriginalFileName != Image | -- |
| T1218.005 | System Binary Proxy Execution: Mshta | mshta.exe with a URL or script argument | -- |
| T1218.010 | System Binary Proxy Execution: Regsvr32 | regsvr32 /s /i:http... scrobj.dll | Legitimate COM registration by installers |
| T1218.011 | System Binary Proxy Execution: Rundll32 | rundll32 with an unusual DLL path or export | Hundreds of legitimate rundll32 invocations per day; map only the malicious one |
| T1112 | Modify Registry | Sysmon 12/13/14 | Almost everything modifies the registry; map only when the modification *was* the evasion |
| T1484 | Domain or Tenant Policy Modification | 5136/5137 on GPO objects; AuditLogs for tenant policy | -- |
| T1497 | Virtualization/Sandbox Evasion | Sandbox report; strings | -- |
| T1620 | Reflective Code Loading | EDR in-memory detections | -- |
| T1553 | Subvert Trust Controls | Certificate installs; 4657 on trust settings | -- |

## Credential Access (TA0006)

| ID | Name | Evidence | Do not map when |
|---|---|---|---|
| T1003.001 | OS Credential Dumping: LSASS Memory | Sysmon 10 on lsass.exe with 0x1010/0x1410/0x1fffff access; EDR credential theft alerts; comsvcs MiniDump | Access from known AV/EDR/backup processes |
| T1003.002 | OS Credential Dumping: Security Account Manager | reg save HKLM\SAM; 4656 on SAM hive | -- |
| T1003.003 | OS Credential Dumping: NTDS | ntdsutil / vssadmin on a DC; ntds.dit copied | Backup software that is expected to touch ntds.dit |
| T1003.006 | OS Credential Dumping: DCSync | 4662 with replication GUIDs (1131f6aa-..., 1131f6ad-...) from a non-DC account | The source *is* a domain controller or Entra Connect / AAD Connect account |
| T1110.001 | Brute Force: Password Guessing | Many 4625 / sign-in failures for one account | -- |
| T1110.003 | Brute Force: Password Spraying | Few failures each across many accounts from one source | Lockout storms from a misconfigured service account |
| T1110.004 | Brute Force: Credential Stuffing | Sign-in failures with leaked credential pairs from many IPs | -- |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | 4769 with RC4 (0x17) etype for SPN accounts, many in a burst | Legacy apps that still request RC4 tickets (baseline first) |
| T1558.004 | Steal or Forge Kerberos Tickets: AS-REP Roasting | 4768 with pre-auth disabled accounts, RC4 | -- |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Access to Login Data / Cookies SQLite files by non-browser processes | -- |
| T1056.001 | Input Capture: Keylogging | EDR; SetWindowsHookEx telemetry | -- |
| T1621 | Multi-Factor Authentication Request Generation | Many MFA prompts denied/timed out then one approved; Okta / Entra sign-in logs | -- |
| T1557 | Adversary-in-the-Middle | AiTM phishing proxy (sign-in from unfamiliar IP seconds after a phishing click, token replay); LLMNR/NBT-NS poisoning | -- |
| T1552.001 | Unsecured Credentials: Credentials In Files | findstr /si password; access to config files with secrets | -- |
| T1528 | Steal Application Access Token | Consent grants to unknown OAuth apps; token refresh from new IP | -- |
| T1539 | Steal Web Session Cookie | Browser cookie DB access; session reuse from a new IP/UA | -- |
| T1606.002 | Forge Web Credentials: SAML Tokens | SAML tokens with unusual lifetime or issuer; AD FS key export | -- |

## Discovery (TA0007)

Discovery commands are noisy and admins run them too. Map them when they occur in the
adversary's session; do not map every `whoami` in the estate.

| ID | Name | Evidence | Do not map when |
|---|---|---|---|
| T1082 | System Information Discovery | systeminfo, hostname, uname -a | -- |
| T1033 | System Owner/User Discovery | whoami, query user | -- |
| T1087.001 / .002 | Account Discovery: Local / Domain Account | net user, net user /domain, Get-ADUser, ldapsearch | -- |
| T1087.004 | Account Discovery: Cloud Account | CloudTrail ListUsers; Graph API /users enumeration | -- |
| T1069.002 | Permission Groups Discovery: Domain Groups | net group "domain admins" /domain | -- |
| T1018 | Remote System Discovery | net view, nltest /dclist, ping sweeps | -- |
| T1016 | System Network Configuration Discovery | ipconfig /all, arp -a, route print | -- |
| T1049 | System Network Connections Discovery | netstat -ano | -- |
| T1057 | Process Discovery | tasklist, Get-Process, ps | -- |
| T1046 | Network Service Discovery | Internal port scans (many SYNs from one host); Sysmon 3 fan-out | Vulnerability scanner hosts |
| T1482 | Domain Trust Discovery | nltest /domain_trusts; Get-ADTrust | -- |
| T1518.001 | Software Discovery: Security Software Discovery | Queries to Defender/EDR registry keys, WMI AntiVirusProduct | -- |
| T1201 | Password Policy Discovery | net accounts /domain | -- |
| T1526 | Cloud Service Discovery | CloudTrail Describe*/List* bursts; Azure Resource Graph queries | Inventory tooling |
| T1580 | Cloud Infrastructure Discovery | DescribeInstances, ListBuckets bursts from a new principal | Same |

## Lateral Movement (TA0008)

| ID | Name | Evidence | Do not map when |
|---|---|---|---|
| T1021.001 | Remote Services: Remote Desktop Protocol | 4624 type 10; 4778/4779; TerminalServices-RemoteConnectionManager 1149 | Helpdesk / admin jump-host RDP |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | 5140/5145 on ADMIN$ / C$; 7045 on the target (PsExec pattern) | Software deployment tools |
| T1021.004 | Remote Services: SSH | auth.log / sshd; 4624 on Windows OpenSSH | -- |
| T1021.006 | Remote Services: Windows Remote Management | 4624 type 3 with wsmprovhost.exe children; WinRM 5985/5986 | Config management (Ansible, DSC) |
| T1570 | Lateral Tool Transfer | Sysmon 11 file create over SMB; 5145 with write access | -- |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | 4624 type 9 / NTLM logons with LogonProcess seclogo; 4624 type 3 NTLM from a workstation | -- |
| T1550.003 | Use Alternate Authentication Material: Pass the Ticket | 4768/4769 anomalies; tickets for accounts that never logged on interactively | -- |
| T1550.004 | Use Alternate Authentication Material: Web Session Cookie | Cloud sign-in with the same session ID from a new IP/UA | -- |
| T1210 | Exploitation of Remote Services | EDR exploit alerts; crash of a service followed by new child | -- |
| T1534 | Internal Spearphishing | Mail from a compromised internal mailbox to colleagues | -- |

## Collection (TA0009)

| ID | Name | Evidence | Do not map when |
|---|---|---|---|
| T1005 | Data from Local System | File access telemetry; scripts enumerating user folders | -- |
| T1039 | Data from Network Shared Drive | 5145 mass reads; file server audit | Backup jobs |
| T1114.002 | Email Collection: Remote Email Collection | MailItemsAccessed; EWS/Graph bulk reads from a new client | -- |
| T1114.003 | Email Collection: Email Forwarding Rule | New-InboxRule / Set-Mailbox ForwardingSmtpAddress in unified audit log | The user created the rule themselves and can confirm it |
| T1560.001 | Archive Collected Data: Archive via Utility | 7z / WinRAR / tar with password flags; large archives in staging dirs | -- |
| T1074 | Data Staged | Large new archives under ProgramData, Temp, or a share | -- |
| T1113 | Screen Capture | EDR; screenshot-capable RATs | -- |
| T1213 | Data from Information Repositories | SharePoint / Confluence / Git bulk download audit | -- |
| T1530 | Data from Cloud Storage | S3 GetObject bursts; ListBucket then mass GetObject from a new principal | Application's own service role |

## Command and Control (TA0011)

| ID | Name | Evidence | Do not map when |
|---|---|---|---|
| T1071.001 | Application Layer Protocol: Web Protocols | Proxy logs: beaconing (fixed interval plus jitter), rare user agent, POST with no referrer | -- |
| T1071.004 | Application Layer Protocol: DNS | Sysmon 22 / DNS logs: long TXT queries, high entropy subdomains, high volume to one domain | -- |
| T1105 | Ingress Tool Transfer | Proxy download of executables; certutil -urlcache; Invoke-WebRequest; curl -o | Patch management downloads |
| T1219 | Remote Access Tools (named Remote Access Software before v17) | AnyDesk, ScreenConnect, Atera, TeamViewer installs or network signatures | The tool is the sanctioned helpdesk product (check environment.md) |
| T1572 | Protocol Tunneling | ngrok, chisel, plink, ssh -R; unusual outbound on 22/443 with long sessions | -- |
| T1090.003 | Proxy: Multi-hop Proxy | Tor exit nodes; residential proxy ASNs | -- |
| T1573 | Encrypted Channel | TLS to an IP with no SNI or self-signed cert; JA3/JA4 matches | Everything is TLS; map only with a distinguishing signal |
| T1132 | Data Encoding | Base64 in URIs / DNS labels | -- |
| T1568 | Dynamic Resolution | DGA-looking NXDOMAIN bursts; fast-flux | -- |
| T1102 | Web Service | C2 over Telegram, Discord, GitHub, Pastebin, cloud storage APIs | -- |
| T1571 | Non-Standard Port | HTTP on 8443/4444/etc; TLS on non-443 | Internal apps with documented ports |

## Exfiltration (TA0010)

| ID | Name | Evidence | Do not map when |
|---|---|---|---|
| T1041 | Exfiltration Over C2 Channel | Outbound byte volume on the beacon connection | -- |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | rclone / MEGAcmd; large uploads to mega, dropbox, s3 from a host that never did | Sanctioned backup to the corporate tenant |
| T1048.003 | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | FTP / raw TCP outbound with large volume | -- |
| T1030 | Data Transfer Size Limits | Many equal-sized chunks | -- |

## Impact (TA0040)

| ID | Name | Evidence | Do not map when |
|---|---|---|---|
| T1486 | Data Encrypted for Impact | Mass file renames with a new extension; ransom notes; Sysmon 11 bursts | Legitimate encryption tooling rollout |
| T1490 | Inhibit System Recovery | vssadmin delete shadows; wmic shadowcopy delete; bcdedit recoveryenabled no; wbadmin delete catalog | Storage admins reclaiming space (rare; verify) |
| T1489 | Service Stop | net stop / sc stop of backup, DB, AV services in a burst; 7036 | Patch windows |
| T1485 | Data Destruction | Mass deletes, disk wipes | -- |
| T1657 | Financial Theft | BEC payment diversion; fraudulent transfers | -- |
| T1491 | Defacement | Web content changes | -- |
| T1496 | Resource Hijacking | Cryptominer processes; cloud compute spikes | -- |
| T1499 / T1498 | Endpoint / Network Denial of Service | Availability alerts | -- |
| T1531 | Account Access Removal | Mass password resets / account deletes by one principal | IdP deprovisioning jobs |

## Cloud-specific reminders

Cloud intrusions are mapped with the same enterprise matrix; the platforms filter in the
Navigator layer (IaaS, SaaS, Office Suite, Identity Provider) narrows the view. The most
frequently seen cloud techniques are already in the tables above: T1078.004, T1098.001,
T1098.003, T1098.005, T1528, T1539, T1550.004, T1606.002, T1621, T1651, T1526, T1580,
T1530, T1567.002, T1114.003. `cloud-incident-investigation` and
`identity-threat-investigation` carry the log-level detail.
