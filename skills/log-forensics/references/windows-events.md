# Windows event IDs that matter in an investigation

Sources: Microsoft "Security auditing" documentation and Windows 10/11 and Server 2016-2025
event reference, as of 2026. Only IDs the authors are confident about are listed; verify the
exact message text against a live system before writing detections. Many of these require
the corresponding audit subcategory to be enabled (noted where it commonly is not).

## Contents
1. Security log: logon and session
2. Security log: account and group management
3. Security log: Kerberos and NTLM (domain controllers)
4. Security log: process, object, and policy
5. Security log: shares, firewall, and misc
6. System log
7. PowerShell logs
8. Task Scheduler, WMI, BITS, Terminal Services, Defender, AppLocker
9. Logon types and failure status codes
10. Collection notes and what disappears

## 1. Security log: logon and session

| ID | Meaning | Why it matters / fields to read |
|---|---|---|
| 4624 | Successful logon | `LogonType`, `TargetUserName`, `IpAddress`, `WorkstationName`, `AuthenticationPackageName`, `LogonProcessName`, `ElevatedToken`. Type 10 = RDP, 3 = network (SMB/RPC), 2 = console, 9 = `runas /netonly` or pass-the-hash tooling, 5 = service, 4 = batch/scheduled task, 7 = unlock, 11 = cached credentials (offline laptop) |
| 4625 | Failed logon | `Status`/`SubStatus` say why (section 9); bursts by user = spray/brute force; bursts by IP with many users = password spray |
| 4634 / 4647 | Logoff / user-initiated logoff | Session length; 4647 is interactive user logging off |
| 4648 | Logon with explicit credentials | "runas", scheduled tasks, lateral movement tools that specify credentials; `TargetServerName` shows where the credentials were used |
| 4672 | Special privileges assigned to new logon | Admin-equivalent logon (SeDebugPrivilege, SeBackupPrivilege, SeTcbPrivilege). Pair with the 4624 of the same `LogonId` |
| 4778 / 4779 | RDP session reconnected / disconnected | Reconnection to an existing session; `ClientAddress` |
| 4800 / 4801 | Workstation locked / unlocked | Physical presence timeline |
| 4964 | Special groups assigned to a new logon | Only if "special groups" auditing configured |

## 2. Security log: account and group management

| ID | Meaning | Why it matters |
|---|---|---|
| 4720 | User account created | New local/domain user; check who (`SubjectUserName`) and when |
| 4722 / 4725 / 4726 | Account enabled / disabled / deleted | Re-enabling a dormant account is a classic |
| 4723 / 4724 | Password change attempt (by user) / password reset (by admin) | Reset of a privileged account by an unexpected admin |
| 4738 | User account changed | Attribute changes including `UserAccountControl` (e.g. "Don't require preauth" enables AS-REP roasting) |
| 4740 / 4767 | Account locked out / unlocked | Lockouts near a spray; `CallerComputerName` |
| 4728 / 4732 / 4756 | Member added to global / local / universal security group | Adds to Administrators, Domain Admins, Remote Desktop Users, DnsAdmins |
| 4729 / 4733 / 4757 | Member removed from those groups | Cleanup after use |
| 4741 / 4742 / 4743 | Computer account created / changed / deleted | Rogue machine accounts (RBCD abuse) |
| 4794 | Attempt to set DSRM administrator password | DC persistence |
| 4798 / 4799 | User's local group membership enumerated / security-enabled local group membership enumerated | Discovery by tools (`net localgroup`, BloodHound collectors); noisy but useful with `CallerProcessName` |

## 3. Security log: Kerberos and NTLM (read on domain controllers)

| ID | Meaning | Why it matters |
|---|---|---|
| 4768 | Kerberos TGT requested | Authentication source IP for a domain account; `PreAuthType`, `TicketEncryptionType` (0x17 = RC4 = weak or forced), failure codes (0x6 unknown user, 0x12 disabled/locked, 0x18 bad password) |
| 4769 | Kerberos service ticket requested | `ServiceName`, `TicketEncryptionType 0x17` with many different SPNs from one user in seconds = Kerberoasting; `ServiceName` of `krbtgt` with unusual options |
| 4770 | TGT renewed | Long-lived sessions |
| 4771 | Kerberos pre-authentication failed | Failed password for domain accounts (0x18) |
| 4776 | NTLM credential validation (DC or local SAM) | NTLM use where Kerberos is expected; `Workstation` field; failures with 0xC000006A |
| 4662 | Operation performed on an AD object | With `Properties` containing the replication GUIDs `1131f6aa-...` / `1131f6ad-...` (DS-Replication-Get-Changes[-All]) from a non-DC account = DCSync. Requires DS Access auditing |
| 5136 / 5137 / 5141 | Directory object modified / created / deleted | GPO changes, SPN additions, `msDS-AllowedToActOnBehalfOfOtherIdentity`, AdminSDHolder edits |
| 4713 / 4716 / 4739 | Kerberos policy / trust / domain policy changed | Rare and high-value |

## 4. Security log: process, object, and policy

| ID | Meaning | Why it matters |
|---|---|---|
| 4688 | New process created | The backbone. Needs "Audit Process Creation" **and** the policy "Include command line in process creation events" for `CommandLine`; `ParentProcessName` on 2012R2+/10+; `TokenElevationType`, `MandatoryLabel` |
| 4689 | Process exited | Duration of a process |
| 4696 | Primary token assigned to process | Token manipulation |
| 4697 | Service installed (Security log) | Same event as System 7045 but with the subject; needs "Audit Security System Extension" |
| 4698 / 4699 / 4700 / 4701 / 4702 | Scheduled task created / deleted / enabled / disabled / updated | Persistence; the XML content is in the event. Needs "Audit Other Object Access Events" |
| 4703 | Token right adjusted | Privilege enable, noisy on modern Windows |
| 4704 / 4705 | User right assigned / removed | `SeDebugPrivilege` etc. granted to a user |
| 4719 | System audit policy changed | Attacker turning off auditing; also GPO refreshes |
| 4657 | Registry value modified | Only for keys with SACLs; Run keys if you configured it |
| 4663 | Attempt to access an object | File/registry access for SACL'ed objects (e.g. `NTDS.dit`, `SAM`, LSASS with 4656) |
| 4656 / 4658 / 4660 / 4670 | Handle requested / closed / object deleted / permissions changed | Object access chain; 4670 on sensitive files/keys |
| 4674 | Operation attempted on a privileged object | Sensitive privilege use |
| 4907 | Auditing settings on object changed | SACL tampering |
| 1102 | Audit log cleared | Always a finding. `SubjectUserName` is who did it |
| 1100 | Event logging service shut down | Normal at shutdown; suspicious mid-day |
| 4616 | System time changed | Timestomping the clock; also NTP corrections (check `PreviousTime`/`NewTime` delta) |

## 5. Security log: shares, firewall, and misc

| ID | Meaning | Why it matters |
|---|---|---|
| 5140 | Network share object accessed | Lateral movement to `ADMIN$`, `C$`, `IPC$`; `IpAddress`, `ShareName`. Needs "Audit File Share" |
| 5145 | Network share object checked (detailed) | Per-file access on shares; very noisy; `RelativeTargetName` shows the file (e.g. `PSEXESVC.exe` written to `ADMIN$`) |
| 5142 / 5143 / 5144 | Share added / modified / deleted | New shares for staging |
| 5156 / 5157 | WFP permitted / blocked a connection | Host-based network log when Sysmon is absent; `Application`, `DestAddress`, `DestPort`. Extremely noisy; filter by process |
| 5158 / 5159 | WFP permitted / blocked a bind | Listening ports opened by malware |
| 4946 / 4947 / 4948 | Firewall rule added / modified / deleted | Attackers opening ports |
| 5025 / 5027 | Firewall service stopped / could not retrieve policy | Tampering |
| 6416 | New external device recognized | USB usage |
| 4618 | Monitored security event pattern occurred | Only if configured |
| 4649 | Replay attack detected | Kerberos replay; rare |

## 6. System log

| ID | Source | Meaning | Why it matters |
|---|---|---|---|
| 7045 | Service Control Manager | New service installed | `ServiceName`, `ImagePath`, `ServiceType`, `StartType`, account. PsExec (`PSEXESVC`), remote-exec tools, and malware persistence all land here |
| 7034 | SCM | Service crashed unexpectedly | LSASS-adjacent crashes, AV crashing |
| 7036 | SCM | Service entered running/stopped state | Timing of Defender, EventLog, backup services stopping |
| 7040 | SCM | Service start type changed | Disabling Defender/EventLog/Windows Update |
| 7023 / 7024 | SCM | Service terminated with error | |
| 104 | Microsoft-Windows-Eventlog | Log file cleared (System/Application/others) | The System-side twin of 1102 |
| 6005 / 6006 | EventLog | Event log service started / stopped | Boot/shutdown markers; a 6006 with no shutdown = log service killed |
| 6008 | EventLog | Previous shutdown was unexpected | Crash or power pull |
| 1074 | User32 | Shutdown/restart initiated | Who and which process (`shutdown.exe`, `msiexec`, ransomware) |
| 12 / 13 | Kernel-General | System started / shutting down | Boot timeline |
| 41 | Kernel-Power | Rebooted without clean shutdown | |
| 1 | Kernel-General | System time changed | Timestomp/NTP |
| 219 | Kernel-PnP | Driver load failure | Sometimes rogue driver attempts |
| 7 / 11 / 51 | Disk | Disk errors | Wipers and destructive activity |
| 20001 / 20003 | UserPnp | Device install | USB/removable media |

## 7. PowerShell logs

| Log | ID | Meaning | Why it matters |
|---|---|---|---|
| Microsoft-Windows-PowerShell/Operational | 4104 | Script block logging: the de-obfuscated script text | The best source for PowerShell attacks; enabled by policy (some suspicious blocks logged even without it). Long scripts split across many 4104s with the same `ScriptBlockId` |
| same | 4103 | Module logging: pipeline execution with parameters | Command and parameter values |
| same | 4105 / 4106 | Script block start / stop | Verbose, usually off |
| same | 53504 | PowerShell named pipe created for remoting | |
| Windows PowerShell (classic) | 400 / 403 | Engine started / stopped | `HostApplication` shows the full command line that launched PowerShell, including `-enc` payloads, even without script block logging |
| same | 600 | Provider started | Also shows `HostApplication` |
| same | 800 | Pipeline execution details | If module logging on |
| PowerShellCore/Operational | 4104 / 4103 | Same for PowerShell 7 | Often forgotten |
| Microsoft-Windows-WinRM/Operational | 6 / 91 / 168 / 169 | WinRM session created / request received / auth | PowerShell remoting lateral movement |

## 8. Other operational logs

| Log | ID | Meaning |
|---|---|---|
| Microsoft-Windows-TaskScheduler/Operational | 106 task registered, 140 task updated, 141 task deleted, 200 action started, 201 action completed, 129 task process launched | Persistence and execution; log is off by default on some builds |
| Microsoft-Windows-WMI-Activity/Operational | 5857 provider loaded, 5858 query error (shows the WQL query and client), 5859 permanent event consumer started, 5860 temporary consumer, 5861 permanent binding created (filter + consumer XML) | 5861 = WMI persistence |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | 21 session logon succeeded, 22 shell start, 23 logoff, 24 disconnected, 25 reconnected, 39/40 disconnected by another session | RDP session timeline with source IP, even when Security auditing is thin |
| Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational | 1149 user authentication succeeded (network-level auth; before the session) | First sign of RDP from an IP |
| Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational | 131 connection accepted, 98 TLS handshake, 140 failed logon (IP only) | RDP brute force source IPs |
| Microsoft-Windows-Bits-Client/Operational | 3 job created, 59 job started (URL), 60 job stopped, 4 job completed | BITS downloads (`bitsadmin`, `Start-BitsTransfer`) |
| Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | 2004 rule added, 2005 modified, 2006 deleted, 2033 all rules deleted | |
| Microsoft-Windows-Windows Defender/Operational | 1116 malware detected, 1117 action taken, 1118/1119 action failed, 1006/1007 (older), 5001 real-time protection disabled, 5004 configuration changed, 5007 configuration changed (exclusions appear here), 5010/5012 scanning disabled, 1121 ASR rule blocked, 1122 ASR audited | Detections and tampering |
| Microsoft-Windows-AppLocker/EXE and DLL, /MSI and Script, /Packaged app | 8002 allowed, 8003 audited (would block), 8004 blocked (EXE/DLL); 8005/8006/8007 same for scripts and MSI | Application control |
| Microsoft-Windows-CodeIntegrity/Operational | 3033 / 3077 blocked image | WDAC |
| Microsoft-Windows-Sysmon/Operational | see `sysmon.md` | |
| Microsoft-Windows-Security-Mitigations/KernelMode, /UserMode | exploit protection blocks | |
| Microsoft-Windows-DNS-Client/Operational | 3006 / 3008 / 3020 query | Client-side DNS if enabled (Sysmon 22 is better) |
| Microsoft-Windows-NetworkProfile/Operational | 10000 / 10001 network connected/disconnected | Laptop location timeline |
| Microsoft-Windows-Shell-Core/Operational | 9707 / 9708 Run/RunOnce entry executed | Startup items running |
| Microsoft-Windows-Diagnostics-Performance | 100 boot time | |
| Setup | 1 - 4 update install | Patch timeline |
| Application | 1000 / 1001 application crash / WER, 1033/1034 MSI installed/removed, 11707 / 11724 MSI install success / uninstall | Installer activity and crashes |
| Microsoft-Windows-LSA/Operational, Security 4610/4611/4614/4622 | Authentication package / security package loaded | Rogue SSP/credential provider |
| Security 4610 / 4697 / System 7045 for `LSA` protection changes | | |

## 9. Logon types and failure codes

Logon types (4624/4625 `LogonType`): 2 Interactive (console), 3 Network (SMB, RPC, WinRM
without CredSSP, IIS), 4 Batch (scheduled task), 5 Service, 7 Unlock, 8 NetworkCleartext (IIS
basic auth), 9 NewCredentials (`runas /netonly`, overpass-the-hash tooling), 10
RemoteInteractive (RDP, RemoteApp, and some VNC), 11 CachedInteractive (domain logon with
cached creds, no DC reachable), 12 CachedRemoteInteractive, 13 CachedUnlock.

4625 / 4776 status codes: `0xC000006D` bad username or password (see SubStatus),
`0xC000006A` wrong password, `0xC0000064` user does not exist, `0xC0000234` locked out,
`0xC0000072` account disabled, `0xC000006F` outside allowed hours, `0xC0000070` workstation
restriction, `0xC0000193` account expired, `0xC0000071` password expired, `0xC000015B` logon
type not granted, `0xC0000224` password must change, `0xC000018C` trust relationship failed,
`0xC0000133` clock skew, `0xC0000413` authentication firewall.

4768/4771/4769 Kerberos result codes: `0x6` client not found (unknown user), `0x7` server not
found (bad SPN), `0xC` policy (time/workstation), `0x12` client revoked (disabled/locked),
`0x17` password expired, `0x18` pre-auth failed (bad password), `0x19` additional pre-auth
required (normal first request), `0x1F` integrity check failed, `0x20` ticket expired,
`0x25` clock skew, `0x3E` KDC does not support the encryption type.

## 10. Collection notes and what disappears

- Live export: `wevtutil epl Security C:\evidence\Security.evtx` (native EVTX keeps everything);
  `Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=...} | Export-Csv` for a quick
  CSV (local time, no zone: record the host's zone). `-Oldest` returns chronological order.
- Retention: default Security log is 20 MB on workstations, often wrapping within hours on
  servers and DCs. Grab it first. If it has wrapped, check the SIEM/forwarder (WEF/WEC), EDR
  timeline, and Volume Shadow Copies of `C:\Windows\System32\winevt\Logs`.
- Registry hives (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`, `UsrClass.dat`),
  `$MFT`, `$UsnJrnl`, `$LogFile`, Prefetch (`C:\Windows\Prefetch`), Amcache (`Amcache.hve`),
  ShimCache (in `SYSTEM`), SRUM (`SRUDB.dat`, network/process usage per hour), scheduled task
  XML (`C:\Windows\System32\Tasks`), WMI repository (`OBJECTS.DATA`), PowerShell history
  (`%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`), RDP bitmap
  cache, LNK/Jump Lists, browser history: all worth collecting with a triage tool (KAPE,
  Velociraptor) before reimaging.
- Time: EVTX stores UTC internally; every viewer renders local. `TimeCreated` in exports is
  local unless you asked for UTC. Note the host's zone and DST state on the custody line.
