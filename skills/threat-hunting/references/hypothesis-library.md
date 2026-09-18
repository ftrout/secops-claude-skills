# Hypothesis library

Concrete, testable hunt hypotheses organized by ATT&CK tactic. Each row names the
technique, the data source that can answer it, the analysis technique that usually works,
and what the benign population looks like so the hunter knows when to stop. Technique IDs
follow MITRE ATT&CK Enterprise v17 (April 2025); IDs are stable across recent versions
but verify sub-technique names against the current release before publishing a report.

A hypothesis is testable when it names a behaviour, a data source, and a population. "An
attacker may be persisting" is not a hypothesis; "an attacker has registered a scheduled
task on a workstation that runs from a user-writable directory" is.

Analysis technique key: **stack** = count values and read the long tail (`scripts/stack.py`);
**prevalence** = distinct hosts/users per value; **baseline** = compare to a prior window;
**sequence** = ordered events within a window; **outlier** = numeric deviation (bytes,
duration, hour of day); **enrich** = join to an external attribute (age of domain, ASN,
signer).

## Contents

- [Initial Access](#initial-access-ta0001)
- [Execution](#execution-ta0002)
- [Persistence](#persistence-ta0003)
- [Privilege Escalation](#privilege-escalation-ta0004)
- [Defense Evasion](#defense-evasion-ta0005)
- [Credential Access](#credential-access-ta0006)
- [Discovery](#discovery-ta0007)
- [Lateral Movement](#lateral-movement-ta0008)
- [Collection](#collection-ta0009)
- [Command and Control](#command-and-control-ta0011)
- [Exfiltration](#exfiltration-ta0010)
- [Impact](#impact-ta0040)
- [Identity and cloud](#identity-and-cloud-cross-tactic)

## Initial Access (TA0001)

| ID | Hypothesis | Technique | Data source | Analysis | Benign population |
|---|---|---|---|---|---|
| IA-1 | An Office application on a workstation has spawned a shell or script interpreter after opening an attachment | T1566.001 Spearphishing Attachment, T1204.002 Malicious File | process creation (parent/child) | stack parent+child, prevalence | Add-ins and macros used by finance/HR; usually a handful of known hosts |
| IA-2 | A user clicked a link in email that resolved to a domain registered in the last 30 days | T1566.002 Spearphishing Link | email URL click logs, proxy, WHOIS/RDAP enrichment | enrich (domain age), stack by domain | Marketing/SaaS trial domains; low volume |
| IA-3 | An internet-facing web server has spawned a process other than its normal worker (web shell) | T1190 Exploit Public-Facing Application, T1505.003 Web Shell | process creation on DMZ hosts | stack child of w3wp/httpd/nginx/php-fpm, prevalence | Deploy scripts, health checks; enumerate and allow-list |
| IA-4 | A VPN or Citrix account authenticated from a country or ASN it has never used before | T1133 External Remote Services, T1078 Valid Accounts | VPN/gateway auth logs | baseline per user (first-seen country/ASN) | Travel, mobile carriers; confirm with the user |
| IA-5 | A removable-media or ISO-mounted file was executed on a workstation | T1091 Replication Through Removable Media, T1204.002 | process creation with image path on D:/E: or mounted ISO paths | stack by drive letter/path prefix | Field engineers, imaging teams |

## Execution (TA0002)

| ID | Hypothesis | Technique | Data source | Analysis | Benign population |
|---|---|---|---|---|---|
| EX-1 | PowerShell has run with an encoded command, hidden window, or download cradle on a non-admin workstation | T1059.001 PowerShell | process creation, PowerShell 4104 script block | stack cmdline tokens (`-enc`, `-w hidden`, `downloadstring`, `iex`), prevalence | Management tooling (SCCM, Intune, RMM) runs encoded commands from known parents |
| EX-2 | A signed Windows utility that can proxy execution (rundll32, regsvr32, mshta, msiexec) was launched with a URL or an unusual path argument | T1218.011 / .010 / .005 / .007 System Binary Proxy Execution | process creation | stack utility + argument pattern, prevalence | Installers and some AV products use msiexec/regsvr32 with local paths |
| EX-3 | WMI or WinRM was used to start a process on a host from another host | T1047 WMI, T1021.006 WinRM | process creation (parent wmiprvse.exe / wsmprovhost.exe), 4688 | stack child of wmiprvse/wsmprovhost by source host | SCCM, monitoring agents, admin scripts from jump hosts |
| EX-4 | A scheduled task or service ran a binary from a user-writable directory | T1053.005 Scheduled Task, T1569.002 Service Execution | process creation (parent taskeng/svchost -k schedule, services.exe), 4698/7045 | stack image path prefix, prevalence | Updaters in %LOCALAPPDATA% (Teams, OneDrive, browsers) are the big benign set |
| EX-5 | A script interpreter (wscript, cscript, python, node) ran a file from Downloads, Temp, or a mail attachment cache | T1059.005 VBScript, T1059.007 JavaScript, T1059.006 Python | process creation | stack interpreter + path prefix | Developer workstations; scope by department |

## Persistence (TA0003)

| ID | Hypothesis | Technique | Data source | Analysis | Benign population |
|---|---|---|---|---|---|
| PE-1 | A Run/RunOnce key or Startup folder entry points at a path outside Program Files/Windows | T1547.001 Registry Run Keys / Startup Folder | registry set events (Sysmon 13), file creation in Startup | stack value data path prefix, prevalence across fleet | Chat clients, cloud sync agents, vendor updaters; build an allow-list once |
| PE-2 | A scheduled task was created whose action is a script or an executable in Temp/AppData/ProgramData | T1053.005 | 4698, Sysmon 1 (schtasks /create), task XML | stack task action path, prevalence | Installer-created update tasks; correlate with install events |
| PE-3 | A new service was installed with an unusual binary path or by a non-deployment account | T1543.003 Windows Service | 7045, 4697 | stack service image path and installing account, baseline new names | Software deployment windows; patch Tuesday spikes |
| PE-4 | A WMI event subscription (filter + consumer + binding) exists on a workstation | T1546.003 WMI Event Subscription | Sysmon 19/20/21, WMI repository query | stack consumer command; anything on workstations is rare | SCCM client and some monitoring use WMI subscriptions on servers |
| PE-5 | A local administrator account was created outside the provisioning process | T1136.001 Create Account: Local | 4720, 4732 | stack creator account and host, baseline | Help desk imaging, lab machines |
| PE-6 | A cron job, systemd unit, or shell profile on a Linux host was modified to launch something from /tmp, /dev/shm, or a home directory | T1053.003 Cron, T1543.002 Systemd Service, T1546.004 Unix Shell Configuration Modification | auditd/EDR file modification on cron/systemd/profile paths | stack modified path + writing process, prevalence | Config management (Ansible, Puppet) runs; correlate with change windows |
| PE-7 | An SSH authorized_keys file gained a key not managed by the key-management process | T1098.004 SSH Authorized Keys | file modification, auditd, key inventory | baseline (diff against inventory) | Manual admin onboarding; should be rare and ticketed |
| PE-8 | A mailbox has a new inbox rule that forwards externally, deletes, or moves messages with keywords like "invoice" or "password" | T1114.003 Email Forwarding Rule, T1564.008 Email Hiding Rules | M365 UAL New-InboxRule / Set-InboxRule, Exchange transport rules | stack rule action + destination domain | Users forwarding to personal mail (policy issue), assistants managing executive inboxes |

## Privilege Escalation (TA0004)

| ID | Hypothesis | Technique | Data source | Analysis | Benign population |
|---|---|---|---|---|---|
| PR-1 | A process running as a standard user spawned a child running as SYSTEM or a high-integrity process without a UAC prompt | T1548.002 Bypass User Account Control, T1068 Exploitation for Privilege Escalation | process creation with integrity level, 4688 with token elevation | stack parent (medium) to child (high/system) pairs | Consent.exe, installers, service control from admin tools |
| PR-2 | A user was added to a privileged group (Domain Admins, Enterprise Admins, local Administrators on servers) outside a change window | T1078.002 Domain Accounts, T1098 Account Manipulation | 4728/4732/4756, Entra ID role assignment audit | baseline by day/hour, stack actor | PAM/JIT tooling adds and removes on schedule; exclude its service account explicitly |
| PR-3 | A Group Policy Object was modified to add a scheduled task, script, or service on many hosts | T1484.001 Group Policy Modification | 5136/5145 on SYSVOL, GPO version changes | stack GPO name + editor, baseline | GPO admins on known accounts; weekly cadence |

## Defense Evasion (TA0005)

| ID | Hypothesis | Technique | Data source | Analysis | Benign population |
|---|---|---|---|---|---|
| DE-1 | A Windows event log was cleared or the audit policy changed on a server | T1070.001 Clear Windows Event Logs, T1562.002 Disable Windows Event Logging | 1102, 104, 4719 | stack host + actor; any on production servers is interesting | Imaging, log rotation scripts on a few hosts |
| DE-2 | EDR, AV, or firewall was disabled, excluded, or uninstalled on an endpoint | T1562.001 Disable or Modify Tools, T1562.004 Disable or Modify System Firewall | EDR tamper events, 5001 (Defender), registry exclusions path, netsh advfirewall in cmdline | stack actor + host, prevalence of exclusion paths | Developers adding build-directory exclusions; document them |
| DE-3 | A system binary is running from a non-standard path or under a different name (masquerading) | T1036.005 Match Legitimate Name or Location, T1036.003 Rename System Utilities | process creation with OriginalFileName / signer vs image name | stack OriginalFileName where name differs, prevalence | Portable admin tools, vendor-repackaged binaries |
| DE-4 | Files under Windows\Temp, ProgramData, or Public have timestamps older than the directory itself or than the creating process (timestomping) | T1070.006 Timestomp | Sysmon 2 (file creation time changed), forensic timeline | stack changer process; any is rare | Archive extraction (7-Zip preserves times), sync clients |
| DE-5 | A process injected into or accessed the memory of another process (LSASS excluded, see CA-1) from an unsigned image | T1055 Process Injection | Sysmon 8/10, EDR injection telemetry | stack source image + target, prevalence | AV, accessibility tools, some game/DRM software |
| DE-6 | A cloud audit trail, flow log, or diagnostic setting was stopped, deleted, or narrowed | T1562.008 Impair Defenses: Disable or Modify Cloud Logs | CloudTrail StopLogging/DeleteTrail/UpdateTrail, Azure diagnostic setting delete, GCP sink delete | stack actor identity; any is rare | IaC pipelines recreating resources; correlate with deploy events |
| DE-7 | A Mark-of-the-Web was stripped, or an archive/ISO delivered a file that then executed without a zone identifier | T1553.005 Subvert Trust Controls: Mark-of-the-Web Bypass | Sysmon 15 (ADS creation), process creation from mounted ISO/VHD paths | stack container type + child process | Software distribution via ISO in some IT teams |

## Credential Access (TA0006)

| ID | Hypothesis | Technique | Data source | Analysis | Benign population |
|---|---|---|---|---|---|
| CA-1 | A process other than known security tools opened a handle to LSASS with read access | T1003.001 OS Credential Dumping: LSASS Memory | Sysmon 10 (TargetImage lsass.exe), EDR credential-access alerts | stack source image + signer, prevalence | AV/EDR, some backup/monitoring agents; allow-list by signer and path |
| CA-2 | An account requested many Kerberos service tickets with RC4 encryption in a short window (Kerberoasting) | T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting | 4769 (TicketEncryptionType 0x17, many distinct services per account) | outlier: distinct SPNs per account per hour, baseline | Vulnerability scanners with domain creds, monitoring accounts |
| CA-3 | A non-domain-controller host requested directory replication (DCSync) | T1003.006 DCSync | 4662 with replication GUIDs (1131f6aa-..., 1131f6ad-...) from non-DC accounts | stack requesting account/host; any is rare | Entra Connect / AD sync service accounts, backup software with replication rights |
| CA-4 | Many accounts saw a single failed logon each from one source in a short window (password spray) | T1110.003 Password Spraying | 4625/4771, IdP sign-in failures, VPN auth | outlier: distinct users per source IP per window | Misconfigured service with a stale password, load balancers hiding the source |
| CA-5 | A process read browser credential stores, password vault files, or cloud CLI credential files | T1555.003 Credentials from Web Browsers, T1552.001 Credentials In Files | EDR file access, Sysmon 11 (copies), cmdline referencing `Login Data`, `.aws/credentials`, `.kube/config` | stack accessing process, prevalence | Browser itself, backup agents, developer tooling |
| CA-6 | A workload queried the cloud instance metadata service for credentials from an unexpected process or with an unexpected user agent | T1552.005 Cloud Instance Metadata API | VPC flow / host firewall to 169.254.169.254, IMDS access logs, CloudTrail user agents | stack process/user agent per instance role | SDKs and agents on every instance; IMDSv1 calls from curl/python are the interesting subset |
| CA-7 | An AS-REP was returned for an account without pre-authentication | T1558.004 AS-REP Roasting | 4768 with PreAuthType 0 | stack account; the list should be tiny and known | Legacy service accounts deliberately configured that way |

## Discovery (TA0007)

| ID | Hypothesis | Technique | Data source | Analysis | Benign population |
|---|---|---|---|---|---|
| DI-1 | A user account ran several reconnaissance commands (whoami, net group, nltest, dsquery, quser) within minutes on one host | T1087.002 Domain Account Discovery, T1482 Domain Trust Discovery, T1033 System Owner/User Discovery | process creation | sequence: distinct discovery binaries per host per 10 minutes | Admin troubleshooting, login scripts; exclude script parents |
| DI-2 | A host scanned many internal addresses or ports in a short window | T1046 Network Service Discovery, T1018 Remote System Discovery | firewall/NetFlow, EDR network events | outlier: distinct destinations per source per 5 minutes | Vulnerability scanners, monitoring, SCCM discovery; allow-list their sources |
| DI-3 | LDAP queries enumerating all users, groups, or SPNs came from a workstation | T1087.002, T1069.002 Domain Groups | LDAP query logs (Defender for Identity, DC 1644 events), DeviceEvents LdapSearch | stack query filter + source host, prevalence | Outlook address book, some helpdesk tools |
| DI-4 | A cloud identity enumerated IAM permissions, roles, buckets, or secrets across the account | T1580 Cloud Infrastructure Discovery, T1087.004 Cloud Account, T1526 Cloud Service Discovery | CloudTrail List*/Describe*/Get* bursts, Azure Graph queries, GCP list calls | outlier: distinct read-only API calls per identity per hour, baseline | CSPM scanners, Terraform plans, cost tools; exclude their roles |
| DI-5 | Security software discovery commands (tasklist, sc query, Get-MpPreference, wmic product) ran on a workstation | T1518.001 Security Software Discovery | process creation, 4104 | stack cmdline, prevalence | Inventory agents; usually one parent |

## Lateral Movement (TA0008)

| ID | Hypothesis | Technique | Data source | Analysis | Benign population |
|---|---|---|---|---|---|
| LM-1 | A workstation initiated RDP, SMB admin-share, or WinRM connections to other workstations | T1021.001 RDP, T1021.002 SMB/Windows Admin Shares, T1021.006 WinRM | network events by port (3389/445/5985), 4624 type 3/10 with workstation source | stack source-to-destination pairs where both are workstations | Helpdesk remote assistance, peer-to-peer patching (Delivery Optimization uses 7680, not SMB) |
| LM-2 | A service was created remotely (PsExec-style) with a random-looking name or a binary in ADMIN$ | T1021.002, T1569.002 Service Execution | 7045 with `\\` paths or short random names, 5145 on ADMIN$ | stack service name entropy + source, prevalence | Deployment tools (PDQ, SCCM) with fixed names |
| LM-3 | An account authenticated to more distinct hosts in a day than its baseline | T1078 Valid Accounts, T1021 | 4624, IdP logs | outlier: distinct destination hosts per account, baseline per account | Admins, scanners, backup accounts; compare to the account's own history |
| LM-4 | Pass-the-hash indicators: NTLM logon (type 3, NTLM, LogonProcess NtLmSsp) with a domain account to hosts where that account never logs on interactively | T1550.002 Pass the Hash | 4624 (LogonType 3, AuthenticationPackage NTLM, KeyLength 0) | baseline account-host pairs | Legacy applications using NTLM; scope to admin accounts first |
| LM-5 | A file was written to another host's admin share and executed within minutes | T1570 Lateral Tool Transfer | 5145 (write on ADMIN$/C$), then process creation on the target | sequence within 5 minutes by source host | Deployment tooling; exclude its accounts |

## Collection (TA0009)

| ID | Hypothesis | Technique | Data source | Analysis | Benign population |
|---|---|---|---|---|---|
| CO-1 | An archive utility created a large or password-protected archive in a staging directory | T1560.001 Archive via Utility, T1074.001 Local Data Staging | process creation (7z/rar/tar with -p or -hp), file creation size | stack archive path + creating user, outlier on size | Backups, developers packaging builds |
| CO-2 | A user account accessed an unusually large number of SharePoint/OneDrive/file-share documents in a short window | T1213.002 Data from Information Repositories: SharePoint, T1039 Data from Network Shared Drive | M365 FileAccessed/FileDownloaded, 5145 | outlier: files per user per hour vs baseline | Sync clients, migrations, eDiscovery |
| CO-3 | A mailbox was accessed via a client or protocol the owner does not use (EWS, IMAP, Graph) or by a delegate added recently | T1114.002 Remote Email Collection | M365 MailItemsAccessed with ClientInfoString, delegate-add audit | stack client string per mailbox, baseline | Mobile clients, archiving tools |
| CO-4 | A screen-capture or keylogging capability was loaded (SetWindowsHookEx importers, GDI capture by unsigned processes) | T1113 Screen Capture, T1056.001 Keylogging | EDR API telemetry, image loads | stack unsigned image + API, prevalence | Collaboration tools, accessibility software |

## Command and Control (TA0011)

| ID | Hypothesis | Technique | Data source | Analysis | Benign population |
|---|---|---|---|---|---|
| C2-1 | A host beacons to one external destination at a fixed interval with small, similar-sized requests | T1071.001 Web Protocols, T1573 Encrypted Channel | proxy/firewall/NetFlow | outlier: interval variance and bytes per (src, dst) pair | Update checks, telemetry, monitoring agents; long-lived and to well-known destinations |
| C2-2 | DNS queries with high entropy labels, very long names, or many unique subdomains of one domain came from a host | T1071.004 DNS, T1568.002 Domain Generation Algorithms | DNS logs | outlier: unique subdomains per domain per host, label entropy; stack by domain | CDNs, anti-virus cloud lookups, Kubernetes service discovery |
| C2-3 | A process other than a browser or updater made HTTP(S) connections to a newly registered or low-prevalence domain | T1071.001, T1105 Ingress Tool Transfer | EDR network events with process, proxy with user agent, domain age enrichment | prevalence (hosts per domain), enrich (domain age), stack process | New SaaS, vendor tools; ask the owner |
| C2-4 | Remote-access or tunnelling software not approved by IT is running (AnyDesk, TeamViewer, ngrok, Cloudflare tunnel, RustDesk) | T1219 Remote Access Software, T1572 Protocol Tunneling | process creation, DNS/proxy to their infrastructure, signer names | stack process + signer, prevalence | Approved helpdesk tool (one product); anything else is a policy question at least |
| C2-5 | Outbound connections to a cloud storage or paste site came from a non-browser process | T1102 Web Service, T1567 Exfiltration Over Web Service | proxy with process/user agent, EDR network events | stack process per destination category | Sync clients (OneDrive, Dropbox) for approved services |
| C2-6 | Long-lived outbound TCP sessions to an external IP on a port other than 80/443/53 from a server | T1571 Non-Standard Port | NetFlow/firewall session duration | outlier: duration and port per server | Database replication, VPN, partner links; inventory them |

## Exfiltration (TA0010)

| ID | Hypothesis | Technique | Data source | Analysis | Benign population |
|---|---|---|---|---|---|
| EF-1 | A host sent far more bytes outbound to a single external destination than its own daily baseline | T1041 Exfiltration Over C2 Channel, T1048 Exfiltration Over Alternative Protocol | NetFlow/firewall/proxy bytes_out | outlier: bytes_out per (src, dst) per day vs 30-day baseline | Backups to cloud, video calls, CI artifact uploads |
| EF-2 | Data was uploaded to a personal cloud storage, webmail, or file-transfer site from a corporate device | T1567.002 Exfiltration to Cloud Storage | proxy with URL category and bytes_out, CASB | stack destination + user, outlier on bytes | Personal use policy violations far outnumber exfil; prioritise by data classification |
| EF-3 | DNS TXT/NULL queries or very long DNS queries carried unusual volumes from one host | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol, T1071.004 | DNS logs | outlier: query length and TXT volume per host | Anti-spam and AV lookups use TXT heavily but to few domains |
| EF-4 | A cloud storage bucket or snapshot was shared publicly, copied to another account, or had its policy changed | T1537 Transfer Data to Cloud Account, T1530 Data from Cloud Storage | CloudTrail PutBucketPolicy/ModifySnapshotAttribute/CopySnapshot, Azure/GCP equivalents | stack actor + target; any cross-account is worth a look | IaC pipelines, approved data-sharing flows |
| EF-5 | A mailbox forwarded a burst of messages with attachments to an external domain | T1114.003, T1048 | Exchange message trace, transport rule hits | outlier: forwarded messages per mailbox per day | Users forwarding to personal mail; still a policy finding |

## Impact (TA0040)

| ID | Hypothesis | Technique | Data source | Analysis | Benign population |
|---|---|---|---|---|---|
| IM-1 | Volume shadow copies were deleted, boot recovery disabled, or backup catalogs removed | T1490 Inhibit System Recovery | process creation (vssadmin delete shadows, wmic shadowcopy delete, bcdedit /set recoveryenabled no, wbadmin delete catalog) | stack cmdline + host; any on servers is urgent | Backup software rotating shadow copies (known parent) |
| IM-2 | One process modified or renamed an unusually high number of files across many directories in minutes | T1486 Data Encrypted for Impact | file modification/rename events, file-share audit (5145) | outlier: file events per process per minute, distinct extensions written | Backup, indexing, AV scans, bulk migrations |
| IM-3 | Many services or processes tied to databases, backups, or security tools were stopped in a short window | T1489 Service Stop | 7036 stopped, process creation (net stop, sc stop, taskkill) | sequence: distinct services stopped per host per 5 minutes | Patching and maintenance windows |
| IM-4 | Cloud resources were deleted or snapshots destroyed at scale by one identity | T1485 Data Destruction, T1531 Account Access Removal | CloudTrail Delete*/Terminate* bursts, Azure/GCP audit | outlier: destructive calls per identity per hour | Cleanup automation, ephemeral environments |

## Identity and cloud (cross-tactic)

| ID | Hypothesis | Technique | Data source | Analysis | Benign population |
|---|---|---|---|---|---|
| ID-1 | An account satisfied MFA after many push notifications in a short period (MFA fatigue) | T1621 Multi-Factor Authentication Request Generation | IdP MFA logs (denied/timeout then approved) | sequence per user within 10 minutes | Users with flaky mobile connectivity |
| ID-2 | A session token was used from a different IP/ASN/device than the one that authenticated (AiTM / token replay) | T1550.004 Use Alternate Authentication Material: Web Session Cookie, T1557 Adversary-in-the-Middle | IdP sign-in logs (interactive vs non-interactive, session ID, device ID) | baseline per session: IP/ASN change without re-auth | Mobile networks, VPN split tunnels |
| ID-3 | A new OAuth application or service principal was granted mail, files, or directory read permissions by a user consent | T1528 Steal Application Access Token, T1098.003 Additional Cloud Roles | Entra consent audit, Okta app grants, Google Workspace token events | stack app name + permissions; prevalence of users who consented | Approved SaaS integrations; keep an allow-list |
| ID-4 | A new MFA method, device, or recovery email was registered for an account shortly after a risky sign-in | T1098.005 Device Registration, T1556.006 Multi-Factor Authentication | IdP security-info change audit, sign-in risk events | sequence: risky sign-in then method add within 24h | New phones, onboarding |
| ID-5 | A long-lived cloud access key or service-account key was created for a human identity or used from a new IP | T1098.001 Additional Cloud Credentials, T1078.004 Cloud Accounts | CloudTrail CreateAccessKey, GCP CreateServiceAccountKey, key usage source IPs | stack creator + target, baseline key usage IP | CI systems, developer laptops; tie to a ticket |
| ID-6 | An identity assumed a role chain or crossed into another account/tenant for the first time | T1078.004, T1550.001 Application Access Token | CloudTrail AssumeRole with sessionissuer chain, Azure cross-tenant sign-ins | baseline (first-seen role/account pairs) | Break-glass tests, new integrations |
