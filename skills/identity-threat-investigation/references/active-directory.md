# Active Directory attack indicators reference

Contents: prerequisites (audit policy); event IDs by phase; attack signatures with what
distinguishes them from noise; KQL examples over `SecurityEvent`; containment including the
krbtgt double reset.

Event IDs and field names are stable across Windows Server 2016 through 2025. Detection
guidance aligns with MITRE ATT&CK v17 (2025) technique IDs where given.

## Prerequisites: what must be audited for these to exist

| Signal | Audit setting | Where |
|---|---|---|
| 4768 / 4769 / 4771 | Account Logon > Audit Kerberos Authentication Service, Audit Kerberos Service Ticket Operations (success and failure) | DCs |
| 4776 | Account Logon > Audit Credential Validation | DCs (NTLM) |
| 4624 / 4625 / 4648 / 4672 | Logon/Logoff > Audit Logon, Audit Special Logon; Audit Other Logon/Logoff | all hosts |
| 4662 | DS Access > Audit Directory Service Access, plus a SACL on the domain root for the replication extended rights | DCs; without the SACL, DCSync is invisible |
| 5136 / 5137 / 5141 | DS Access > Audit Directory Service Changes, plus SACLs on the objects | DCs |
| 4720-4767 account management | Account Management > Audit User Account Management, Security Group Management, Computer Account Management | DCs |
| 4663 on NTDS.dit | Object Access > Audit File System plus SACL on `%SystemRoot%\NTDS\ntds.dit` | DCs |
| 4688 with command line | Detailed Tracking > Audit Process Creation, and "Include command line in process creation events" | all hosts (or Sysmon 1) |
| 1102 | always logged when the Security log is cleared | all hosts |

If a query returns nothing, first confirm the audit setting; "no events" is often "not
audited".

## Event IDs by phase

**Authentication**
- 4768 Kerberos TGT requested. Fields: `TargetUserName`, `ServiceName` (krbtgt), `IpAddress`, `TicketEncryptionType` (0x12 AES256, 0x11 AES128, 0x17 RC4, 0x18 RC4-HMAC-EXP, 0x3 DES), `PreAuthType` (0 = none, 2 = PA-ENC-TIMESTAMP, 15/16/17 = PKINIT / smart card), `Status` (0x0 ok, 0x6 unknown principal, 0x12 disabled/locked/expired, 0x17 password expired, 0x18 bad password, 0x25 clock skew)
- 4769 Kerberos service ticket (TGS) requested. Fields: `TargetUserName` (requesting user), `ServiceName` (SPN account), `IpAddress`, `TicketEncryptionType`, `TicketOptions`, `Status` (0x0 ok)
- 4770 TGT renewed; 4771 Kerberos pre-auth failed (`Status` 0x18 bad password: the Kerberos side of spray); 4772 / 4773 TGT / TGS request failed
- 4776 NTLM credential validation on the DC. `Status` 0xC000006A bad password, 0xC0000064 no such user, 0xC0000234 locked, 0xC0000072 disabled. `Workstation` is the originating host name (attacker-controlled string)
- 4624 successful logon. `LogonType` 2 interactive, 3 network, 4 batch, 5 service, 7 unlock, 8 network cleartext, 9 new credentials (runas /netonly; pass-the-hash and overpass-the-hash tooling produce this), 10 RDP, 11 cached. `AuthenticationPackageName` (Kerberos / NTLM / Negotiate), `LogonProcessName`, `IpAddress`, `ElevatedToken`, `TargetLogonId` (join to 4672 / 4634)
- 4625 failed logon. `Status` 0xC000006D with `SubStatus` 0xC000006A bad password, 0xC0000064 user does not exist, 0xC0000234 locked, 0xC0000072 disabled, 0xC000006F outside hours, 0xC0000070 workstation restriction, 0xC0000193 account expired, 0xC0000071 password expired
- 4648 logon with explicit credentials (runas, scheduled tasks, lateral movement with alternate creds)
- 4672 special privileges assigned at logon (SeDebugPrivilege, SeBackupPrivilege, SeTcbPrivilege, SeImpersonatePrivilege, SeLoadDriverPrivilege). Admin logon marker

**Directory access and changes**
- 4662 operation performed on a directory object. `Properties` contains GUIDs of the attributes / extended rights, `SubjectUserName`, `ObjectName`, `AccessMask`
- 5136 directory object modified (`AttributeLDAPDisplayName`, `AttributeValue`, `ObjectDN`, `OperationType` add/delete value); 5137 created; 5141 deleted; 5139 moved
- 4670 permissions on an object changed; 4780 ACL set on an admin account (AdminSDHolder propagation)
- 4713 Kerberos policy changed; 4739 domain policy changed; 4706 / 4707 trust created / removed; 4716 trust info modified; 4865 / 4866 / 4867 trusted forest info

**Account management**
- 4720 user created; 4722 enabled; 4724 password reset attempt (by another account); 4723 password change attempt (by self); 4725 disabled; 4726 deleted; 4738 user account changed (`UserAccountControl` text such as `'Don't Require Preauth' - Enabled`, `'Password Not Required' - Enabled`, `ServicePrincipalName` changes); 4740 lockout; 4767 unlocked; 4781 renamed
- 4728 / 4732 / 4756 member added to security-enabled global / local / universal group; 4729 / 4733 / 4757 removed; 4735 / 4737 / 4755 group changed
- 4741 computer created; 4742 computer changed (`msDS-AllowedToActOnBehalfOfOtherIdentity` for RBCD, `ServicePrincipalName`, `UserAccountControl` trusted-for-delegation flags); 4743 deleted
- 4794 attempt to set DSRM password
- 4697 service installed (also System 7045); 4698 scheduled task created; 4702 updated

**Log and defense tampering**
- 1102 audit log cleared; 4719 system audit policy changed; 4907 auditing settings on object changed; 4817 auditing settings on global SACL changed
- 1100 event logging service shut down; Sysmon 255 / service stop

## Attack signatures

**Kerberoasting (T1558.003)**
- Many 4769 from one `IpAddress` / `TargetUserName` in seconds, each with a different
  `ServiceName` (user accounts with SPNs, not computer accounts ending in `$`), and
  `TicketEncryptionType` 0x17 (RC4) when the domain otherwise uses AES.
- Noise: AES-only environments still emit 0x17 for accounts that have not had a password
  change since AES was enabled, and some legacy apps request RC4. Baseline the ratio.
- Strong version: 4769 for a honey SPN account that no legitimate client ever requests.
- Follow-up: 4624 type 3 with the cracked service account from a new host.

**AS-REP roasting (T1558.004)**
- 4768 with `PreAuthType` 0 and `TicketEncryptionType` 0x17 for accounts that have
  `DONT_REQ_PREAUTH` set. Preceded by LDAP enumeration of `userAccountControl`.
- 4738 with `'Don't Require Preauth' - Enabled` is the attacker *creating* the condition.
- Noise: a handful of legacy accounts legitimately have pre-auth off; they will show up
  on a schedule from the same hosts.

**DCSync (T1003.006)**
- 4662 on the domain object (`ObjectType` `%{19195a5b-6da0-11d0-afd3-00c04fd930c9}` domain-DNS)
  with `Properties` containing `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes),
  `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All), or
  `89e95b76-444d-4c62-991a-0facbeda640c` (DS-Replication-Get-Changes-In-Filtered-Set),
  where `SubjectUserName` is not a domain controller computer account (not ending in `$`
  and not in the Domain Controllers OU) and not the Entra Connect / sync service account.
- Also 4662 `AccessMask` 0x100 (control access) with those GUIDs from a workstation IP.
- Noise: Entra Connect (PHS) legitimately performs replication reads; know its account and
  server. Backup tools with AD agents sometimes do too.
- Preceded by 5136 / 4670 granting the replication rights to a non-DC principal.

**Golden ticket (T1558.001)**
- 4624 / 4672 for an account on a member server or DC with no 4768 for that account on any
  DC in the preceding ticket lifetime (a forged TGT never asks the KDC for a TGT).
- 4769 where `TargetUserName` or `TargetDomainName` looks wrong: an account that does not
  exist, a domain name in the wrong case or as FQDN where NetBIOS is expected, a SID that
  does not match the name.
- Tickets encrypted with RC4 (0x17) for a krbtgt that uses AES.
- After a krbtgt reset, continued successful 4769 for tickets that predate the reset are
  the confirmation.

**Silver ticket (T1558.002)**
- 4624 type 3 on the target service host (CIFS, HTTP, MSSQL) with no corresponding 4769 on
  any DC for that service ticket; account name / SID anomalies in the 4624.
- Preceded by theft of the service account or computer account hash; correlate with
  credential dumping on the host.

**NTDS.dit theft (T1003.003)**
- 4688 / Sysmon 1 on a DC: `ntdsutil.exe` invoked with arguments creating an IFM (install
  from media) snapshot; `vssadmin.exe` or `diskshadow.exe` creating a shadow copy on a DC;
  `esentutl.exe` copying from a shadow copy path; PowerShell or `wmic` calling
  `Win32_ShadowCopy` on a DC.
- Application log 8222 (VSS shadow copy created) on a DC outside backup windows; 4663 on
  `ntds.dit` from a non-backup process; 4674 / 4673 for `SeBackupPrivilege` use by an
  unexpected account.
- Off-DC alternative: `SeBackupPrivilege` holder reading `\\dc\C$\Windows\NTDS` via
  backup semantics (4663 with backup-operator accounts).

**Shadow credentials and delegation backdoors**
- 5136 modifying `msDS-KeyCredentialLink` on a user or computer by someone other than the
  object itself or a device-registration service (shadow credentials, then 4768 with
  `PreAuthType` 16 PKINIT for that account).
- 4742 / 5136 setting `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) or
  `msDS-AllowedToDelegateTo`, or `UserAccountControl` `TRUSTED_FOR_DELEGATION` /
  `TRUSTED_TO_AUTH_FOR_DELEGATION`.
- 5136 on `AdminSDHolder` (`ObjectDN` contains `CN=AdminSDHolder,CN=System`), on GPO
  objects (`gPCFileSysPath`, `versionNumber`), or adding `sIDHistory`.
- 4728 / 4732 / 4756 adding to Domain Admins, Enterprise Admins, Schema Admins,
  Administrators, Account Operators, Backup Operators, DnsAdmins, Group Policy Creator Owners.
- 4794 DSRM password set; registry `DsrmAdminLogonBehavior` changes on DCs.

**Password spray and stuffing (T1110.003 / .004)**
- 4771 (Kerberos) or 4776 (NTLM) failures with bad-password status across many
  `TargetUserName` from one `IpAddress` / `Workstation` in a short window; 4625 on the
  target if it was a service (OWA, VPN, RDP gateway) with `LogonType` 3 or 8.
- Followed by one success (4768 / 4776 0x0 / 4624) from the same source.
- 4740 lockouts across many accounts at once.

**Pass-the-hash / overpass-the-hash (T1550.002)**
- 4624 `LogonType` 9 with `LogonProcessName` `seclogo` and `AuthenticationPackageName`
  `Negotiate` on the source host (the "runas /netonly" pattern used by hash-injection
  tooling), followed by 4624 type 3 NTLM on the target host from that source.
- 4768 with RC4 (0x17) for a user whose normal logons are AES.
- 4776 NTLM successes for admin accounts from workstations that normally use Kerberos.

## KQL over `SecurityEvent`

```kusto
// Kerberoasting: one requester, many SPN accounts, RC4, short window
SecurityEvent
| where TimeGenerated > ago(1d) and EventID == 4769
| where TicketEncryptionType == "0x17" and not(ServiceName endswith "$") and ServiceName !~ "krbtgt"
| summarize SPNs = dcount(ServiceName), Services = make_set(ServiceName, 20), First = min(TimeGenerated), Last = max(TimeGenerated)
      by TargetUserName, IpAddress, bin(TimeGenerated, 5m)
| where SPNs >= 5

// AS-REP roasting
SecurityEvent
| where TimeGenerated > ago(7d) and EventID == 4768
| where PreAuthType == "0" and TicketEncryptionType == "0x17"
| project TimeGenerated, TargetUserName, IpAddress, Status

// DCSync from non-DC principals
SecurityEvent
| where TimeGenerated > ago(7d) and EventID == 4662
| where Properties has_any ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
                           "89e95b76-444d-4c62-991a-0facbeda640c")
| where not(SubjectUserName endswith "$") and SubjectUserName !in ("MSOL_<sync-account>", "<aad-connect-account>")
| project TimeGenerated, Computer, SubjectUserName, SubjectDomainName, ObjectName, AccessMask, Properties

// Golden ticket hint: logons for accounts with no TGT request in the last 10 hours
let tgts = SecurityEvent | where TimeGenerated > ago(12h) and EventID == 4768 and Status == "0x0"
           | summarize by TargetUserName = tolower(TargetUserName);
SecurityEvent
| where TimeGenerated > ago(2h) and EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "Kerberos"
| where not(TargetUserName endswith "$") and TargetUserName !in ("ANONYMOUS LOGON")
| extend u = tolower(TargetUserName)
| join kind=leftanti tgts on $left.u == $right.TargetUserName
| summarize Logons = count(), Hosts = make_set(Computer, 10), IPs = make_set(IpAddress, 10) by TargetUserName

// Sensitive group membership changes
SecurityEvent
| where TimeGenerated > ago(30d) and EventID in (4728, 4732, 4756)
| where TargetUserName in ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
                          "Account Operators", "Backup Operators", "DnsAdmins", "Group Policy Creator Owners")
| project TimeGenerated, Computer, SubjectUserName, MemberName, TargetUserName

// Dangerous attribute changes (needs DS Changes auditing)
SecurityEvent
| where TimeGenerated > ago(30d) and EventID == 5136
| where AttributeLDAPDisplayName in ("msDS-KeyCredentialLink", "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-AllowedToDelegateTo", "servicePrincipalName", "sIDHistory", "userAccountControl", "scriptPath",
    "gPCFileSysPath", "nTSecurityDescriptor")
   or ObjectDN has "CN=AdminSDHolder,CN=System"
| project TimeGenerated, SubjectUserName, ObjectDN, AttributeLDAPDisplayName, AttributeValue, OperationType

// Spray via Kerberos pre-auth failures
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == 4771 and Status == "0x18"
| summarize Users = dcount(TargetUserName), Attempts = count() by IpAddress, bin(TimeGenerated, 10m)
| where Users >= 10

// NTDS theft tooling on domain controllers (needs 4688 command line or Sysmon 1)
SecurityEvent
| where TimeGenerated > ago(7d) and EventID == 4688
| where Computer in ("DC01.corp.yourcompany.example", "DC02.corp.yourcompany.example")
| where NewProcessName has_any ("ntdsutil.exe", "vssadmin.exe", "diskshadow.exe", "esentutl.exe")
   or CommandLine has_any ("ntds.dit", "Win32_ShadowCopy", "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy")
| project TimeGenerated, Computer, SubjectUserName, NewProcessName, CommandLine, ParentProcessName
```

Splunk and Elastic equivalents follow the same field logic; use `siem-query-authoring`
for syntax and CIM / ECS field names (`EventCode`, `event.code`).

## Containment

| Situation | Action | Caution |
|---|---|---|
| Single user account compromised | disable, reset password, clear `adminCount` artifacts if any, review group memberships, check `msDS-KeyCredentialLink` and SPNs on the account | if hybrid, do it in AD and let sync push it; also revoke cloud sessions (`entra-id.md`) |
| Admin (tier 0) account compromised | reset twice (so the previous hash is gone from the n-1 history), remove from groups, audit everything it touched (5136, 4662, 4728+), reset any service and computer accounts it could have dumped | assume every account it could read is compromised |
| DCSync or NTDS theft confirmed | treat every domain hash as stolen: krbtgt double reset, reset all privileged accounts, all service accounts with SPNs, gMSA rotation, computer account passwords for tier 0, Entra Connect account, trust passwords, DSRM passwords; rotate certificates if AD CS keys were reachable | this is a domain rebuild-grade event; plan it, do not improvise |
| Golden ticket suspected | krbtgt double reset (below); find and reboot hosts holding forged tickets | forged tickets remain valid until the *second* reset completes |
| Silver ticket | reset the affected service or computer account password twice | |
| Shadow credentials / RBCD / delegation backdoor | clear the attribute (`msDS-KeyCredentialLink`, `msDS-AllowedToActOnBehalfOfOtherIdentity`), remove delegation flags, review who had write access to the object | |
| AdminSDHolder / ACL backdoor | restore the ACL from a known-good copy, force SDProp, re-check protected groups | |
| Spray from one source | block at the edge (VPN, OWA), consider lockout policy, MFA on the exposed service | do not lock accounts wholesale; the attacker's spray becomes a DoS |

**krbtgt double reset, done safely**
1. Reset once (`Reset-KrbtgtKey` style script from Microsoft, or via ADUC). Kerberos keeps
   the current and previous key, so existing tickets still validate and nothing breaks.
2. Wait for replication to every DC (verify with `repadmin /showobjmeta` on krbtgt), then
   wait longer than the maximum TGT lifetime (default 10 hours) so every legitimate ticket
   has been renewed with the new key.
3. Reset a second time. Now tickets forged with the old key fail everywhere.
4. Repeat for every RODC krbtgt (`krbtgt_<id>`) in scope.
5. Expect a brief spike of 4769 failures and service restarts for anything holding stale
   tickets; schedule it and tell the platform teams. Two resets back to back without the
   wait breaks authentication across the forest.
