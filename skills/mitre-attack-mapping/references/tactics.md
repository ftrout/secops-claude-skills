# ATT&CK Enterprise tactics

Source: MITRE ATT&CK Enterprise matrix, v17 (April 2025). Tactic IDs and names have been
stable since v8 (October 2020) and are unchanged in later releases; confirm at
https://attack.mitre.org/tactics/enterprise/ if you are on a newer release.

A **tactic** is the adversary's *goal* at a moment in the intrusion ("why"). A
**technique** is *how* they pursued it. Every technique belongs to one or more tactics, and
a single observed behaviour is mapped to a technique **under** the tactic it served in that
intrusion. The Navigator layer field `tactic` uses the shortname column below.

| Order | ID | Name | Shortname (Navigator) | The question it answers |
|---|---|---|---|---|
| 1 | TA0043 | Reconnaissance | `reconnaissance` | What did they learn about us before touching us? |
| 2 | TA0042 | Resource Development | `resource-development` | What infrastructure, accounts, or tooling did they set up? |
| 3 | TA0001 | Initial Access | `initial-access` | How did they get the first foothold? |
| 4 | TA0002 | Execution | `execution` | How did they run code on our systems? |
| 5 | TA0003 | Persistence | `persistence` | How do they survive reboots, password changes, or cleanup? |
| 6 | TA0004 | Privilege Escalation | `privilege-escalation` | How did they get higher permissions? |
| 7 | TA0005 | Defense Evasion | `defense-evasion` | How did they avoid being detected or blocked? |
| 8 | TA0006 | Credential Access | `credential-access` | How did they steal or forge credentials? |
| 9 | TA0007 | Discovery | `discovery` | How did they learn the environment from the inside? |
| 10 | TA0008 | Lateral Movement | `lateral-movement` | How did they move between systems? |
| 11 | TA0009 | Collection | `collection` | How did they gather the data they wanted? |
| 12 | TA0011 | Command and Control | `command-and-control` | How did they communicate with compromised systems? |
| 13 | TA0010 | Exfiltration | `exfiltration` | How did they take data out? |
| 14 | TA0040 | Impact | `impact` | How did they disrupt, destroy, or manipulate? |

Note the IDs are not in matrix order: Reconnaissance (TA0043) and Resource Development
(TA0042) were added in v8 and placed first; Command and Control (TA0011) sits before
Exfiltration (TA0010) in the matrix despite the higher number.

## Techniques that live under several tactics

These are the ones most often assigned to the wrong tactic. Pick the tactic the behaviour
served *in this intrusion*, and list the technique twice only when the evidence supports
both goals.

| Technique | Tactics it appears under | Choosing |
|---|---|---|
| T1078 Valid Accounts | Initial Access, Persistence, Privilege Escalation, Defense Evasion | Initial Access if it was the entry; Persistence if it was retained for re-entry; Defense Evasion when the point is blending in |
| T1053 Scheduled Task/Job | Execution, Persistence, Privilege Escalation | Execution for a one-shot run; Persistence when it recurs or survives reboot |
| T1547 Boot or Logon Autostart Execution | Persistence, Privilege Escalation | Almost always Persistence |
| T1543 Create or Modify System Process | Persistence, Privilege Escalation | Persistence unless the service runs as SYSTEM and that was the point |
| T1055 Process Injection | Defense Evasion, Privilege Escalation | Defense Evasion unless it targeted a higher-privileged process |
| T1548 Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion | Privilege Escalation for UAC bypass that gained admin |
| T1134 Access Token Manipulation | Defense Evasion, Privilege Escalation | Privilege Escalation when a SYSTEM token was stolen |
| T1133 External Remote Services | Initial Access, Persistence | Initial Access for the first VPN logon; Persistence for the second account they created to keep coming back |
| T1098 Account Manipulation | Persistence, Privilege Escalation | Persistence for added credentials; Privilege Escalation for added roles |
| T1556 Modify Authentication Process | Credential Access, Defense Evasion, Persistence | Credential Access when it captures passwords; Persistence when it installs a skeleton key |
| T1574 Hijack Execution Flow | Persistence, Privilege Escalation, Defense Evasion | Defense Evasion for side-loading a payload; Persistence when the hijacked path runs at every logon |
| T1036 Masquerading | Defense Evasion | Only one tactic, listed here because it is often wrongly filed under Execution |
| T1056 Input Capture | Collection, Credential Access | Credential Access for keylogging passwords; Collection for everything else |
| T1557 Adversary-in-the-Middle | Credential Access, Collection | Credential Access for AiTM phishing proxies that capture session tokens |

## Kill-chain sanity check

A mapping that lists Impact with no Initial Access, or Exfiltration with no Collection, is
either incomplete or the evidence is thin. That is not necessarily wrong (you often only
see part of an intrusion) but say so explicitly in the mapping's "gaps" section rather than
inventing techniques to fill the chain.
