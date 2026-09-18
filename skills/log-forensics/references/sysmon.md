# Sysmon event reference

System Monitor (Sysinternals), event IDs as of Sysmon v15.x (2024-2025). Log:
`Microsoft-Windows-Sysmon/Operational`. Event volume and content depend entirely on the
configuration file deployed (common baselines: SwiftOnSecurity sysmon-config, Olaf Hartong's
sysmon-modular). Record the config version in the evidence notes; an event's absence means
nothing if the config excluded it.

| ID | Event | Key fields | Use in an investigation |
|---|---|---|---|
| 1 | Process creation | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `Hashes`, `OriginalFileName`, `IntegrityLevel`, `CurrentDirectory`, `ProcessGuid`, `ParentProcessGuid`, `LogonId` | The primary execution record. `OriginalFileName` exposes renamed binaries; `Hashes` (config-dependent: SHA256, MD5, IMPHASH) feed `malware-triage`; `ProcessGuid` links every other event from that process |
| 2 | File creation time changed | `Image`, `TargetFilename`, `CreationUtcTime`, `PreviousCreationUtcTime` | Timestomping; also legitimate for installers and browsers |
| 3 | Network connection | `Image`, `User`, `Protocol`, `SourceIp/Port`, `DestinationIp/Port`, `DestinationHostname`, `Initiated` | Process-to-network attribution; beacons, lateral movement (445/135/5985/3389 outbound), unusual processes talking out (`rundll32`, `mshta`, Office) |
| 4 | Sysmon service state changed | `State`, `Version`, `SchemaVersion` | Sysmon stopped = blind spot; note the time |
| 5 | Process terminated | `Image`, `ProcessGuid` | Durations; pair with 1 |
| 6 | Driver loaded | `ImageLoaded`, `Hashes`, `Signed`, `Signature`, `SignatureStatus` | BYOVD (vulnerable driver) attacks, rootkits; unsigned or oddly signed drivers |
| 7 | Image (DLL) loaded | `Image`, `ImageLoaded`, `Signed`, `SignatureStatus`, `OriginalFileName` | DLL side-loading (a DLL from an unusual path loaded by a signed EXE), unsigned DLLs in system processes, credential-theft DLLs loading into LSASS. Very high volume; configs usually restrict it |
| 8 | CreateRemoteThread | `SourceImage`, `TargetImage`, `StartAddress`, `StartModule`, `StartFunction` | Classic injection; benign from some AV/EDR and `csrss` |
| 9 | RawAccessRead | `Image`, `Device` | Direct disk reads (`\\.\PhysicalDrive0`): NTDS/SAM theft, wipers, some backup tools |
| 10 | ProcessAccess | `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace` | LSASS access (`TargetImage` ends with `lsass.exe`, `GrantedAccess` 0x1010, 0x1038, 0x1FFFFF) = credential dumping; `CallTrace` with `UNKNOWN` modules suggests injected code |
| 11 | FileCreate | `Image`, `TargetFilename`, `CreationUtcTime` | Dropped files, tools written to `C:\Users\Public`, `%TEMP%`, `ProgramData`, startup folders; ransomware notes |
| 12 | Registry object added or deleted | `EventType`, `TargetObject` | Run keys, services keys, IFEO, COM hijack CLSIDs |
| 13 | Registry value set | `TargetObject`, `Details` | Persistence values, Defender exclusions, UAC, RDP enable (`fDenyTSConnections`), `DisableRestrictedAdmin`, WDigest `UseLogonCredential` |
| 14 | Registry object renamed | `TargetObject`, `NewName` | Rare |
| 15 | FileCreateStreamHash | `TargetFilename`, `Hash`, `Contents` (for small streams) | Alternate data streams; `Zone.Identifier` (Mark-of-the-Web) reveals download source URL in `Contents` on newer versions |
| 16 | Sysmon configuration change | `Configuration`, `ConfigurationFileHash` | Tampering with monitoring |
| 17 | Pipe created | `PipeName`, `Image` | Named pipes of C2 frameworks and tools (`\psexesvc`, `\msagent_*`, `\postex_*`, `\MSSE-*-server`); admin tools too |
| 18 | Pipe connected | `PipeName`, `Image` | Client side of the above |
| 19 | WMI event filter activity | `Operation`, `EventNamespace`, `Name`, `Query` | WMI persistence, step 1 |
| 20 | WMI event consumer activity | `Name`, `Type` (`CommandLineEventConsumer`, `ActiveScriptEventConsumer`), `Destination` | WMI persistence, step 2 (the payload) |
| 21 | WMI event consumer to filter binding | `Consumer`, `Filter` | WMI persistence, step 3 |
| 22 | DNS query | `QueryName`, `QueryResults`, `Image` | Process-attributed DNS; C2 domains, DGA, DNS tunneling (long labels), which process resolved what |
| 23 | FileDelete (archived) | `TargetFilename`, `Hashes`, `Image`, `IsExecutable`, `Archived` | Sysmon saved a copy of the deleted file (if configured): recovers dropped tools that self-delete |
| 24 | Clipboard change | `Image`, `Session`, `ClientInfo`, `Hashes` (contents archived) | RDP clipboard use; credential pasting |
| 25 | Process tampering | `Image`, `Type` (`Image is replaced`, `Image is locked for access`) | Process hollowing / herpaderping detection |
| 26 | FileDeleteDetected | `TargetFilename`, `Hashes`, `Image` | Deletion logged without archiving |
| 27 | FileBlockExecutable | `TargetFilename`, `Hashes` | Sysmon blocked writing an executable (if configured) |
| 28 | FileBlockShredding | `TargetFilename`, `Image` | Blocked secure-delete tools (`sdelete`) |
| 29 | FileExecutableDetected | `TargetFilename`, `Hashes`, `Image` | New executable written (v15+); cheaper than 11 for hunting droppers |
| 255 | Error | | Sysmon internal errors; may indicate tampering or a broken config |

## Reading Sysmon well

- **Correlate by `ProcessGuid`**, not PID (PIDs are reused). A single GUID ties process
  creation (1), network (3), DLL loads (7), file writes (11), registry (12/13), DNS (22),
  and termination (5) into one process story. `ParentProcessGuid` builds the tree.
- **Parent/child anomalies** are the fastest tells: Office spawning `cmd`/`powershell`/`wscript`,
  `w3wp.exe`/`httpd` spawning shells (webshell), `services.exe` spawning odd binaries (7045
  twin), `lsass.exe` with children, `explorer.exe` launching from `C:\Users\Public`, `WmiPrvSE.exe`
  spawning shells (WMI lateral movement), `svchost.exe` with no `-k` argument.
- **Paths**: user-writable locations (`%TEMP%`, `%APPDATA%`, `C:\Users\Public`, `C:\ProgramData`,
  `C:\PerfLogs`, `C:\Windows\Tasks`, `C:\Windows\Temp`, recycle bin) running executables.
- **Hashes and `OriginalFileName`**: renamed system tools (`OriginalFileName: PSEXESVC.exe`,
  `Mimikatz.exe`, `procdump`, `rundll32.exe` copied as `notepad.exe`).
- **Signature fields on 6 and 7**: `Signed: false` in system processes, or signed by an
  unexpected publisher, or `SignatureStatus: Expired/Revoked`.
- **Time**: `UtcTime` fields are UTC already (unlike `TimeCreated` in exports rendered
  locally). Prefer `UtcTime` for the timeline.
- **Volume and gaps**: configs exclude most noise. If you see no 3/22 for a process, check
  the config before concluding it never talked to the network. A 4 (service stopped) or 16
  (config changed) mid-incident is itself an event.
- **Blind spots**: kernel-mode activity, memory-only injection without a new thread, ETW
  patching (process may appear silent), events on hosts where Sysmon was never installed,
  and anything the config excluded.

## Sysmon on Linux

Sysmon for Linux (2021+) logs to syslog/journal with the same IDs for the subset it supports
(1, 3, 5, 9, 11, 16, 23). Fields mirror the Windows schema; timestamps are UTC.
