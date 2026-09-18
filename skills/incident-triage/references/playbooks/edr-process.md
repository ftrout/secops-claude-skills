# Triage playbook: EDR / process alerts

Covers: suspicious process trees, LOLBin abuse, credential access (LSASS), script
interpreters spawning from Office or browsers, persistence writes, ransomware behaviour
flags, and "malware detected/quarantined" events.

## Questions to answer
1. What ran, from where, launched by what, as whom? (full process chain, hashes, signer, path)
2. Was it blocked or did it execute? Blocked-before-execution is a different tier.
3. Is this binary/path/command line known in the environment (prevalence over 30 days)?
4. What happened in the 15 minutes before and after on this host (network, files, registry, logons)?
5. Is there a change ticket, software deployment, or admin activity that explains it?

## Data to pull
- EDR process tree with command lines, parent chain, signer, file prevalence, first-seen date.
- Network connections from the process (destination, port, DNS name, bytes).
- File writes and registry writes by the process (Run keys, services, scheduled tasks, WMI).
- Host logon sessions at the time (interactive, remote, service) and the initiating user.
- Sysmon / Windows Security events if collected: 4688, 4624, 4672, 7045, 4698, Sysmon 1/3/11/13.
- Vulnerability/patch state of the host and EDR sensor health (is the host fully instrumented?).

## Benign explanation checklist
- [ ] Signed vendor binary in its normal install path, prevalence high across the fleet.
- [ ] Matches a software deployment (SCCM/Intune/Jamf/Ansible) window and account.
- [ ] Admin activity by a named engineer with a change ticket or a known maintenance window.
- [ ] Security tooling (vuln scanner, backup agent, EDR itself, red team with a scheduled exercise).
- [ ] Developer workstation running build tools, containers, or debuggers that touch process memory.
- [ ] Known false-positive pattern already documented in tuning notes for this rule.
- [ ] Legitimate script with a corporate signing certificate or from a managed repo path.

Note: "signed" is not "safe". Signed-but-abused binaries (LOLBins) are the point of many alerts.

## True-positive indicators
- Office/PDF reader/browser spawning `cmd`, `powershell`, `wscript`, `mshta`, `rundll32`, `regsvr32`.
- Encoded/obfuscated command lines, download cradles, long base64, unusual `-w hidden` flags.
- Binary executed from user-writable paths (Downloads, Temp, AppData, Public, Recycle Bin) with
  low or zero fleet prevalence, unsigned or with a recently issued or revoked certificate.
- Renamed system utilities (hash matches a known tool but the filename does not).
- LSASS access with unusual access masks from non-security tooling; SAM/NTDS/registry hive dumps.
- Persistence writes immediately after execution; shadow copy deletion; mass file renames.
- Outbound connections to newly registered domains, raw IPs on uncommon ports, or known C2 infra.
- Attempts to disable or uninstall the EDR sensor, Defender, or logging.

## Scoping questions
- Same hash, command line, or parent chain on other hosts in the last 30 days?
- Same user logged on elsewhere around the same time? Any lateral movement events (4624 type 3/10,
  PsExec-style service installs, WinRM, RDP) from this host?
- Did the process reach out to the network, and did anything else in the fleet reach the same destination?
- Was any account with elevated privileges active on the host during the window?

## Escalation criteria
- Escalate to tier 2 / IR immediately when: execution confirmed and any of credential access,
  persistence, C2 beaconing, ransomware behaviour, or a crown-jewel host.
- Escalate the same shift when: unsigned, low-prevalence binary executed with no benign explanation
  after data pull, even if nothing else observed.
- Contain (isolate host) only via the documented approval path in `environment.md`; isolation before
  evidence capture destroys volatile data on some platforms, so capture memory/triage package first if
  the EDR supports it.

## Hand-offs
- Hashes, paths, and dropped files to `malware-triage`; extracted indicators to `ioc-extraction`.
- Command lines and parent chains to `log-forensics` for host timeline reconstruction.
- Repeated false positives to `detection-engineering` with the tuning evidence.
