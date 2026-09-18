# Triage playbook: network / IDS / firewall alerts

Covers: IDS/IPS signature hits (Suricata, Snort, vendor NGFW threat logs), DNS
sinkhole or threat-list hits, beaconing detections, port scans, data-volume anomalies,
and TLS/JA3 fingerprint matches.

## Questions to answer
1. Direction: inbound (external to us), outbound (us to external), or lateral (internal to internal)?
2. Was the connection **allowed** or blocked? A blocked inbound scan is noise; an allowed outbound hit is not.
3. What internal asset and user are behind the internal IP at that moment (DHCP/NAT/VPN attribution)?
4. Is the signature itself reliable? Check the rule's age, known false-positive notes, and hit volume.
5. Did the internal host do anything else unusual around the same time?

## Data to pull
- Full flow record: 5-tuple, bytes in/out, duration, packet counts, app-ID, URL/SNI if available.
- The signature or threat-list entry that fired, and its documentation / false-positive notes.
- DHCP, NAT, and VPN logs to attribute the internal IP to a host and user at the exact time.
- DNS queries from the internal host before the connection (what name resolved to that IP?).
- Proxy logs for the same destination (was it a browser fetch with a referer, or a bare process?).
- EDR network events on the host: which process made the connection.
- Same destination across the fleet in the last 30 days; same signature across sources in the last 7 days.

## Benign explanation checklist
- [ ] Inbound, blocked, from a known mass scanner (GreyNoise or similar says background noise).
- [ ] Vulnerability scanner or pen-test box on the approved list is the source.
- [ ] Signature is a known-noisy content match (e.g. fires on a legitimate CDN, update service, or telemetry).
- [ ] Destination is a shared cloud IP now hosting a legitimate service; threat-list entry is stale.
- [ ] Traffic is a health check, monitoring probe, backup, or replication between documented systems.
- [ ] Sinkhole hit from a security tool, a browser prefetch, or a mail client rendering a link preview.

## True-positive indicators
- Allowed outbound connection from a workstation process that is not a browser, to a raw IP or
  newly registered domain, on an uncommon port, with regular intervals (beaconing).
- DNS: high-entropy subdomains, TXT record volume, or many NXDOMAINs from one host (tunnelling / DGA).
- Large outbound byte counts to cloud storage, paste sites, or personal accounts outside business hours.
- Inbound exploit signature followed by outbound connection from the targeted server (call-back).
- Lateral: SMB/RDP/WinRM/SSH from a workstation to many hosts; admin protocol use from a non-admin subnet.
- TLS to a destination with a self-signed cert, mismatched SNI, or a JA3/JA4 tied to known tooling.

## Scoping questions
- How many internal hosts talked to the same destination or matched the same signature?
- First-seen date for this destination in the environment; is this new behaviour for the host?
- Does the destination resolve from other names, and did other hosts query those names?
- If lateral, what accounts authenticated across the flows?

## Escalation criteria
- Escalate immediately: allowed outbound C2-pattern traffic, confirmed exploit-then-callback on a server,
  lateral movement from a workstation, or evidence of exfiltration volume.
- Escalate the same shift: unexplained outbound to a low-reputation destination from a process you cannot identify.
- Blocking a destination at the firewall/DNS is usually low-risk but still follows the change process in
  `environment.md`; blocking an internal host's traffic is containment and needs approval.

## Hand-offs
- Host-side investigation of the internal asset: `log-forensics` and the `edr-process` playbook.
- Destination indicators: `ioc-extraction` for the list, `threat-intel-analysis` for attribution context.
- Repeated noisy signatures: `detection-engineering` for tuning; write a query with `siem-query-authoring` to measure volume.
