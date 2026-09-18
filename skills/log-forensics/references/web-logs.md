# Web server and proxy log reference

## Formats

| Source | Default location | Format | Time zone |
|---|---|---|---|
| Apache httpd | `/var/log/apache2/access.log` (Debian), `/var/log/httpd/access_log` (RHEL); `error.log` | Combined: `client - user [DD/Mon/YYYY:HH:MM:SS +0000] "METHOD /path HTTP/1.1" status bytes "referer" "user-agent"` | Local time with explicit offset in the bracket |
| nginx | `/var/log/nginx/access.log`, `error.log` | Same combined format by default; JSON if configured | Same |
| IIS | `%SystemDrive%\inetpub\logs\LogFiles\W3SVC<siteid>\u_exYYMMDD.log` | W3C extended: `#Fields:` header line, space-separated; typical fields `date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken` | **UTC by default** (unless "use local time for file naming and rollover" changed it); one of the few logs that already is |
| IIS HTTPERR | `%SystemRoot%\System32\LogFiles\HTTPERR\` | Requests rejected before reaching IIS (malformed, connection limits) | UTC |
| Tomcat / Java app servers | `logs/localhost_access_log.YYYY-MM-DD.txt`, `catalina.out` | Access log pattern configurable (`%h %l %u %t "%r" %s %b`) | Local with offset |
| Squid | `/var/log/squid/access.log` | `epoch.ms elapsed client code/status bytes method URL user hierarchy/peer type` | Epoch (UTC) |
| Commercial proxies / SWG (Zscaler, Netskope, Cisco Umbrella, Bluecoat/Symantec) | SIEM or vendor export | CSV/JSON with user, source IP, URL, category, action (allow/block), bytes in/out, user agent, threat name | Usually UTC in exports; confirm |
| Load balancers / WAF (AWS ALB, Cloudflare, F5, ModSecurity) | vendor-specific | Include client IP behind proxies (`X-Forwarded-For`), TLS details, rule matches | Usually UTC |
| Reverse proxy note | | The `client` field is the proxy/LB unless `X-Forwarded-For` is logged; configure `%{X-Forwarded-For}i` (Apache) or `$http_x_forwarded_for` (nginx), and treat XFF as attacker-controllable |

Status code reminders: 200 success, 301/302 redirect, 401/403 auth failure/forbidden, 404 not
found (scanner noise), 405 method not allowed, 500 server error (exploitation side effects),
502/503/504 backend problems. IIS `sc-substatus` and `sc-win32-status` add detail (e.g.
`401.2`, `403.14`). `time-taken` and bytes help spot uploads and downloads.

## What attacks look like in access logs

| Pattern | What to look for |
|---|---|
| Scanning / recon | Thousands of 404s from one IP; paths like `/wp-login.php`, `/.env`, `/.git/config`, `/phpmyadmin`, `/actuator`, `/console`, `/manager/html`, `/owa`, `/autodiscover`, `/ecp`; scanner user agents (`sqlmap`, `nikto`, `nuclei`, `masscan`, `zgrab`, `python-requests`, `Go-http-client`, `curl`) |
| Credential attacks | Many `POST /login` (or `/owa/auth.owa`, `/api/token`, `/wp-login.php`) from one IP with 401/302; one IP hitting many usernames (spray); a burst of 401 followed by 200/302 = success |
| Injection attempts | Query strings with `' OR`, `UNION SELECT`, `../`, `%2e%2e/`, `<script`, `${jndi:` (Log4Shell), `{{`, `;wget`, `|curl`, `cmd=`, `exec`, encoded variants (`%27`, `%3C`); 500 responses to those requests suggest the input reached the backend |
| Webshell | A `POST` to a file in an upload/static directory (`/uploads/*.php`, `/images/*.aspx`, `/tmp/*.jsp`); a new file path that suddenly receives requests; short fixed-size responses; requests with no referer and a fixed non-browser user agent; the same IP hitting the same file repeatedly with `POST`; parameters like `cmd=`, `pass=`; upload endpoints returning 200 shortly before |
| Exploitation of a known CVE | Product-specific paths (e.g. Exchange `/autodiscover/autodiscover.json?@evil/...`, Confluence `/setup/`, MOVEit `/moveitisapi/`, Citrix `/vpn/../vpns/`, Ivanti `/api/v1/totp/user-backup-code/../..`); compare with vendor advisories and CISA KEV for the product version |
| Data exfiltration | Large `bytes` on `GET` of unusual files (`.zip`, `.bak`, `.sql`, database exports) or many sequential IDs (`/api/users/1..5000`, IDOR scraping); long-running sessions with high `time-taken` |
| File upload | `POST`/`PUT` with large request bodies to upload handlers, followed by `GET` of the uploaded path |
| SSRF / cloud metadata | Requests containing `169.254.169.254`, `metadata.google.internal`, `localhost`, internal hostnames in parameters |
| Path traversal / LFI | `../`, `..%2f`, `..\`, `/etc/passwd`, `win.ini`, `web.config` in paths |
| DoS | Request rate spikes, many 503s, slowloris (many partial connections in error log) |
| Beaconing via proxy | Same URL/host at regular intervals, similar sizes, low-reputation or newly registered domain, unusual user agent, `CONNECT` to raw IPs, long base64-ish paths |

## Pivoting from a web log finding

1. Take the source IP and time. Does the same IP appear in auth logs (SSH), VPN logs, other
   sites, or the proxy? Is it a Tor exit, VPN provider, cloud provider, or residential proxy?
2. Take the path of the suspicious file. Find its creation on disk (mtime/ctime, auditd `PATH`,
   Sysmon 11), who wrote it (the web server user, or a deploy account), and the first request to
   it (`grep <path> access.log* | head`).
3. Take the web server process (`w3wp.exe`, `httpd`, `nginx`, `php-fpm`, `java`). Which child
   processes did it spawn (4688/Sysmon 1 with that parent; auditd EXECVE with `ppid`)? A
   `cmd.exe` or `/bin/sh` child of a web server is the webshell executing.
4. Take the user agent and any unusual header. Search the whole estate for it.
5. For proxies: take the destination host. Which other internal hosts talked to it, when did
   the first contact happen, is it in threat intel (`threat-intel-analysis`), and what
   process was it (Sysmon 3/22 or EDR network events)?

## Volume management

- Filter out known scanners and monitoring (uptime checkers, your own vulnerability scanner,
  CDN health checks) after noting their IPs; keep the raw file untouched.
- Work in stages: counts per IP, per path, per status, per user agent (`cut`/`awk`, or the
  `stack.py` script from `threat-hunting`), then drill into the outliers.
- Timeline only the significant lines (`--grep` on the timeline builder) plus a "first and
  last seen" row per attacker IP.

## Proxy-specific reading

- `action=blocked` entries are attempts, not successes; `allowed` entries to the same
  destination minutes later (after category change or a different URL) are the concern.
- Category fields ("newly registered", "uncategorized", "dynamic DNS", "proxy avoidance")
  are useful filters; so is `bytes_out` far exceeding `bytes_in` (upload/exfil).
- User attribution depends on the auth mode (NTLM/Kerberos/agent). Unauthenticated entries
  from a source IP still map to a host via DHCP/asset logs at that time.
- TLS inspection off means only `CONNECT host:443` with sizes and timings; beaconing analysis
  still works on those.
