# Linux log and artifact reference

Paths are the common defaults for Debian/Ubuntu and RHEL/Fedora families as of 2026. Some
distributions ship journald only (no `/var/log/*.log` text files) unless `rsyslog` is
installed; check both. Most text logs are local time with no zone unless configured
(`RSYSLOG_ForwardFormat` / `journalctl -o short-iso-precise --utc` give explicit zones).

## Contents
1. Authentication and sessions
2. Command execution and privilege
3. auditd
4. Persistence locations
5. Files, users, and keys to inspect
6. Network and services
7. Time and evidence handling

## 1. Authentication and sessions

| Artifact | Location | What it shows | Notes |
|---|---|---|---|
| auth log | `/var/log/auth.log` (Debian), `/var/log/secure` (RHEL) | sshd, sudo, su, PAM, cron session opens, useradd/passwd | Lines: `Accepted publickey|password for <user> from <ip> port <p> ssh2`, `Failed password for [invalid user] <user> from <ip>`, `Invalid user <user> from <ip>`, `session opened for user <u>(uid=N) by (uid=M)`, `Disconnected from`, `Received disconnect` |
| journal | `journalctl -u ssh -u sshd --since "2026-09-15 17:00" --until ... --utc -o short-iso-precise` | Same content when rsyslog absent; `-o json` for structured export with `_SOURCE_REALTIME_TIMESTAMP` (epoch microseconds) | Persistent only if `/var/log/journal` exists; otherwise lost at reboot |
| wtmp | `/var/log/wtmp`, read with `last -F -i` (or `utmpdump`) | Logins, logouts, reboots, with source IP | Binary; attackers zero their entries; compare with auth log |
| btmp | `/var/log/btmp`, `lastb -F -i` | Failed logins | Often huge from internet brute force |
| lastlog | `/var/log/lastlog`, `lastlog` | Last login per user | Sparse file; one glance at unexpected accounts logging in |
| utmp | `/run/utmp`, `who`, `w` | Current sessions | Volatile |
| sshd config and keys | `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/`, `~/.ssh/authorized_keys`, `authorized_keys2` | Password auth allowed, root login allowed, added keys (with `command=`, `from=` options) | New keys are the most common persistence; check mtime and key comments |
| PAM | `/etc/pam.d/*`, `/etc/security/` | Backdoored auth modules (`pam_unix.so` replaced, extra `.so` in `/lib/security`) | Compare package hashes (`rpm -V pam`, `debsums pam`) |
| su / sudo | auth log | `su: (to root) user on pts/1`, `sudo: user : TTY=pts/1 ; PWD=... ; USER=root ; COMMAND=...` | sudo lines are the best command record most systems have |
| login definitions | `/etc/login.defs`, `/etc/securetty` | | |

## 2. Command execution and privilege

| Artifact | Location | Notes |
|---|---|---|
| Shell history | `~/.bash_history`, `~/.zsh_history`, `~/.sh_history`, `/root/.bash_history`, `~/.python_history`, `~/.mysql_history`, `~/.psql_history`, `~/.lesshst`, `~/.viminfo`, `~/.wget-hsts` | Written at shell exit, no timestamps unless `HISTTIMEFORMAT` set (then `#<epoch>` lines precede commands). Empty or symlinked to `/dev/null` = anti-forensics. `unset HISTFILE`, `history -c`, `export HISTSIZE=0` in the first commands is itself the finding |
| sudo log | auth log; `/var/log/sudo-io/` if `log_output` enabled | I/O logs replay full sessions |
| auditd | section 3 | The reliable command record when configured |
| systemd journal | `journalctl _COMM=sudo`, `_UID=0`, `SYSLOG_IDENTIFIER=` | |
| Process accounting | `/var/log/account/pacct`, `lastcomm` (if `acct` installed) | Every process with user and tty |
| Cron logs | `/var/log/cron` (RHEL), auth/syslog (Debian: `CRON[pid]: (user) CMD (...)`) | Execution of scheduled commands |
| Package manager | `/var/log/dpkg.log`, `/var/log/apt/history.log`, `/var/log/yum.log`, `/var/log/dnf.log`, `/var/log/dnf.rpm.log` | Tools installed by the attacker (`nmap`, `socat`, `masscan`, compilers); also what was removed |
| Compilers and interpreters | `gcc`, `python3`, `perl` present; `~/.cache/pip`, `/tmp/*.c`, `/dev/shm` | Exploit or tool builds on the host |
| Docker / containers | `docker logs`, `/var/lib/docker/containers/*/*-json.log`, `journalctl -u docker` | Escapes, mounted host paths |
| Web server | see `web-logs.md` | Webshell requests that spawn shells |

## 3. auditd

Location `/var/log/audit/audit.log`; query with `ausearch`, summarize with `aureport`.
Timestamps are epoch: `msg=audit(1757944992.123:4567)` (seconds.millis:serial). Records with
the same serial belong to one event. `--format` and `-i` interpret uids and syscalls.

| Record type | Meaning | Key fields |
|---|---|---|
| `SYSCALL` | System call matched a rule | `syscall`, `success`, `exit`, `uid`, `auid` (original login uid, survives `su`/`sudo`), `ses`, `comm`, `exe`, `key` (rule name) |
| `EXECVE` | Command and arguments (with `-a always,exit -F arch=b64 -S execve`) | `argc`, `a0..aN` (hex-encoded if they contain spaces/special chars) |
| `PATH` | File path involved in the syscall | `name`, `inode`, `mode`, `ouid` |
| `CWD` | Working directory | |
| `PROCTITLE` | Full command line (hex) | |
| `USER_AUTH`, `USER_ACCT`, `USER_LOGIN`, `USER_START`, `USER_END`, `USER_CMD` | PAM authentication, account check, login, session start/end, sudo command | `acct`, `addr`, `terminal`, `res=success|failed` |
| `CRED_ACQ`, `CRED_DISP`, `CRED_REFR` | Credential acquired/disposed/refreshed | |
| `LOGIN` | Login uid set (`auid`) | |
| `ADD_USER`, `DEL_USER`, `ADD_GROUP`, `DEL_GROUP`, `USER_MGMT`, `USER_CHAUTHTOK`, `GRP_MGMT`, `ROLE_ASSIGN` | Account management | `acct`, `id`, `exe` |
| `CONFIG_CHANGE` | Audit rules changed | Attacker disabling auditing |
| `DAEMON_START`, `DAEMON_END`, `DAEMON_ABORT` | auditd lifecycle | A gap between END and START is a blind window |
| `SERVICE_START`, `SERVICE_STOP` | systemd units | New services |
| `ANOM_*`, `AVC` | Anomalies, SELinux denials | Exploitation side effects |
| `SOCKADDR`, `SOCKETCALL` | Network syscall details (with rules on `connect`/`bind`) | Destination in hex `saddr` |
| `KERN_MODULE` | Kernel module loaded (`init_module`) | Rootkits |
| `TTY` | Keystrokes (if `pam_tty_audit` enabled) | |

Useful queries: `ausearch -ts 09/15/2026 17:00:00 -te 09/15/2026 19:00:00 -m EXECVE -i`,
`ausearch -ua <auid> -i`, `ausearch -k <rulekey>`, `aureport -au --failed`,
`aureport -x --summary`. Without rules loaded (`auditctl -l` empty), auditd logs little
beyond PAM events.

## 4. Persistence locations

| Mechanism | Where to look | What to check |
|---|---|---|
| Cron | `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}/`, `/var/spool/cron/crontabs/<user>` (Debian), `/var/spool/cron/<user>` (RHEL), `/etc/anacrontab` | New entries, `@reboot`, base64 or curl-pipe-sh, entries for unexpected users; mtime of the files |
| systemd | `/etc/systemd/system/`, `/lib/systemd/system/`, `/run/systemd/system/`, `~/.config/systemd/user/`, `*.timer` units, `systemctl list-unit-files --state=enabled`, `systemctl list-timers --all` | Units with odd names, `ExecStart` pointing to `/tmp`, `/dev/shm`, `/var/tmp`, home dirs; recently changed (`find /etc/systemd -newer <ref>`); generators in `/etc/systemd/system-generators/` |
| init / rc | `/etc/rc.local`, `/etc/init.d/`, `/etc/rc*.d/` | Legacy but still honored on many systems |
| Shell startup | `/etc/profile`, `/etc/profile.d/*.sh`, `/etc/bash.bashrc`, `/etc/bashrc`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.bash_logout`, `~/.zshrc`, `/etc/environment` | Aliases for `ls`/`sudo`/`ssh` (credential capture), `PROMPT_COMMAND`, `LD_PRELOAD` exports |
| Library preload | `/etc/ld.so.preload`, `LD_PRELOAD`/`LD_LIBRARY_PATH` in env or unit files, `/etc/ld.so.conf.d/` | Userland rootkits; the file normally does not exist |
| SSH | `authorized_keys` (all users, including service accounts and `root`), `sshd_config` `AuthorizedKeysFile`/`AuthorizedKeysCommand`, `/etc/ssh/ssh_config.d/`, `~/.ssh/config` `ProxyCommand`/`LocalCommand`, `/etc/ssh/sshrc`, `~/.ssh/rc` | Keys, backdoored config, `rc` scripts run at every login |
| PAM / NSS | `/etc/pam.d/`, `/lib*/security/`, `/etc/nsswitch.conf` | Extra modules, modified `pam_unix.so` |
| Users and groups | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`, `/etc/sudoers.d/` | New UID 0 accounts, shells set on service accounts, `NOPASSWD:ALL`, users added to `sudo`/`wheel`/`docker`; `passwd -S`, `getent passwd` |
| Kernel modules | `lsmod`, `/etc/modules`, `/etc/modules-load.d/`, `/lib/modules/$(uname -r)/`, `dmesg` for taint messages | Rootkits; hidden modules |
| udev | `/etc/udev/rules.d/` with `RUN+=` | Runs on device events |
| at | `/var/spool/at/`, `/var/spool/cron/atjobs/`, `atq` | One-shot jobs |
| Web server | webshells in document roots (`.php/.jsp/.aspx` with recent mtime), modified `.htaccess`, cron-driven re-drops | Pair with access log |
| Binaries replaced | `rpm -Va`, `debsums -c`, `dpkg --verify`; `/usr/bin/ssh`, `/usr/sbin/sshd`, `/bin/ps`, `/bin/ls`, `/bin/netstat` | Trojaned binaries |
| Immutable files | `lsattr -R /etc /usr/bin 2>/dev/null | grep -- '----i'` | Attackers set `+i` to prevent cleanup |
| Docker / k8s | `docker ps -a`, containers with `--privileged` or host mounts, cron in containers, `/var/lib/kubelet` static pods | Container-level persistence |

## 5. Files, users, and keys to inspect

- Recently modified files: `find / -xdev -newermt "2026-09-15 17:00" ! -newermt "2026-09-15 19:00" -type f 2>/dev/null`;
  SUID/SGID binaries: `find / -xdev -perm -4000 -o -perm -2000 -type f`; world-writable and
  hidden dirs in `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user/*`; files named ` ` or `...`.
- `stat` gives atime/mtime/ctime; `ctime` cannot be set by `touch`, so an mtime older than ctime
  suggests timestomping. Mounting with `noatime` (common) makes atime useless.
- Deleted-but-open files: `ls -l /proc/*/fd 2>/dev/null | grep deleted`, `/proc/<pid>/exe`
  pointing to `(deleted)`: running malware whose binary was removed. Copy via `/proc/<pid>/exe`.
- Process state (volatile): `ps -eo pid,ppid,user,lstart,etime,cmd --forest`,
  `/proc/<pid>/cmdline`, `/proc/<pid>/environ`, `/proc/<pid>/cwd`, `/proc/<pid>/maps`.
- Users: `awk -F: '$3==0' /etc/passwd`, `awk -F: '$2!="*" && $2!="!"' /etc/shadow` (accounts
  with passwords set), `lastlog`, home directories with `.ssh` for unexpected accounts.
- Credentials attackers look for: `~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`,
  `~/.git-credentials`, `~/.netrc`, `.env` files, `/etc/shadow`, private keys (`id_*`), cloud
  metadata access in web logs (`169.254.169.254`).

## 6. Network and services

| Artifact | Command / location | Notes |
|---|---|---|
| Listening sockets | `ss -tulpn`, `ss -tanp`, `lsof -i` | Unexpected listeners, reverse shells (established to odd ports from `bash`, `python`, `nc`, `socat`) |
| Firewall | `iptables-save`, `nft list ruleset`, `ufw status`, `firewall-cmd --list-all` | Opened ports, redirected traffic |
| DNS and hosts | `/etc/hosts`, `/etc/resolv.conf`, `systemd-resolved` logs | Hijacked resolution |
| Connections history | no default log; use `conntrack`, netflow, firewall logs (`/var/log/kern.log`, `/var/log/ufw.log`), proxy logs, or auditd `SOCKADDR` | Most Linux hosts have no native connection log; say so |
| Proxy env | `/etc/environment`, `/etc/profile.d/proxy.sh`, `~/.curlrc`, `~/.wgetrc` | Traffic redirection |
| Services | `systemctl list-units --type=service --state=running`, `systemctl status <unit>` | |

## 7. Time and evidence handling

- Zone: `timedatectl` shows the host zone and NTP state; `date -u` for the current UTC.
  Text logs use the host zone unless the format includes an offset. `journalctl --utc` and
  `-o short-iso-precise` remove the ambiguity; pass `--assume-tz` to the timeline builder for
  anything else.
- Year: classic syslog format (`Sep 15 18:05:11`) has no year; logs rotated across New Year
  need `--year` per file.
- Collect in this order on a live system: volatile (`ps`, `ss`, `/proc`, `w`, memory if
  possible), then logs (`tar czf` of `/var/log`, journal export `journalctl -o export`),
  then persistence locations and home directories, then the disk image if warranted. Hash
  every archive (`sha256sum`) and record the custody line.
- Rotated logs: `auth.log.1`, `auth.log.2.gz`; `zcat`/`zgrep`. journald: `--since` reaches
  across rotations automatically.
- Do not run cleanup, `updatedb`, package upgrades, or reboots before collection; each one
  changes timestamps or discards volatile evidence.
