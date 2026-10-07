# Linux logs

## Where things are

| Path | Contents |
|---|---|
| /var/log/auth.log | logins, sudo, ssh (Debian, Ubuntu) |
| /var/log/secure | same on RHEL, CentOS, Fedora |
| /var/log/syslog | general messages (Debian, Ubuntu) |
| /var/log/messages | same on RHEL family |
| /var/log/kern.log | kernel messages |
| /var/log/audit/audit.log | auditd, if installed |
| /var/log/wtmp | successful logins, read with `last` |
| /var/log/btmp | failed logins, read with `lastb` |
| /var/log/lastlog | last login per user, read with `lastlog` |
| /var/log/apache2/access.log | Apache on Debian, Ubuntu (RHEL: /var/log/httpd/) |
| /var/log/nginx/access.log | Nginx |
| /var/log/dpkg.log, /var/log/apt/history.log | package installs (Debian, Ubuntu) |
| /var/log/fail2ban.log, /var/log/ufw.log | fail2ban and firewall, if used |

auth.log timestamps have no year and use local time. Keep that in mind when you compare with other sources.

## journalctl

```
journalctl -u ssh --since "1 hour ago"    # service is sshd on RHEL family
journalctl -p err -b                      # errors since boot
journalctl -f                             # follow live
journalctl _UID=1000                      # messages from one user id
```

## SSH and logins

```
# failed passwords
grep "Failed password" /var/log/auth.log

# top source IPs of failed logins
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head

# invalid user names that were tried
grep "Invalid user" /var/log/auth.log

# successful logins (password or key)
grep "Accepted" /var/log/auth.log

# who logged in and from where
last -a | head
sudo lastb | head
```

A line like `Failed password for root from 203.0.113.7 port 51234 ssh2` has the IP four fields from the end, which is why the awk above uses `$(NF-3)`.

Many failures and then one `Accepted` from the same IP is the pattern to report.

## sudo and accounts

```
grep "sudo:" /var/log/auth.log | grep COMMAND
grep -E "useradd|usermod|groupadd|passwd" /var/log/auth.log
awk -F: '$3==0 {print $1}' /etc/passwd        # accounts with uid 0
```

Also check `~/.ssh/authorized_keys` of each user for keys nobody remembers adding.

## Persistence checks

```
crontab -l
ls -la /etc/cron.* /var/spool/cron/crontabs/
systemctl list-unit-files --state=enabled
find / -perm -4000 -type f 2>/dev/null        # SUID files
find /tmp /var/tmp /dev/shm -type f -mtime -2 2>/dev/null
```

## Network and processes

```
ss -tulpn          # listening ports and the process
ss -tnp            # established connections
ps auxf            # process tree
lsof -i            # open network files
```

## Web server logs

Apache and Nginx combined format: `$1` is the client IP, `$7` the path, `$9` the status code.

```
# top IPs
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head

# all 404s (scanning for paths)
awk '$9==404' access.log | head

# most requested paths
awk '{print $7}' access.log | sort | uniq -c | sort -rn | head

# common attack strings
grep -Ei "union.*select|\.\./|<script|/etc/passwd" access.log

# scanner user agents
grep -Ei "sqlmap|nikto|gobuster|dirb|wpscan" access.log
```

URL encoded input shows up as `%27` (quote), `%3C` (<), `%2e%2e%2f` (../). Decode before you grep if nothing matches.

## auditd

```
ausearch -k <key>      # events by rule key
aureport --failed      # summary of failures
aureport -au           # authentication report
```

## Quick triage order

1. `last -a`, `lastb`: who got in, from where
2. auth.log: failures, then accepted logins, then sudo
3. `ss -tulpn`, `ps auxf`: anything running or listening that should not
4. cron, systemd units, authorized_keys: how it would come back
5. web logs, if there is a web server
