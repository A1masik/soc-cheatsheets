# Common ports

| Port | Service |
|---|---|
| 20, 21 | FTP (data, control) |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS (UDP and TCP) |
| 67, 68 | DHCP |
| 80 | HTTP |
| 88 | Kerberos |
| 110 | POP3 |
| 123 | NTP |
| 135 | MS RPC |
| 137, 138, 139 | NetBIOS |
| 143 | IMAP |
| 161, 162 | SNMP |
| 389 | LDAP |
| 443 | HTTPS |
| 445 | SMB |
| 465, 587 | SMTP over TLS, submission |
| 636 | LDAPS |
| 993 | IMAPS |
| 995 | POP3S |
| 1433 | MS SQL |
| 3306 | MySQL |
| 3389 | RDP |
| 5432 | PostgreSQL |
| 5985, 5986 | WinRM (HTTP, HTTPS) |
| 8080 | alternative HTTP |

## Wazuh (4.x, all-in-one)

| Port | Use |
|---|---|
| 1514 | agent events to the manager |
| 1515 | agent enrollment |
| 55000 | Wazuh API |
| 9200 | Wazuh indexer |
| 443 | dashboard |

## ELK

| Port | Use |
|---|---|
| 9200 | Elasticsearch |
| 5601 | Kibana |
| 5044 | Logstash, input from Beats |

## Why these show up in alerts

- 445, 139: SMB, lateral movement and worms
- 3389: RDP, brute force and remote access
- 22: SSH brute force
- 23: Telnet should not be open on anything modern
- 53 with big responses or long names: possible DNS tunnelling
- 5985, 5986: WinRM, remote command execution
