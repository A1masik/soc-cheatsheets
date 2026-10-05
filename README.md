# SOC cheat sheets

Short reference notes for SOC Tier 1 practice: reading packets, Windows events and Linux logs.

| File | What is inside |
|---|---|
| [wireshark.md](wireshark.md) | display filters, capture filters, tshark one-liners |
| [windows-event-ids.md](windows-event-ids.md) | Security, System, Sysmon, PowerShell, RDP, Defender |
| [linux-logs.md](linux-logs.md) | log locations, grep and awk patterns for auth and web logs |
| [ports.md](ports.md) | common ports, plus Wazuh and ELK ports |

Notes

- Wireshark filters use 4.x syntax. Older versions differ a little (for example `ssl` instead of `tls`).
- Event IDs follow Microsoft documentation. Many Security events only appear if the matching audit policy is on.
- These are starting points for triage, not proof. One event rarely tells the whole story.

Sources: Wireshark User's Guide, Microsoft Learn (security auditing), Sysmon documentation, man pages.
