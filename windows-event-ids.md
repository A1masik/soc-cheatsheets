# Windows event IDs

Most Security events need the matching audit policy turned on. If an ID never shows up, check the policy first.

## Logons (Security log)

| ID | Meaning |
|---|---|
| 4624 | successful logon |
| 4625 | failed logon |
| 4634 | logoff |
| 4647 | user started the logoff |
| 4648 | logon with explicit credentials (runas, some remote tools) |
| 4672 | special privileges assigned to a new logon, usually an admin account |
| 4776 | NTLM credential check (on a domain controller) |
| 4768 | Kerberos TGT requested |
| 4769 | Kerberos service ticket requested |
| 4771 | Kerberos pre-authentication failed |
| 4740 | account locked out |

### Logon types (field in 4624 and 4625)

| Type | Meaning |
|---|---|
| 2 | interactive, at the keyboard |
| 3 | network, for example SMB shares |
| 4 | batch, scheduled tasks |
| 5 | service |
| 7 | unlock |
| 8 | network with clear text password |
| 9 | new credentials (runas /netonly) |
| 10 | remote interactive, RDP |
| 11 | cached interactive, domain account while offline |

### Failure codes (SubStatus in 4625)

| Code | Meaning |
|---|---|
| 0xC0000064 | user name does not exist |
| 0xC000006A | wrong password |
| 0xC000006D | generic logon failure |
| 0xC0000072 | account disabled |
| 0xC0000234 | account locked out |
| 0xC0000070 | workstation restriction |
| 0xC0000071 | password expired |

## Accounts and groups (Security log)

| ID | Meaning |
|---|---|
| 4720 | user account created |
| 4722 | account enabled |
| 4723 | user tried to change own password |
| 4724 | password reset attempt by someone else |
| 4725 | account disabled |
| 4726 | account deleted |
| 4738 | account changed |
| 4728 | member added to a global security group |
| 4732 | member added to a local security group (check for Administrators) |
| 4756 | member added to a universal security group |

## Processes, tasks, services

| ID | Log | Meaning |
|---|---|---|
| 4688 | Security | process created |
| 4689 | Security | process ended |
| 4697 | Security | service installed |
| 7045 | System | new service installed |
| 7036 | System | service started or stopped |
| 7040 | System | service start type changed |
| 4698 | Security | scheduled task created |
| 4699 | Security | scheduled task deleted |
| 4702 | Security | scheduled task updated |
| 106 | TaskScheduler/Operational | task registered |

Command line in 4688 is off by default. To get it: Audit Process Creation (Advanced Audit Policy > Detailed Tracking) and then Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events.

## Files, shares, registry

| ID | Meaning |
|---|---|
| 4663 | attempt to access an object (needs a SACL on the file) |
| 4657 | registry value modified |
| 5140 | network share accessed |
| 5145 | file checked on a share, detailed |

## Tampering and system

| ID | Log | Meaning |
|---|---|---|
| 1102 | Security | audit log cleared |
| 104 | System | an event log was cleared |
| 4719 | Security | audit policy changed |
| 6005 | System | event log service started (boot) |
| 6006 | System | event log service stopped (shutdown) |
| 6008 | System | unexpected shutdown |
| 41 | System | Kernel-Power, reboot without clean shutdown |
| 1074 | System | shutdown or restart started by a process or user |

## PowerShell

| ID | Log | Meaning |
|---|---|---|
| 4104 | PowerShell/Operational | script block logging, shows the real code |
| 4103 | PowerShell/Operational | module logging |

Script block logging has to be enabled by policy.

## RDP

| ID | Log | Meaning |
|---|---|---|
| 4624 type 10 | Security | RDP logon |
| 1149 | TerminalServices-RemoteConnectionManager/Operational | user authentication succeeded |
| 21 | TerminalServices-LocalSessionManager/Operational | session logon |
| 22 | same | shell start |
| 23 | same | session logoff |
| 24 | same | session disconnected |
| 25 | same | session reconnected |

## Microsoft Defender (Windows Defender/Operational)

| ID | Meaning |
|---|---|
| 1116 | malware detected |
| 1117 | action taken on malware |
| 5001 | real-time protection disabled |
| 5007 | configuration changed |

## Sysmon (Microsoft-Windows-Sysmon/Operational)

| ID | Meaning |
|---|---|
| 1 | process created, with hashes and parent process |
| 2 | file creation time changed |
| 3 | network connection |
| 5 | process ended |
| 6 | driver loaded |
| 7 | image (DLL) loaded |
| 8 | CreateRemoteThread, common in injection |
| 10 | process access, watch for lsass.exe as target |
| 11 | file created |
| 12, 13, 14 | registry object, value set, rename |
| 15 | file stream created |
| 17, 18 | named pipe created, connected |
| 19, 20, 21 | WMI filter, consumer, binding |
| 22 | DNS query |
| 23 | file deleted (archived) |
| 25 | process tampering |

## Patterns to look for

- Brute force: many 4625 from one source in a short time, then a 4624 from the same source. Check logon type 3 or 10.
- Password spray: few attempts per account but many different accounts, one source.
- New admin: 4720 followed by 4732 on the Administrators group.
- Persistence: 7045, 4698, new Run keys (Sysmon 13).
- Covering tracks: 1102 or 104.
- Credential dumping: Sysmon 10 with lsass.exe as the target process.
- Kerberoasting (possible): many 4769 from one account with ticket encryption type 0x17.
- Odd parent and child: winword.exe or excel.exe starting cmd.exe or powershell.exe.
- Living off the land binaries to watch: certutil, mshta, rundll32, regsvr32, bitsadmin, wmic, powershell with -enc.

## Reading events from the command line

```
# last 10 failed logons
wevtutil qe Security "/q:*[System[(EventID=4625)]]" /c:10 /rd:true /f:text

# same with PowerShell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10
```
