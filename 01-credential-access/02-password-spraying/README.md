# T1110.003 – Password Spraying (Domain, SMB/NTLM)

| | |
|---|---|
| **Module** | Credential Access |
| **Technique** | Password Spraying — [T1110.003](https://attack.mitre.org/techniques/T1110/003/) (sub-technique of [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force) |
| **Tactic** | Credential Access ([TA0006](https://attack.mitre.org/tactics/TA0006/)) |
| **Environment** | [`00-environment`](../../00-environment/) |

> [TODO: confirm the actual folder number for this module in the repo — the repo screenshot only showed `00-environment` and `03-command-and-control`, so the Credential Access number needs to be matched manually when placing this file]

## Summary

I ran a password spraying attack (T1110.003) against domain controller SOC-DC01 — one password against 5 domain accounts at once, over SMB/NTLM using NetExec. By default a single failed logon in Wazuh only trips a level 5 rule and gets lost in the noise, so the outcome was writing a correlation rule (101030) that ties together 5+ failed logons against different accounts from one IP within a 5-minute window, and actually raises this to a level 10 alert.

## Environment

| Role | Host | IP | Notes |
|---|---|---|---|
| Attacker | SOC-LIN-01 | 10.10.30.100 | NetExec |
| Target | SOC-DC01 | 10.10.10.200 | Domain Controller, `soclab.local`, Windows Server 2022 Build 20348 |

Full topology and network segmentation: [`00-environment`](../../00-environment/).

## Setup

- Created OU `SprayLab` in AD with 5 test accounts: `spray1`–`spray5`.
- Edited the `Default Domain Controllers Policy` GPO:
  `Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies → Logon/Logoff → Audit Logon → Success and Failure`.
   this had to be enabled deliberately, it's not there on the default audit policy.

## Attack Execution

NetExec — authenticates against multiple Windows/AD protocols (SMB, WinRM, LDAP, MSSQL, SSH, RDP, WMI) in one command.

```
┌──(attacker㉿SOC-LIN-01)-[~]
└─$ netexec smb 10.10.10.200 -u spray1 spray2 spray3 spray4 spray5 -p 'Wiosna2026!'
SMB         10.10.10.200    445    SOC-DC01         [*] Windows Server 2022 Build 20348 x64 (name:SOC-DC01) (domain:soclab.local) (signing:True) (SMBv1:False)
SMB         10.10.10.200    445    SOC-DC01         [-] soclab.local\spray1:Wiosna2026! STATUS_LOGON_FAILURE
SMB         10.10.10.200    445    SOC-DC01         [-] soclab.local\spray2:Wiosna2026! STATUS_LOGON_FAILURE
SMB         10.10.10.200    445    SOC-DC01         [-] soclab.local\spray3:Wiosna2026! STATUS_LOGON_FAILURE
SMB         10.10.10.200    445    SOC-DC01         [-] soclab.local\spray4:Wiosna2026! STATUS_LOGON_FAILURE
SMB         10.10.10.200    445    SOC-DC01         [-] soclab.local\spray5:Wiosna2026! STATUS_LOGON_FAILURE
```

All 5 attempts failed on password, as expected (test accounts, password deliberately wrong).

## Telemetry / Observation

Source: Windows Security Event Log on SOC-DC01, forwarded by the Wazuh agent.

| Field | Value |
|---|---|
| Event ID | 4625 (An account failed to log on) |
| Host | SOC-DC01 |
| LogonType | 3 (network) |
| Authentication Package | NTLM |
| SubStatus | `0xc000006a` (wrong password) |
| Source IP | 10.10.30.100 |
| Target accounts | spray1, spray2, spray3, spray4, spray5 (5 distinct) |
| Time window | 05:36:45.622 – 05:36:45.708 (5 attempts in < 100 ms) |

[TODO: paste raw Wazuh JSON alert for one of the 4625 events]

The time window speaks for itself — that's not a human login cadence, it's an automated burst. Without correlation these 5 events look like 5 separate, unrelated failed logons.

## Detection

**Out-of-the-box:** a single failed logon matches Wazuh rule sid `60122`, level 5. On its own that's not alarming — users mistype passwords constantly.

**Correlation rule (written for this lab):**

```xml
<!-- 5+ failed logons against different accounts from the same IP within 5 minutes -->
<rule id="101030" level="10" frequency="5" timeframe="300">
  <if_matched_sid>60122</if_matched_sid>
  <same_field>win.eventdata.ipAddress</same_field>
  <different_field>win.eventdata.targetUserName</different_field>
  <description>Possible Password Spraying: 5+ unsuccessful Windows login attempt on different accounts from $(win.eventdata.ipAddress) within 5 minutes</description>
  <mitre>
    <id>T1110.003</id>
  </mitre>
</rule>
```

Logic: base rule 60122 has to match 5 times (`frequency="5"`) within a 300-second window (`timeframe="300"`), where all matches share the same `ipAddress` (`same_field`) but have a different `targetUserName` (`different_field`)  — without it, the rule would also fire on plain single-account brute-force, not just spraying across accounts.



## Analysis / IR

### L1 Triage

Within a fraction of a second (05:36:45.622–05:36:45.708), 5 failed logons (4625, LogonType 3) appeared from a single IP (10.10.30.100) against SOC-DC01, across 5 different accounts. Authentication via NTLM, SubStatus `0xc000006a` — wrong password.

**Verdict:** True Positive. Confirmed T1110.003 attempt (password spraying, Credential Access) against SOC-DC01 — a Tier 0 endpoint (Domain Controller). Attack conducted against 5 accounts (spray1–5), source 10.10.30.100. No further activity from this IP was observed after these attempts, within the analyzed window. No confirmed successful logon on any target account.

**Recommendation:** block the IP at the firewall, escalate to L2.

### L2 Triage

- IP verified as malicious (in this lab: the attacker machine, SOC-LIN-01).
- Target accounts checked — regular domain users, no privileged access.
- Action taken: blocked traffic from 10.10.30.100 at the firewall.
- Detection engineering: wrote correlation rule 101030 (see Detection section) — raises the default level 5 for a single event to level 10 for a confirmed spraying pattern.

**L1/L2 split in this scenario:** L1 does the initial triage based on the already-correlated alert — recognizes the pattern (one IP, many accounts, short window), issues a preliminary verdict and recommendation. L2 brings in context — IP reputation, impact on accounts (whether anything privileged was touched), enforces containment, and owns the detection improvement so L1 doesn't have to manually piece together 5 separate 4625 events next time.



## References

- MITRE ATT&CK — [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [NetExec (GitHub)](https://github.com/Pennyw0rth/NetExec)
