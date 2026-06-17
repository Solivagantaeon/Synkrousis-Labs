# Incident 01 — RDP Brute-Force Leading to Successful Logon

**Tactic:** Initial Access / Credential Access
**MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing), T1078 (Valid Accounts)
**Severity:** High — verdict: escalate
**Detected by:** Wazuh (custom correlation rule 555555)

---

## Summary

An external host on the ATTACK segment conducted an RDP password-guessing
attack against a domain-joined Windows 10 workstation, targeting a local
account with administrative privileges. After a series of failed attempts the
attacker authenticated successfully, establishing initial access to the host.

Each stage was detected in Wazuh. Stock rules flagged the failed attempts and
their aggregation, and a custom correlation rule tied the failure burst to the
subsequent success — the signal that distinguishes a defended attempt from a
compromised credential.

---

## Environment

| Role     | Host         | IP           | Segment          |
| -------- | ------------ | ------------ | ---------------- |
| Attacker | SOC-LIN-01   | 10.10.30.103 | VLAN 30 (ATTACK) |
| Target   | SOC-WIN-10   | 10.10.10.150 | VLAN 10 (VICTIM) |
| SIEM     | wazuh-master | 10.10.20.243 | VLAN 20 (SOC)    |

Target account: `AdminLokalny` — local account, member of Administrators.

---

## Timeline

| Time (approx) | Event                                | Wazuh rule.id | Win Event ID |
| ------------- | ------------------------------------ | ------------- | ------------ |
| T+0s          | First failed logon from 10.10.30.103 | 60122         | 4625         |
| T+0–25s       | ~14 failed logons, same source IP    | 60122 (×14)   | 4625         |
| T+12s         | Failure burst aggregated             | 60204         | 4625         |
| T+26s         | Successful logon, same source IP     | 92657         | 4624         |
| T+26s         | Special privileges assigned to logon | 67028         | 4672         |
| T+26s         | **Correlation: brute-force success** | **100600**    | —            |

All authentication events carried `logonType 3` (network) and
`authenticationPackageName NTLM`, consistent with a remote RDP logon driven by
an external tool rather than interactive console access.

---

## Indicators

- Source IP: `10.10.30.103` (ATTACK segment — outside the victim network)
- Targeted account: `AdminLokalny` (privileged local account)
- Logon type: 3 (network)
- Auth package: NTLM / NTLM V2
- Workstation name in events: `SOC-LIN-01`
- Pattern: high-rate 4625 burst from a single source, terminated by a 4624
  from the same source within a short window

---

## Analysis

The defining characteristic of this incident was a burst of failed logon attempts from a single source, immediately followed by a successful logon from the same IP.

Stock Wazuh rules detect both events separately - multiple logon failures (60204) and a successful Windows logon (92657), but do not correlate them into a single high-severity alert. I wrote a custom correlation rule (100600) to close that gap: it fires when a successful logon follows a failure burst from the same source within a 120-second window.

---

## Verdict

**Escalate.** A privileged local account on a domain-joined host was
successfully accessed via remote password guessing from outside the victim
network. This constitutes confirmed initial access and is the entry point for
follow-on activity (credential theft, lateral movement).



---

## Detection artifacts

- Rule: [`detection-rules/01-rdp-bruteforce.xml`](../detection-rules/01-rdp-bruteforce.xml)
- Attack reproduction: [`attacks/01-rdp-bruteforce.md`](../attacks/01-rdp-bruteforce.md)
