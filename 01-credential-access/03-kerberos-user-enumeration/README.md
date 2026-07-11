# T1087.002 - Kerberos User Enumeration and Password Spraying

| | |
|---|---|
| **Module** | Credential Access |
| **Technique** | T1087.002 Account Discovery: Domain Account (enumeration phase), T1110.003 Password Spraying (spray phase), T1078.002 Valid Accounts: Domain Accounts (confirmed successful authentication) |
| **Tactic** | Discovery ([TA0007](https://attack.mitre.org/tactics/TA0007/)), Credential Access ([TA0006](https://attack.mitre.org/tactics/TA0006/)) |
| **Environment** | [`00-environment`](../../00-environment/) |

## Summary

I enumerated valid domain accounts against the soclab.local DC with kerbrute's Kerberos `userenum`, then ran a password spray with kerbrute's `passwordspray`, first with a deliberately wrong password, then the real lab password. The second spray authenticated successfully against 10 domain accounts, including two service accounts (svc-sql, svc-backup). On the blue side the enumeration and spray were visible in the DC security log (events 4768 and 4771), and two custom Wazuh correlation rules fired: 101050 caught the spray pattern regardless of outcome, and 101060 escalated to critical once the spray produced a successful logon. Verdict: confirmed compromise.

## Environment

| Role | Host | IP | Notes |
|---|---|---|---|
| Attacker | SOC-LIN-01 | 10.10.30.100 | kerbrute v1.0.3 |
| Target | SOC-DC01 | 10.10.10.200 | Domain Controller, `soclab.local`, Windows Server 2022 Build 20348 |
| Monitoring | Wazuh manager | - | Ingests Windows Security events forwarded from SOC-DC01 |

Attacker and DC sit in different segments (10.10.30.0/24 and 10.10.10.0/24). Full topology, segmentation, and AD account provisioning for this lab: [`00-environment`](../../00-environment/).

## Setup

```bash
cd /opt
sudo wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O kerbrute
sudo chmod +x kerbrute
```

## Attack Execution

### Phase 1 - Username Enumeration

```bash
sudo ./kerbrute userenum -d soclab.local --dc 10.10.10.200 -o wyniki_enum.txt userlist.txt
```

kerbrute sends a TGT request (AS-REQ) per candidate username with no pre-authentication. A `PRINCIPAL UNKNOWN` response means the username does not exist; a prompt for pre-auth means it does. Either way this never counts as a login failure, so it cannot trip account lockout.

### Phase 2 - Password Spraying

First spray, deliberately wrong password:

```bash
./kerbrute passwordspray -d soclab.local --dc 10.10.10.200 -v validusers.txt 'ZlyStrzal2025!'
```

Second spray, real lab password:

```bash
./kerbrute passwordspray -d soclab.local --dc 10.10.10.200 -v validusers.txt 'L@bPass2026!'
```

## Telemetry and Observation

All authentication telemetry came from the DC (SOC-DC01) Windows Security log. Two details up front:

Kerberos logs the two failure modes on different event IDs. A non-existent principal shows as **4768 with status 0x6**; an existing account with a bad password shows as **4771 with status 0x18** (Windows logs 4771, not 4768, for pre-auth failures). A success is **4768 with status 0x0**, meaning a TGT was issued.

The source appeared both as `10.10.30.100` and its IPv4-mapped IPv6 form `::ffff:10.10.30.100`, so each Kerberos event was logged twice, once per representation. This matters for tuning and for counting: it doubles the raw event count.

Events observed, all on 2026-07-11:

| Time (approx) | Event ID | Status | Meaning | Accounts |
|---|---|---|---|---|
| 19:25:34 | 4768 | 0x6 | KDC_ERR_C_PRINCIPAL_UNKNOWN, account does not exist | notauser1, notauser2, qhostaccount (several AS-REQ in a ~16 ms burst) |
| 19:30:28 | 4768 | 0x6 | account does not exist | non-existent test names |
| 19:30:28 | 4771 | 0x18 | KDC_ERR_PREAUTH_FAILED, account exists, wrong password | rtydraniu |
| 19:32:22 | 4768 | 0x0 | KDC_ERR_NONE, TGT issued, authentication succeeded | 10 accounts (see verdict) |

The two spray windows line up with the two spray commands above. The 19:30:28 window (all failures) is the first spray with the wrong password; the 19:32:22 window (successes) is the second spray with the real password.

## Detection

Detection is Wazuh, reading the Windows Security eventchannel from SOC-DC01. Three rules are relevant:

| Rule ID | Level | Logic | MITRE |
|---|---|---|---|
| 60103 | 5 | Base rule for 4768 with severity AUDIT_SUCCESS. Fires on every legitimate logon, so on its own it is noise. Used only as an `if_sid` condition for the correlation rule below. | - |
| 101050 | 12 | Correlation: same `ipAddress`, different `targetUserName`, 5 hits in 300 s. Detects the spray pattern regardless of whether any login succeeded. | T1110.003 |
| 101060 | 15 | Correlation: same conditions as 101050 plus a success condition (`if_sid` 60103). Fires only when the spray produced a successful logon. | T1110.003, T1078 |

101050 and 101060 are my custom rules; 60103 is the base 4768 success rule they chain off.

What fired (19:34:15 to 19:34:16):
- 101060, level 15: "Password spray SUCCESSFUL", account jan.kowalski
- 101050, level 12: "Possible Password Spraying", account qhostaccount

The account named on each alert is just the target of the single event that pushed the counter over the threshold, not the full victim set. 101050 named qhostaccount, which does not even exist. The real list of compromised accounts has to be reconstructed from the underlying 4768/0x0 events, not read off the alert field.

## Analysis and IR

### L1 triage

Observed: Kerberos traffic from a single source (10.10.30.100) to many domain accounts in sub-second windows, in two phases. Phase 1 (~19:25:34) was 4768/0x6 against names that do not exist. Phase 2 (~19:30:28) added 4771/0x18 against rtydraniu, an account that does exist.

Read: 4768/0x6 is KDC_ERR_C_PRINCIPAL_UNKNOWN (unknown principal); 4771/0x18 is KDC_ERR_PREAUTH_FAILED (account exists, bad password). A dozen requests from one IP to different accounts in a fraction of a second is not a single user. The shape (name enumeration turning into logins across many accounts) is automated credential access.

Decision: escalate to L2. At this point only failures are visible (0x6, 0x18), but the enumeration-into-spray shape means the same window has to be checked for successes (4768/0x0). Verification priority: the service accounts svc-sql and svc-backup.

### L2 verdict

Single source (10.10.30.100), whole thing inside a few minutes:

| Time (approx) | Phase | What happened |
|---|---|---|
| 19:25:34 | Enumeration | 4768/0x6, probing account names |
| 19:30:28 | Spray, attempts | 4768/0x6 plus 4771/0x18 on rtydraniu |
| 19:32:22 | Spray, success | 4768/0x0 on 10 accounts |
| 19:34:15 | Detection | 101050 and 101060 fired |

Confirmed compromise. In the 19:32:22 window there were 20 events of 4768/0x0 (audit success) across 10 unique accounts, each account appearing twice (once as 10.10.30.100, once as `::ffff:10.10.30.100`). A valid TGT issued means the authentication succeeded.

Compromised (10):
- jan.kowalski, anna.nowak, robert.dabrowski, piotr.zielinski
- katarzyna.wojcik, tomasz.kaminski, agnieszka.szymanska, m.lewandowska
- svc-sql, svc-backup (service accounts, priority)

Not compromised: rtydraniu (exists, wrong password), qhostaccount / notauser1 / notauser2 (do not exist).

There is a roughly two minute gap between the first success (19:32:22) and the alert (19:34:15). That is real detection latency and worth noting as a metric. I have not pinned down the exact cause from the logs alone: it is either the correlation window accumulating enough events to cross the threshold or ingestion delay, and separating the two would need the rule timing and the agent and ingest timestamps side by side.

### Containment and remediation

1. Reset passwords on all 10 compromised accounts. Priority: svc-sql, svc-backup.
2. Revoke active TGTs and sessions. For the service accounts this means changing the password and restarting the services that use them, otherwise cached tickets stay valid.
3. Isolate or block 10.10.30.100 at the network layer.
4. Establish what svc-sql and svc-backup can reach (databases, backups) and put those systems under priority monitoring.

## IOCs

- Source: 10.10.30.100, also seen as `::ffff:10.10.30.100`
- Events: 4768 status 0x6 (unknown principal) and 0x0 (success), 4771 status 0x18 (pre-auth failed)
- Wazuh rules that fired: 101050, 101060 (base rule 60103)
- Accounts of note: the 10 compromised accounts listed above, plus the probed or failed names qhostaccount, notauser1, notauser2, rtydraniu

## Conclusions and Gotchas

- Username enumeration is the blind spot here, and the Windows event log cannot close it. kerbrute `userenum` never generates a logon failure and cannot trip lockout. The names that miss (non-existent accounts) do log as 4768/0x6, which is why they show up in the telemetry above, but the healthy valid accounts kerbrute actually confirms produce no event at all during enumeration; only stale accounts (disabled, locked, or expired) leave a 4768 on a probe. So the log records the misses and hides the hits, and 4768/0x6 on its own is ambiguous anyway, since benign typos and misconfigured clients produce the same code. Kerberos auditing (Audit Kerberos Authentication Service, success and failure) is already fully enabled on the DC and still cannot reliably surface this phase, so catching enumeration in this environment needs network-level visibility over the AS-REQ traffic, which is what Zeek covers. The valid accounts enumerated in Phase 1 only became visible to the event pipeline later, as the 4768/0x0 spray successes.
- Kerberos spraying dodges the event most people watch. Per ATT&CK, attackers use LDAP and Kerberos auth precisely because it avoids the high-visibility Windows logon-failure event 4625 that failed SMB attempts produce. That is why detection here has to key on 4768 and 4771 rather than 4625. If your alerting only watches 4625, this whole chain is invisible.
- Know your status codes, and know which event carries them. The triage hinges on three: 4768/0x6 (name does not exist), 4771/0x18 (name exists, wrong password), 4768/0x0 (success). Note the failure modes split across two event IDs, not one. Failures alone (0x6, 0x18) are only attempts; the verdict flips to compromise on the 0x0 events. This is exactly why L1 escalated instead of closing on "just failed logins".
- Alert on success, not just on the pattern. Splitting the logic into 101050 (pattern) and 101060 (pattern plus success) means a spray that fails is a medium signal and a spray that lands is critical. The critical alert is high confidence precisely because a success inside a single-source, many-user burst is hard to explain away.
- The `::ffff:` double-logging is a real trap. Every Kerberos event showing up under both the IPv4 and the IPv4-mapped IPv6 address doubles the raw count, so the 20 success events are 10 real authentications. A correlation threshold set naively against these counts fires earlier than expected, and, more importantly, an account count read straight off raw events is double the truth if the duplication is not accounted for.
- Visibility boundary. Everything here is reconstructed from the DC's Kerberos logging. There is no EDR or host telemetry on SOC-LIN-01, so the kerbrute process, the wordlists, and the local output file are not visible. From the DC side I can prove the enumeration, the spray, and which accounts authenticated, but not what ran on the attacker host or what happened after the tickets were issued. Post-compromise actions with the stolen svc-sql or svc-backup tickets would only show up in logging on the systems those accounts touch, which is the point of containment step 4.

## References

- MITRE ATT&CK, [T1087.002 Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/)
- MITRE ATT&CK, [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- MITRE ATT&CK, [T1078.002 Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)
- kerbrute, [GitHub](https://github.com/ropnop/kerbrute)
- Securonix, [Hunting Kerbrute: Analysis, Detection and Mitigation of Kerberos Attacks in Active Directory](https://www.securonix.com/blog/hunting-kerbrute-analysis-detection-and-mitigation-of-kerberos-attacks-in-active-directory/)
- Microsoft, [Event 4768: A Kerberos authentication ticket (TGT) was requested](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- Microsoft, [Event 4771: Kerberos pre-authentication failed](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771)
