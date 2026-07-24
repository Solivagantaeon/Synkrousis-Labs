# T1204.002 - Malicious Macro Execution via LibreOffice Document

| | |
|---|---|
| Module | Execution |
| Technique | T1204.002 User Execution: Malicious File, T1059.001 Command and Scripting Interpreter: PowerShell, T1059.003 Command and Scripting Interpreter: Windows Command Shell |
| Tactic | Execution (TA0002) |
| Environment | [00-environment](../../00-environment/) |

## Summary

Built and opened a LibreOffice Writer document with a macro set to auto-run on open (`Tools > Customize > Events > Open Document`), chaining `soffice.bin -> cmd.exe -> powershell.exe` to launch `calc.exe` as a benign stand-in. Sysmon EID 1 captured the whole chain and proved the parent-child linkage by `processGuid`, but the two out-of-the-box Wazuh alerts fired only at level 3 and 4 and did not recognize the office-spawns-shell pattern. Wrote a custom rule (105000) that keys on the `parentImage -> image` relationship instead. Verdict: confirmed execution, caught structurally rather than by payload content.

## Environment

| Role | Host | IP | Notes |
|---|---|---|---|
| Attacker / Victim | [TODO: hostname alias per 00-environment] | 10.10.10.150 | Windows host, LibreOffice installed, macro security set to Low. Same machine authored and opened the file. |
| Monitoring | Wazuh manager | - | Ingests the Sysmon Operational channel (Event ID 1, Process Creation) forwarded from 10.10.10.150. LibreOffice has no native macro-execution logging, so all visibility comes from Sysmon process-creation telemetry. |

Single-host lab: the file was authored and opened on the same machine. No separate attacker host, no delivery vector. The goal was to test detection of macro-based execution in isolation, not a full delivery chain. Full topology and host provisioning: [00-environment](../../00-environment/).

## Red Team

### Setup

Built a LibreOffice Writer document (`Hacked.odt`) with a macro wired to auto-execute on file open, via `Tools > Customize > Events > Open Document`, bound to the macro below.

Note: this is LibreOffice Basic, not Microsoft VBA. The syntax is VBA-like (shared heritage), but it runs in LibreOffice's own Basic runtime, not the VBA engine used by Microsoft Office. Worth being precise about, since the two are often conflated.

```basic
Sub MojeMakro()
    Dim payload As String
    payload = "cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ""Start-Process calc.exe"""
    Shell payload, vbHide
End Sub
```

The macro shells out to `cmd.exe`, which calls `powershell.exe` with `-NoProfile -ExecutionPolicy Bypass`, which launches `calc.exe`. `calc.exe` is a harmless stand-in for arbitrary code; the point is the execution chain, not the payload. `Shell ... vbHide` runs the command with a hidden window.

Macro security in LibreOffice (`Tools > Options > LibreOffice > Security > Macro Security`) was set to Low for this test. The default is Medium, which shows a confirmation dialog before running any macro on open. Low skips that prompt, so the macro fires with no user interaction beyond opening the file. This is an artificial condition and is called out on purpose: on a host with default settings this chain does not run silently, it needs a user to click "Enable Macros" or a pre-set Low configuration. A Low macro-security setting on a real endpoint would itself be a hardening finding.

### Execution

File authored and opened on the same host, `10.10.10.150`. No delivery vector (email, share, USB) was exercised; the goal was isolated testing of macro auto-execution detection, not a phishing chain.

Opening `Hacked.odt` triggered the macro automatically (per the Low macro security setting), which spawned the `soffice.bin -> cmd.exe -> powershell.exe -> calc.exe` chain. `calc.exe` launching confirmed execution.

Execution time: `14:46:20.841 UTC` (Sysmon `utcTime` of the first process-creation event; see Telemetry).

Evidence: [TODO: evidence/<screenshot filename>.png - calc.exe running / process tree]

## Telemetry and Observation

Source: Sysmon Operational channel, Event ID 1 (Process Creation), from 10.10.10.150, forwarded to Wazuh. All fields below are `data.win.eventdata.*`. LibreOffice logs nothing about the macro itself, so Sysmon is the only reason this is visible at all.

Two process-creation events cover the chain:

| Time (UTC, `utcTime`) | Event ID | Image | Parent Image |
|---|---|---|---|
| 14:46:20.841 | 1 | `C:\Windows\System32\cmd.exe` | `C:\Program Files\LibreOffice\program\soffice.bin` |
| 14:46:20.970 | 1 | `...\WindowsPowerShell\v1.0\powershell.exe` | `C:\Windows\System32\cmd.exe` |

Same execution context across both events:
- `user` = `SOCLAB\Administrator` in both. `integrityLevel` = High in both, so the chain runs elevated, not as a constrained standard user.
- `logonId` = `0xee019` in both, which confirms one logon session rather than two coincidental logons under the same account name.

Parent-child linkage is proven by GUID, not by PID or image name (PIDs get reused, GUIDs do not): the `processGuid` of event 1 (`{20649595-d7bc-6a60-9901-000000004a00}`) equals the `parentProcessGuid` of event 2. The 129 ms gap between the two `utcTime` values (14:46:20.841 -> 14:46:20.970) is consistent with automated back-to-back process spawning, not human interaction.

Command lines (`commandLine`):
- Event 1: `cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process calc.exe"`
- Event 2: `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process calc.exe"`

The origin is in event 1's `parentCommandLine`: the `swriter.exe` invocation opening `Hacked.odt` from the user's Desktop, which pins the exact file and location that started the chain.

## Detection

The two alerts that fired out of the box came from Wazuh's base Sysmon process-creation rules, at level 4 and level 3. Both are generic: they log the process starts but key on nothing about the `parentImage -> image` relationship, so neither surfaced the actual signal, an office binary (`soffice.bin`) spawning a shell. Low severity, no context. That gap is the finding, and the reason for the custom rule below.

| Rule ID | Level | Logic | MITRE |
|---|---|---|---|
| 61603 | 0 | Base Sysmon EID 1 process-creation telemetry rule. Raw, unscored. Used only as the `if_sid` anchor for the custom rule. | - |
| [TODO] | 4 | Base Wazuh Sysmon process-creation rule, generic. | - |
| [TODO] | 3 | Base Wazuh Sysmon process-creation rule, generic. | - |
| 105000 | 8 | Custom. Office application (`parentImage`) spawning an interpreter or LOLBin (`image`). See below. | T1204.002, T1059 |

### Detection engineering - custom rule 105000

```xml
<rule id="105000" level="8">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)\\(winword|excel|powerpnt|outlook|msaccess|onenote|visio|mspub|soffice|swriter|scalc|simpress)\.(exe|bin)$</field>
  <field name="win.eventdata.image" type="pcre2">(?i)\\(cmd|powershell|pwsh|wscript|cscript|mshta|regsvr32|rundll32|bitsadmin|certutil|msbuild)\.exe$</field>
  <description>Office application spawned a command/script interpreter or LOLBin - possible malicious macro</description>
  <mitre>
    <id>T1204.002</id>
    <id>T1059</id>
  </mitre>
</rule>
```

Anchor: `if_sid 61603`, the raw Sysmon EID 1 telemetry rule, not any default Wazuh detection. The custom rule sits directly on top of the telemetry so it does not inherit the generic rules' blind spot.

Logic: both fields must match (AND). `parentImage` is an office application (Microsoft Office or LibreOffice binaries), `image` is an interpreter or LOLBin (`cmd`, `powershell`, `pwsh`, `wscript`, `cscript`, `mshta`, `regsvr32`, `rundll32`, `bitsadmin`, `certutil`, `msbuild`). This is a structural pattern: it keys on the parent-child relationship and does not look at `commandLine` content at all. In this lab it matches on `soffice.bin -> cmd.exe`.

Level 8, deliberately moderate. The rule is broad by construction (11 possible parents against 11 possible children), so its false-positive surface is wider than a content-specific rule; and because it does not evaluate the payload, it should not carry the weight of a rule that has confirmed obfuscation or download behavior. It is a tripwire, not a verdict.

False-positive risk: on a clean single-user host like this lab, effectively zero, nothing legitimately drives an office app to spawn a shell. On a real estate it needs a baseline, since some environments have signed macros, add-ins, or deployment/templating documents that legitimately call scripts; those would need an allowlist. Tuning path: a higher-severity sibling rule that adds a `commandLine` regex for the usual weaponization markers (`-enc`, `-e `, `bypass`, `downloadstring`, `frombase64string`) could escalate confirmed-malicious cases to level 12+, while 105000 stays the broad early trip.

MITRE: T1204.002 (User Execution: Malicious File) for the macro-open origin, plus T1059 (Command and Scripting Interpreter) at the parent level because the child can be any of several interpreters, not just PowerShell.

Rule lives in [`rules/`](rules/). [TODO: confirm the two base rule IDs (level 3 and 4) from the alert output to fill the table above.]

## Analysis and IR

### L1 triage

Observed: two Sysmon EID 1 events on 10.10.10.150, 129 ms apart, forming `soffice.bin -> cmd.exe -> powershell.exe`, running as `SOCLAB\Administrator` at High integrity, single logon session (`0xee019`). PowerShell launched with `-NoProfile -ExecutionPolicy Bypass`.

Read: an office application spawning a command shell is the classic malicious-document execution pattern, not normal LibreOffice behavior. `-ExecutionPolicy Bypass` is a standard evasion flag. Sub-second, back-to-back spawning is automated, not a user typing commands. Running at High integrity as Administrator raises the impact ceiling.

Decision: treat as confirmed execution and escalate. The two low-level base alerts under-rate this badly, so it would be easy to miss on severity alone; the parent-child chain is what makes the call.

### L2 verdict

The chain is proven end to end by the GUID linkage (event 1 `processGuid` = event 2 `parentProcessGuid`), so this is not two unrelated processes that happen to share a name. Confirmed code execution via a document macro.

Payload assessment from the command lines: the final action is only `Start-Process calc.exe`. No `-enc` / base64, no `DownloadString` or other network fetch, no `-WindowStyle Hidden`. So the payload itself is inert and there is no obfuscation or C2 indicator, but the execution technique is fully real. (Note: the process ran hidden anyway, but via the macro's `Shell ... vbHide`, not via a PowerShell flag, so it does not show up as `-WindowStyle Hidden` in `commandLine`.) In a real incident the verdict would be successful execution with the follow-on payload swappable for anything; here the payload is benign by design.

### IOCs

- File: `Hacked.odt` on `C:\Users\Administrator\Desktop\`
- Process chain: `soffice.bin -> cmd.exe -> powershell.exe`
- Command line: `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process calc.exe"`
- Host: 10.10.10.150; account: `SOCLAB\Administrator` (High integrity), logon `0xee019`

## Conclusions and Gotchas

Visibility boundary. Sysmon EID 1 is the only reason any of this is visible. LibreOffice logs nothing about the macro firing, so without command-line process auditing (Sysmon, or Windows 4688 with command-line auditing enabled) the entire chain is invisible. Everything in triage was reconstructed from process-creation telemetry, not from any application log.

The signal is structural, not the file and not the payload. An `.odt` is not inherently malicious, and the payload here is a calculator. What makes this detectable is the parent-child anomaly: an office binary spawning a shell or LOLBin. That is what rule 105000 keys on, and it is why the rule ignores `commandLine` content entirely.

The base rules fired but missed it, and that is the core finding. The out-of-the-box Sysmon rules logged the process starts at level 3 and 4 with no notion that an office app spawning `cmd.exe` is worth a second look. Severity alone would have buried this in noise. A detection that keys on the relationship, not the individual process, is what closes the gap.

Pattern versus content is a deliberate tradeoff. 105000 is a broad structural tripwire at level 8: it catches the technique early but cannot tell an inert `calc.exe` from a weaponized encoded payload. That separation is intentional, structure trips the alert, payload severity is decided in triage or by a stacked content-aware rule. It is worth being explicit that this rule would fire identically whether the macro launched a calculator or ransomware.

Macro security Low did a lot of work. It removed the "Enable Macros" gate, so the macro ran on open with no interaction. Default Medium changes the scenario: the user has to click through a prompt, and a Low setting on a real endpoint is itself a hardening finding worth its own detection.

LibreOffice Basic is not VBA, and it matters for hunting. The artifacts differ from a Microsoft Office maldoc: the parent process is `soffice.bin` / `swriter.exe`, not `winword.exe`. A rule or hunt that only lists Microsoft Office binaries misses this entirely, which is why the 105000 regex includes the LibreOffice binaries alongside the Office ones.

Negative indicators are part of the verdict. No obfuscation, no network fetch, no PowerShell hidden-window flag. Calling out what is absent is how "technique confirmed" gets separated from "payload severity", and it is the kind of detail that keeps a triage honest rather than assuming the worst or dismissing it.

## References

- MITRE ATT&CK, T1204.002 User Execution: Malicious File
- MITRE ATT&CK, T1059.001 Command and Scripting Interpreter: PowerShell
- MITRE ATT&CK, T1059.003 Command and Scripting Interpreter: Windows Command Shell
- Sysmon Event ID 1 (Process Creation) documentation
- [TODO: Atomic Red Team T1204.002 test reference if you used one]