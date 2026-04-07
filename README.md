#  Purple Team Home Lab — SOC Detection Engineering

[![SIEM](https://img.shields.io/badge/SIEM-Wazuh-3C82F8?style=flat-square&logo=wazuh&logoColor=white)](https://wazuh.com/)
[![OS](https://img.shields.io/badge/OS-Windows%2010%20%7C%20Server%202022-0078D6?style=flat-square&logo=windows&logoColor=white)]()
[![OS](https://img.shields.io/badge/OS-Ubuntu%2024.04-E95420?style=flat-square&logo=ubuntu&logoColor=white)]()
[![Virtualization](https://img.shields.io/badge/Virtualization-Proxmox-E57000?style=flat-square&logo=proxmox&logoColor=white)](https://www.proxmox.com/)
[![C2](https://img.shields.io/badge/C2-Sliver-333333?style=flat-square&logo=hackthebox&logoColor=white)](https://github.com/BishopFox/sliver)
[![Logging](https://img.shields.io/badge/Logging-Sysmon-0078D6?style=flat-square&logo=microsoft&logoColor=white)]()
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-E4002B?style=flat-square)](https://attack.mitre.org/)
[![AD](https://img.shields.io/badge/Directory-Active%20Directory-0078D6?style=flat-square&logo=microsoft&logoColor=white)]()

synkrousis from greek *σύγκρουση*, meaning collision or clash

In this lab, it represents the intersection where offensive tactics meet defensive monitoring. This clash is how i find gaps in my defenses

## Why I Built This
Synkrousis Labs is my personal research environment dedicated to Purple Teaming and SOC Detection Engineering. I built this lab to move beyond theoretical alerts and analyze the practical mechanics of attack chains. The primary focus of this repository is executing realistic adversary behaviors, analyzing the resulting raw telemetry, identifying visibility gaps, and engineering custom SIEM rules to detect advanced techniques.




## Lab Architecture

Everything runs on a single physical server with Proxmox.It is designed to simulate realistic corporate network environment

| VM               | OS                  | Role                                          |
| ---------------- | ------------------- | --------------------------------------------- |
| **SOC-DC01**     | Windows Server 2022 | Domain Controller (AD DS + DNS)               |
| **SOC-WIN10-01** | Windows 10 Pro      | Victim Workstation                            |
| **SOC-WAZUH-01** | Ubuntu Server 24.04 | Wazuh SIEM/EDR — log collection & correlation |


```
┌─────────────────────────────────────────────────┐
│                  PROXMOX HOST                   │
│                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ SOC-DC01 │  │SOC-WIN10 │  │ SOC-WAZUH-01 │   │
│  │ (AD/DNS) │  │ (Target) │  │    (SIEM)    │   │
│  │ .1.200   │  │ .1.110   │  │   .1.150     │   │
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘   │
│       └──────────────┴───────────────┘          │
│               192.168.1.0/24                    │
└─────────────────────────────────────────────────┘
```

## Labs

### Lab 1 — Initial Access & C2 via Sliver + Detection Gap Analysis

Full attack simulation: delivering an implant via PowerShell, establishing a C2 session (mTLS), post-exploitation (SAM dump). Then analysis from SOC L1 perspective (triaging a level 14 alert) and L3 perspective (identifying an 8-minute visibility gap + writing a cascade of custom detection rules).

**MITRE ATT&CK:** `T1059.001` `T1204.002` `T1036` `T1562.001`

**Key finding:** Default Wazuh rules caught the SAM dump (level 14) but completely missed the implant execution. The attacker had ~8 minutes of undetected activity. I wrote a cascade of 4 rules (100510–100513) that cut detection time to seconds.

→ [Full writeup](docs/lab-01-c2-sliver.md)



## Custom Detection Rules

The main deliverable from Lab 1 — a cascade of Wazuh rules that close the visibility gap:

```
100510 (level 0) ─── gate: interpreter spawned exe from writable path
    │
    ├── 100511 (level 11) ─── exe not on whitelist → ALERT
    ├── 100512 (level 12) ─── exe uses system process name → ALERT (masquerading)
    └── 100513 (level 10) ─── exe in non-standard root dir → ALERT
```

→ [Rule files + documentation](detection-rules/wazuh/)

## What I Learned

- Default SIEM rules catch the loud stuff (credential dumping, registry abuse) but **miss the execution phase** — the attacker had a full 8 minutes of free movement before a high-level alert fired
- Writing a rule cascade taught me how the Wazuh engine actually works — child rules, negation, pcre2 regex, silent tagging with `no_log`
- Real SOC analysis works backwards: you start from the alert, pivot on parent process, and hunt through level 0 logs to reconstruct the full chain
- Standing up the infrastructure itself (AD, DNS, Sysmon, Wazuh agents) involved a ton of troubleshooting that no documentation fully prepares you for

## Repository Structure

```
synkrousis-labs/
├── README.md
├── lab-001-c2-sliver/
│   ├── writeup.md
│   ├── detection-rules/
│   │   └── execution-cascade.xml
│   ├── report/
│   │   └── incident-report.pdf
│   └── screenshots/
├── lab-002-credential-access-wmi/
│   ├── writeup.md
│   ├── detection-rules/
│   └── screenshots/
├── lab-003-.../
│   └── ...
└── infrastructure/
    └── README.md 
```
