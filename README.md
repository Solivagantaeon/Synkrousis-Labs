# Synkrousis Home Lab | SOC Detection Engineering

[![SIEM](https://img.shields.io/badge/SIEM-Wazuh-3C82F8?style=flat-square&logo=wazuh&logoColor=white)](https://wazuh.com/)
[![Virtualization](https://img.shields.io/badge/Virtualization-Proxmox-E57000?style=flat-square&logo=proxmox&logoColor=white)](https://www.proxmox.com/)
[![C2](https://img.shields.io/badge/C2-Sliver-333333?style=flat-square&logo=hackthebox&logoColor=white)](https://github.com/BishopFox/sliver)
[![Logging](https://img.shields.io/badge/Logging-Sysmon-0078D6?style=flat-square&logo=microsoft&logoColor=white)]()
[![AD](https://img.shields.io/badge/Directory-Active%20Directory-0078D6?style=flat-square&logo=microsoft&logoColor=white)]()

*synkrousis* — from Greek *σύγκρουση*, collision or clash. The point where offensive tactics meet defensive monitoring.

---

## Lab Architecture

Everything runs on a single Proxmox host. The lab is segmented behind a pfSense firewall into three isolated VLANs — victim network, SOC, and attacker — modeled after a real enterprise environment.

```
                 ┌─────────────────────────┐
                 │      Home Router         │
                 │  192.168.1.1 / internet  │
                 └────────────┬─────────────┘
                              │
        ┌─────────────────────┼──────────────────────────────────┐
        │ PROXMOX HOST  (192.168.1.23)                            │
        │                     │                                   │
        │              ┌──────┴───────┐                           │
        │              │  pfSense VM  │                           │
        │              │   (VMID 301) │                           │
        │              └──────┬───────┘                           │
        │                     │ trunk: VLAN 10 / 20 / 30          │
        │      ┌──────────────┼───────────────┐                   │
        │      │              │               │                   │
        │  ┌───┴────┐   ┌─────┴─────┐   ┌─────┴─────┐            │
        │  │VLAN 10 │   │  VLAN 20  │   │  VLAN 30  │            │
        │  │VICTIM  │   │    SOC    │   │  ATTACK   │            │
        │  │AD+endp.│   │   Wazuh   │   │ attacker  │            │
        │  └────────┘   └───────────┘   └───────────┘            │
        └─────────────────────────────────────────────────────────┘
```

| VM              | OS                  | VLAN | Role                         |
|-----------------|---------------------|------|------------------------------|
| SOC-DC-01       | Windows Server 2022 | 10   | Domain Controller (AD + DNS) |
| SOC-WIN-10      | Windows 10 Pro      | 10   | Victim workstation           |
| wazuh-master    | Ubuntu 24.04        | 20   | Wazuh manager + cluster node |
| wazuh-worker    | Ubuntu 24.04        | 20   | Wazuh worker node            |
| wazuh-indexer-1 | Ubuntu 24.04        | 20   | OpenSearch indexer           |
| wazuh-indexer-2 | Ubuntu 24.04        | 20   | OpenSearch indexer           |
| SOC-LIN-01      | Kali Linux          | 30   | Attacker machine             |

---

## Labs

### Lab 001 — Initial Access & C2 via Sliver

Full attack simulation against the AD environment: PowerShell implant delivery, mTLS C2 session via Sliver, post-exploitation SAM dump. Analysis from both L1 (alert triage) and L3 (detection gap hunting) perspectives. Default Wazuh rules caught the SAM dump but missed the entire execution phase — 8 minutes of undetected activity. Closed the gap with a cascade of 4 custom rules.

**MITRE ATT&CK:** `T1059.001` `T1204.002` `T1036` `T1562.001`

**Key finding:** Default SIEM rules fire on noisy post-exploitation (credential dumping, registry abuse) but miss initial execution. The attacker had a full 8-minute window before any alert fired.

→ [Writeup](lab-001-c2-sliver/docs/lab-01-c2-sliver.md) · [Detection rules](lab-001-c2-sliver/detection-rules/wazuh/execution-cascade.xml)

---

### Lab 002 — Network Segmentation with pfSense

Migrated the lab from a flat `192.168.1.0/24` network to a segmented architecture behind pfSense. Three isolated VLANs with explicit firewall rules controlling inter-zone traffic. Wazuh cluster (4 nodes) migrated to the SOC VLAN with updated configs across all components.

**Key decisions:** victim network can reach Wazuh agent ports but can't see the SOC; attacker VLAN can reach the victim but is blocked from the SOC; management access from the home network goes through pfSense WAN rules only.

→ [Writeup](lab-002-network-segmentation/docs/writeup.md)

---

## Repository Structure

```
synkrousis-labs/
├── README.md
├── lab-001-c2-sliver/
│   ├── docs/
│   │   └── lab-01-c2-sliver.md
│   └── detection-rules/
│       └── wazuh/
│           └── execution-cascade.xml
└── lab-002-network-segmentation/
    ├── docs/
    │   └── writeup.md
    └── firewall-rules/
```
