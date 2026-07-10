# Synkrousis Home Lab | SOC Detection Engineering

[![SIEM](https://img.shields.io/badge/SIEM-Wazuh-3C82F8?style=flat-square&logo=wazuh&logoColor=white)](https://wazuh.com/)
[![Virtualization](https://img.shields.io/badge/Virtualization-Proxmox-E57000?style=flat-square&logo=proxmox&logoColor=white)](https://www.proxmox.com/)
[![Logging](https://img.shields.io/badge/Logging-Sysmon-0078D6?style=flat-square&logo=microsoft&logoColor=white)]()
[![AD](https://img.shields.io/badge/Directory-Active%20Directory-0078D6?style=flat-square&logo=microsoft&logoColor=white)]()

*synkrousis* — from Greek *σύγκρουση*, collision or clash. The point where offensive tactics meet defensive monitoring.

---

## Lab Architecture

Everything runs on a single Proxmox host. The lab is segmented behind a pfSense firewall into three isolated VLANs — victim network, SOC, and attacker — modeled after a real enterprise environment.

```
                 ┌─────────────────────────┐
                 │      Home Router        │
                 │  192.168.1.1 / internet │
                 └────────────┬────────────┘
                              │
        ┌─────────────────────┼──────────────────────────────────┐
        │ PROXMOX HOST  (192.168.1.23)                           │
        │                     │                                  │
        │              ┌──────┴───────┐                          │
        │              │  pfSense VM  │                          │
        │              │   (VMID 301) │                          │
        │              └──────┬───────┘                          │
        │                     │ trunk: VLAN 10 / 20 / 30         │
        │      ┌──────────────┼───────────────┐                  │
        │      │              │               │                  │
        │  ┌───┴────┐   ┌─────┴─────┐   ┌─────┴─────┐            │
        │  │VLAN 10 │   │  VLAN 20  │   │  VLAN 30  │            │
        │  │VICTIM  │   │    SOC    │   │  ATTACK   │            │
        │  │AD+endp.│   │   Wazuh   │   │ attacker  │            │
        │  └────────┘   └───────────┘   └───────────┘            │
        └────────────────────────────────────────────────────────┘
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
