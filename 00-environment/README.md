# Lab 002 — Network Segmentation with pfSense

The lab originally ran on a flat `192.168.1.0/24` network - every machine could reach every other machine with no controls in place. C2 traffic would have leaked freely into the home network, and the attacker VM could see the SOC. This lab documents migrating the entire environment behind a pfSense firewall with VLAN segmentation.

---

## Architecture

```
                 ┌─────────────────────────┐
                 │      Home Router        │
                 │  192.168.1.1 / internet │
                 └────────────┬────────────┘
                              │ (home network 192.168.1.0/24)
                              │
        ┌─────────────────────┼──────────────────────────────────┐
        │ PROXMOX HOST  (192.168.1.23)                           │
        │                     │                                  │
        │              ┌──────┴───────┐                          │
        │   WAN (vtnet0)│  pfSense VM  │ LAN trunk (vtnet1)      │
        │  192.168.1.141│   (VMID 301) │ → vmbr1 (VLAN-aware)    │
        │              └──────┬───────┘                           │
        │                     │ trunk: VLAN 10 / 20 / 30 + untagged│
        │      ┌──────────────┼───────────────┬──────────────┐    │
        │      │              │               │              │    │
        │  ┌───┴────┐   ┌─────┴─────┐   ┌─────┴─────┐  ┌──────┴──┐ │
        │  │VLAN 10 │   │  VLAN 20  │   │  VLAN 30  │  │  MGMT   │ │
        │  │VICTIM  │   │    SOC    │   │  ATTACK   │  │10.10.99 │ │
        │  │AD+endp.│   │   Wazuh   │   │ attacker  │  │  .0/24  │ │
        │  └────────┘   └───────────┘   └───────────┘  └─────────┘ │
        └─────────────────────────────────────────────────────────┘
```

pfSense sits **behind** the home router — its WAN is just a regular DHCP client on `192.168.1.x`. This way the home router doesn't need to be touched, and the entire lab hides behind pfSense. Double NAT is fine here.

`vmbr0` bridges to the physical NIC (WAN side). `vmbr1` is an internal VLAN-aware bridge with no physical port — the lab is fully isolated from the home network unless explicitly allowed through pfSense rules.

---

## Address Plan

### Proxmox bridges

| Bridge   | Type                          | Role                              |
|----------|-------------------------------|-----------------------------------|
| vmbr0    | bridge to physical NIC        | WAN uplink                        |
| vmbr1    | internal, VLAN-aware, no port | trunk for all lab VLANs           |
| vmbr1.20 | VLAN interface on host        | management access to SOC VLAN     |

### VLANs

| VLAN | Interface | Gateway    | Network         | DHCP range       | DNS              | Role                  |
|------|-----------|------------|-----------------|------------------|------------------|-----------------------|
| —    | LAN       | 10.10.99.1 | 10.10.99.0/24   | .100–.199        | 10.10.99.1       | management/bootstrap  |
| 10   | VICTIM    | 10.10.10.1 | 10.10.10.0/24   | .100–.199        | 10.10.10.200 (DC)| AD + endpoints        |
| 20   | SOC       | 10.10.20.1 | 10.10.20.0/24   | .100–.199        | 10.10.20.1       | Wazuh cluster         |
| 30   | ATTACK    | 10.10.30.1 | 10.10.30.0/24   | .100–.199        | 10.10.30.1       | attacker machine      |

VLAN 10 uses the DC as DNS server — AD domain members require DC for name resolution, otherwise domain join and Kerberos break.

### VM addressing

| Machine         | VMID | Old IP        | New IP          | VLAN |
|-----------------|------|---------------|-----------------|------|
| Proxmox (host)  | —    | 192.168.1.23  | 192.168.1.23    | —    |
| pfSense         | 301  | —             | WAN 192.168.1.141 / LAN 10.10.99.1 | — |
| wazuh-indexer-1 | —    | 192.168.1.241 | 10.10.20.241    | 20   |
| wazuh-indexer-2 | —    | 192.168.1.242 | 10.10.20.242    | 20   |
| wazuh-master    | —    | 192.168.1.243 | 10.10.20.243    | 20   |
| wazuh-worker    | —    | 192.168.1.244 | 10.10.20.244    | 20   |
| SOC-LIN-01      | 100  | 192.168.1.24  | 10.10.30.x DHCP | 30   |
| SOC-DC-01       | 110  | 192.168.1.200 | 10.10.10.200    | 10   |
| SOC-WIN-10      | 111  | 192.168.1.150 | 10.10.10.150    | 10   |


---

## Firewall Rules

Rules are applied on the **source interface**. A new interface has implicit deny-all — everything must be explicitly allowed.

**VICTIM (VLAN 10)**

| # | Action | Proto   | Source        | Destination   | Port      | Reason                        |
|---|--------|---------|---------------|---------------|-----------|-------------------------------|
| 1 | Pass   | TCP     | 10.10.10.0/24 | 10.10.20.0/24 | 1514,1515 | Wazuh agents → manager        |
| 2 | Pass   | TCP/UDP | 10.10.10.0/24 | 10.10.10.200  | 53        | DNS to DC                     |
| 3 | Pass   | Any     | 10.10.10.0/24 | Any           | —         | endpoints → internet          |
| 4 | Block  | Any     | 10.10.10.0/24 | 10.10.20.0/24 | —         | victim network can't see SOC  |

Rules 1 and 2 must sit above rule 4 — pfSense processes rules top-down and stops at the first match.

**SOC (VLAN 20)**

| # | Action | Proto | Source        | Destination   | Reason                              |
|---|--------|-------|---------------|---------------|-------------------------------------|
| 1 | Pass   | Any   | 10.10.20.0/24 | Any           | SOC → internet                      |
| 2 | Block  | Any   | 10.10.20.0/24 | 10.10.10.0/24 | SOC doesn't initiate to victim      |
| 3 | Block  | Any   | 10.10.20.0/24 | 10.10.30.0/24 | SOC can't see the attacker          |

**ATTACK (VLAN 30)**

| # | Action | Proto | Source        | Destination   | Reason                              |
|---|--------|-------|---------------|---------------|-------------------------------------|
| 1 | Pass   | Any   | 10.10.30.0/24 | 10.10.10.0/24 | attacker → victim                   |
| 2 | Block  | Any   | 10.10.30.0/24 | 10.10.20.0/24 | attacker can't reach SOC            |
| 3 | Pass   | Any   | 10.10.30.0/24 | Any           | downloading tools, C2 callbacks     |

**WAN (laptop access from home network)**

| # | Action | Proto | Source         | Destination  | Port | Reason           |
|---|--------|-------|----------------|--------------|------|------------------|
| 1 | Pass   | TCP   | 192.168.1.0/24 | 10.10.20.243 | 443  | Wazuh dashboard  |
| 2 | Pass   | TCP   | 192.168.1.0/24 | 10.10.10.200 | 3389 | DC RDP           |
| 3 | Pass   | TCP   | 192.168.1.0/24 | 10.10.10.150 | 3389 | WIN-10 RDP       |
| 4 | Pass   | TCP   | 192.168.1.0/24 | 10.10.10.200 | 22   | DC SSH           |
| 5 | Pass   | TCP   | 192.168.1.0/24 | 10.10.10.150 | 22   | WIN-10 SSH       |

---

## Wazuh Cluster Migration

Migration order: indexers → worker → master. Each node: reassign NIC to `vmbr1` with VLAN tag 20, set static IP via Netplan, restart services.

**Indexers** (`/etc/wazuh-indexer/opensearch.yml`):
```yaml
network.host: 10.10.20.241   # indexer-2: 10.10.20.242
discovery.seed_hosts:
  - "10.10.20.241"
  - "10.10.20.242"
```

**Worker and master — filebeat** (`/etc/filebeat/filebeat.yml`):
```yaml
output.elasticsearch:
  hosts: ["10.10.20.241:9200", "10.10.20.242:9200"]
```

**Worker** (`/var/ossec/etc/ossec.conf`):
```xml
<client><server><address>10.10.20.243</address></server></client>
```

**Dashboard** (`/etc/wazuh-dashboard/opensearch_dashboards.yml`):
```yaml
server.host: 0.0.0.0
```
Dashboard was binding to the old IP — changing to `0.0.0.0` makes it accept connections on whatever address the interface has.

**Wazuh agents on Windows** (DC and WIN-10):
```powershell
(Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf") `
  -replace "192.168.1.243", "10.10.20.243" | `
  Set-Content "C:\Program Files (x86)\ossec-agent\ossec.conf"
Restart-Service WazuhSvc
```

**Verify cluster health:**
```bash
sudo /var/ossec/bin/cluster_control -l
curl -k -u admin:PASSWORD https://10.10.20.241:9200/_cluster/health?pretty
# expected: "status": "green", "number_of_nodes": 2
```

---

## Issues Encountered

| Problem                             | Symptom                                         | Fix                                                                  |
| ----------------------------------- | ----------------------------------------------- | -------------------------------------------------------------------- |
| VM boot loop                        | Always returned to pfSense installer screen     | Set boot order to `scsi0;ide2`, detach ISO after install             |
| Default LAN conflicted with WAN     | `192.168.1.1/24` collided with home network     | Changed LAN to `10.10.99.1/24`                                       |
| Proxmox host couldn't reach VLAN 20 | `Destination Host Unreachable`                  | Added `vmbr1.20` with IP `10.10.20.254` in `/etc/network/interfaces` |
| Dashboard returned connection reset | Tunnel worked but page reset                    | Set `server.host: 0.0.0.0` in opensearch_dashboards.yml              |
| Dashboard offline after migration   | API connection still pointed to `192.168.1.243` | Updated API connection in dashboard GUI                              |
| No network adapter on Windows VMs   | `Get-NetAdapter` returned empty                 | Installed VirtIO drivers from `virtio-win.iso`                       |
| No laptop access to lab             | SSH tunnels failed, no routes                   | Added static routes on laptop + WAN rules in pfSense                 |

---

