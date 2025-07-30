# 🧪 Task 2 – Writing IDS Rules (HTTP Traffic)

In this task, we practiced basic rule writing in Snort by detecting TCP traffic on port 80 and analyzing packet details. This builds foundational skills for identifying unencrypted web traffic — a common attack vector.

---

## 🔧 Objective

Write a rule to detect all TCP traffic to or from port 80 and use Snort to analyze specific packet fields like IP addresses, sequence numbers, TTL, and ports.

---

## 📜 Snort Rule

```snort
alert tcp any any <> any 80 (msg:"TCP traffic to/from port 80"; sid:1000001; rev:1;)
```

- `<>` makes the rule bidirectional (both to and from port 80).
- `msg` helps label the alert clearly.

---

## 🧪 Run Snort on the PCAP

```bash
sudo snort -c local.rules -l . -r mx-3.pcap
```

> Make sure your rule is in `local.rules` and that you're using the correct PCAP file provided by the room.

You should get:

```
Snort processed 164 packets.
```

✅ **Answer:** `164 packets`

---

## 🔍 Deep Packet Inspection

To answer packet-specific questions, I reran Snort and inspected the binary alert log:

```bash
sudo snort -c local.rules -A full -l . -r mx-3.pcap
sudo snort -r snort.log.* -n [packet_number]
```

| Question                              | Command Example                              | Answer               |
|---------------------------------------|----------------------------------------------|----------------------|
| Destination IP of packet 63          | `sudo snort -r snort.log.* -n 63`            | `216.239.59.99`      |
| ACK number of packet 64              | `sudo snort -r snort.log.* -n 64`            | `0x2E6B5384`         |
| SEQ number of packet 62              | `sudo snort -r snort.log.* -n 62`            | `0x36C21E28`         |
| TTL of packet 65                     | `sudo snort -r snort.log.* -n 65`            | `128`                |
| Source IP of packet 65               | `sudo snort -r snort.log.* -n 65`            | `145.254.160.237`    |
| Source Port of packet 65             | `sudo snort -r snort.log.* -n 65`            | `3371`               |

---

## 🧠 Lessons Learned

- Use `<>` when you want to catch both directions of traffic.
- Snort logs alerts in binary format by default — use `snort -r` or `strings` to inspect packet details.
- Rule testing is iterative: test small, check logs, then refine.
- Always assign unique SIDs to avoid errors across rules.

---

## ✅ Recap

This task reinforced core detection principles using Snort:
- Writing a TCP port-based rule
- Triggering alerts on real PCAP data
- Investigating individual packet fields using Snort

We’ll build on this foundation in Task 3 by working with FTP traffic and login patterns.
