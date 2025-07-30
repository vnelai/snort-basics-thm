# 🧩 Snort Rule Writing Cheatsheet

This cheatsheet summarizes key syntax, best practices, and troubleshooting tips for writing effective Snort IDS rules.

---

## 🛠️ Basic Rule Syntax

```snort
alert tcp any any -> any 80 (msg:"HTTP traffic"; sid:1000001; rev:1;)
```

- **alert** – Action to take (`alert`, `log`, `pass`, etc.)
- **tcp** – Protocol to inspect (`tcp`, `udp`, `icmp`, etc.)
- **any any -> any 80** – Source IP/Port to Destination IP/Port
- **msg** – Message that shows in alerts
- **sid** – Unique Snort rule ID
- **rev** – Revision number for versioning the rule

---

## 🔀 Direction Operators

| Operator | Meaning         | Use Case                              |
|----------|------------------|----------------------------------------|
| `->`     | One-way traffic  | Client to server (HTTP, exploits)      |
| `<>`     | Bidirectional    | FTP, chat protocols, handshake flows   |

---

## 🔍 Common Rule Options

- `content:"GET"` – Match string "GET"
- `nocase` – Case-insensitive matching
- `dsize:770<>855` – Match payloads between 770 and 855 bytes
- `offset:0; depth:10;` – Match within the first 10 bytes
- `flow:to_server,established;` – Match TCP streams to server side
- `classtype:attempted-admin;` – Alert classification
- `sid:1000001;` – Required unique rule ID
- `rev:1;` – Revision number for rule updates

---

## 📦 Payload-Based Detection

- PNG file (magic bytes):  
  `content:"|89 50 4E 47 0D 0A 1A 0A|";`

- GIF file:  
  `content:"GIF8";`

- FTP success:  
  `content:"230 ";`

- FTP failure:  
  `content:"530 ";`

- Log4Shell payload:  
  `content:"${jndi:"; nocase;`

---

## 🧠 SID Guidelines

- Use SIDs > 1,000,000 for local/custom rules.
- Never reuse the same SID across rules — it causes errors.
- `rev` tracks edits to a rule, but SID must be unique per rule.

---

## 🧪 Running Snort for Labs

Read a PCAP and use a local rule file:

```bash
sudo snort -c local.rules -l . -r file.pcap
```

Verbose output in console:

```bash
sudo snort -c local.rules -A console -r file.pcap
```

Use a specific alert mode for full info:

```bash
sudo snort -c local.rules -A full -l . -r file.pcap
```

---

## 🛠️ Troubleshooting Tips

- **Missing semicolon?** Snort rules break silently — check for `;` at the end of every option.
- **No alerts showing?** You might have a logic error (wrong port, content mismatch).
- **Duplicate SID error?** Use unique SIDs for each rule or it won’t load.
- **Snort only shows one error at a time.** Fix and rerun each time until clean.

---

## 🔍 Helpful Log Analysis

Extract readable strings from logs:

```bash
sudo strings snort.log.* | grep -i "ftp"
```

Find how many rules triggered:

```bash
grep "\[\*\*\]" alert | awk -F ':' '{print $2}' | sort -u | wc -l
```

Get unique SID prefixes:

```bash
grep "\[\*\*\]" alert | awk -F ':' '{print $2}' | cut -c1-6 | sort -u
```

---

## ✅ Summary

Snort is powerful but picky — writing rules is as much about understanding the protocol as it is about getting syntax right. Whether you're detecting FTP logins, file transfers, or exploit payloads, the key is to test iteratively and log everything.

Happy hunting!
