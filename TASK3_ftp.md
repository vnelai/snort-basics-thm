# 🧪 Task 3 – Writing IDS Rules (FTP Traffic)

In this task, we explored detecting FTP activity using Snort. FTP is a plaintext protocol, which makes it both easy to monitor and a security concern in modern networks. We wrote rules to detect various login states using FTP status codes.

---

## 🔧 Objective

Write Snort rules to detect general FTP traffic, failed login attempts, successful logins, username-only logins, and specific usernames like "Administrator". Analyze the number of matches for each condition using Snort on a provided PCAP file.

---

## 📁 PCAP File Used

`ftp-png-gif.pcap`

---

## 📜 Rule 1 – Detect all TCP traffic on port 21

```snort
alert tcp any any <> any 21 (msg:"All TCP traffic on port 21"; sid:1000001; rev:1;)
```

**Command:**

```bash
sudo snort -c local.rules -l . -r ftp-png-gif.pcap
```

✅ **Answer:** 307 packets detected

---

## 📜 Rule 2 – Detect failed FTP login attempts (code 530)

```snort
alert tcp any any <> any 21 (msg:"Failed FTP login attempt"; content:"530 "; sid:1000002; rev:1;)
```

✅ **Answer:** 41 packets

---

## 📜 Rule 3 – Detect successful FTP login (code 230)

```snort
alert tcp any any <> any 21 (msg:"Successful FTP login"; content:"230 "; sid:1000003; rev:1;)
```

✅ **Answer:** 1 packet

---

## 📜 Rule 4 – Detect "username only" login (code 331)

```snort
alert tcp any any <> any 21 (msg:"FTP login - valid username, awaiting password"; content:"331 "; sid:1000004; rev:1;)
```

✅ **Answer:** 42 packets

---

## 📜 Rule 5 – Detect username "Administrator" being used

```snort
alert tcp any any -> any 21 (msg:"FTP login attempt with username Administrator"; content:"USER Administrator"; nocase; sid:1000005; rev:1;)
```

✅ **Answer:** 7 packets

---

## 🧠 Lessons Learned

- FTP traffic is unencrypted, so status codes like `530`, `230`, and `331` can be easily detected in the payload.
- Always comment out or deactivate previous rules to avoid false matches and Snort parsing issues.
- Use `nocase` when you expect usernames or commands to be case-insensitive.
- Matching specific login stages can help distinguish brute force attempts from valid user activity.

---

## 🛡️ Summary

This task showed how to:
- Write protocol-specific rules for FTP
- Detect login stages based on status codes
- Apply practical logic for intrusion detection
- Analyze login attempts at a granular level

This type of rule tuning is valuable in real-world SOC environments where brute force detection and authentication monitoring are critical.
