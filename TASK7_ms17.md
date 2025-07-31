# 🧪 Task 7 – Using External Rules to Detect MS17-010 Exploitation

This task applied Snort to detect a real-world vulnerability: **MS17-010**, better known as the vulnerability behind EternalBlue and the infamous WannaCry ransomware. This exercise involved analyzing a PCAP of exploit activity and writing a custom rule to match payload content.

---

## 📁 PCAP File Used

`ms-17-010.pcap`

---

## 🔧 Objective

- Use a provided Snort rule file to detect exploit traffic
- Write a new rule to match a known exploitation string: `\\IPC$`
- Extract information from triggered alerts such as the accessed path
- Understand how this exploit works and its severity

---

## 📜 Step 1 – Use the Provided Rule File

```bash
sudo snort -c local.rules -r ms-17-010.pcap -A console
```

✅ **Answer:** 25,154 packets detected

---

## 📜 Step 2 – Custom Rule to Detect `\\IPC$`

```snort
alert tcp any any -> any any (msg:"IPC$ access detected"; content:"\\IPC$"; sid:1000005; rev:1;)
```

**Command:**

```bash
sudo snort -c local-1.rules -r ms-17-010.pcap -A console
```

✅ **Answer:** 12 packets detected

---

## 🔍 Step 3 – Investigate Alert Logs

After logging alerts:

```bash
sudo snort -c local-1.rules -r ms-17-010.pcap -l .
sudo strings snort.log.* | grep -i ipc
```

✅ **Requested Path Detected:**

```
\\192.168.116.138\IPC$
```

---

## 📊 Step 4 – Research CVSS Score

**MS17-010 CVSS v2 Score:** `9.3`  
(Source: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-0143))

This classifies it as a **critical remote code execution vulnerability**, with low complexity and no authentication needed — the worst kind.

---

## 🧠 Lessons Learned

- EternalBlue exploits SMB vulnerabilities in Windows, leveraging unauthenticated access to named pipes like `\\IPC$`.
- Matching known strings in traffic (like `\\IPC$`) is a fast way to narrow down exploit behavior in noisy captures.
- Large alert volumes (~25k) show why detection tuning and rule specificity matter in real environments.

---

## 🛡️ Real-World Relevance

EternalBlue was weaponized into WannaCry and NotPetya — attacks that cost billions. This task taught me how:

- To detect it using Snort
- To isolate specific activity (IPC access)
- To recognize the value of writing **targeted rules** inside massive attack traffic

This is exactly the type of threat detection work SOC analysts and threat hunters perform every day.

---

## ✅ Summary

In this task, I:

- Ran Snort against exploit traffic
- Wrote a detection rule for IPC access
- Extracted the exploited path
- Researched the severity of the vulnerability (CVSS 9.3)

This bridges theoretical CVE knowledge with practical network-level detection skills.
