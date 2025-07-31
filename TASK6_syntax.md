# 🧪 Task 6 – Troubleshooting Rule Syntax & Logic Errors

This task was all about breaking, fixing, and understanding why Snort rules fail to load or produce zero alerts. I worked through multiple broken rule files and corrected them to detect traffic successfully.

This is exactly the kind of skill a SOC analyst or detection engineer needs — knowing how to debug why your rules aren't firing.

---

## 📁 PCAP File Used

`mx-1.pcap`

---

## 🔧 Objective

Fix syntax and logic errors in a series of broken Snort rule files (`local-1.rules` to `local-7.rules`) and verify they generate alerts.

---

## 🛠️ Common Error Types Encountered

| Type                  | Example Fix                              |
|-----------------------|-------------------------------------------|
| Missing space         | `any(any:` → `any any (`                 |
| Wrong operator        | `<-` is invalid → use `->` or `<>`       |
| Invalid quote/colon   | `msg:"text":` → `msg:"text";`            |
| Duplicate SIDs        | Change SIDs per rule (must be unique)    |
| Logical mismatch      | Wrong ports, directions, or content      |
| Missing required field| e.g. `msg` was completely omitted        |

---

## 🔍 Fixes and Answers

### ✅ 6.1 – Fix spacing error

**Original:**
```snort
alert tcp any 3372 -> any any(msg: "Troubleshooting 1"; sid:1000001; rev:1;)
```

**Fix:**
```snort
alert tcp any 3372 -> any any (msg: "Troubleshooting 1"; sid:1000001; rev:1;)
```

✅ **Answer:** 16 packets

---

### ✅ 6.2 – Missing source port

**Original:**
```snort
alert icmp any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:1;)
```

**Fix:**
```snort
alert icmp any any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:1;)
```

✅ **Answer:** 68 packets

---

### ✅ 6.3 – Duplicate SID

**Original:**
```snort
alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000001; rev:1;)
```

**Fix:**
```snort
alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)
```

✅ **Answer:** 87 packets

---

### ✅ 6.4 – Invalid character `:` instead of `;`

**Fix:**
```snort
alert tcp any 80,443 -> any any (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)
```

✅ **Answer:** 90 packets

---

### ✅ 6.5 – Multiple issues (operator + sid + semicolon)

**Fix:**
```snort
alert icmp any any <> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert icmp any any -> any any (msg: "Inbound ICMP Packet Found"; sid:1000002; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000003; rev:1;)
```

✅ **Answer:** 155 packets

---

### ✅ 6.6 – Logic error: content mismatch (`get` vs `GET`)

**Original:**
```snort
alert tcp any any <> any 80 (msg: "GET Request Found"; content:"|67 65 74|"; sid:1000001; rev:1;)
```

**Fix:**
```snort
alert tcp any any <> any 80 (msg:"GET Request Found"; content:"GET"; sid:1000001; rev:1;)
```

✅ **Answer:** 2 packets

---

### ✅ 6.7 – Missing required field: `msg`

**Original:**
```snort
alert tcp any any <> any 80 (content:"http"; sid:1000001; rev:1;)
```

**Fix:**
```snort
alert tcp any any <> any 80 (msg:"HTTP traffic detected"; content:"http"; sid:1000001; rev:1;)
```

✅ **Answer (field missing):** `msg`

---

## 🧠 Lessons Learned

- Snort doesn’t always crash — sometimes it silently ignores bad rules or fails to alert due to logic errors.
- A rule that compiles but shows zero alerts can still be broken.
- Always:
  - Check that every rule ends in `;`
  - Use a **unique SID** for each rule
  - Avoid invalid operators (`<-` is not valid!)
  - Validate logic: ports, content, direction

---

## 🛡️ Real-World Insight

Being able to troubleshoot a failing rule is one of the most valuable skills you can have in blue team operations. Whether you’re tuning detections or reviewing a teammate’s rule, you need to understand both **syntax** and **intent** to make effective changes.

This task gave me a strong understanding of how to debug Snort rules like a professional.


