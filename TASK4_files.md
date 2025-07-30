# 🧪 Task 4 – Writing IDS Rules (File Signatures: PNG & GIF)

This task focused on detecting file transfers based on unique byte patterns (magic bytes). These are often used to identify file types in transit, even when filenames or extensions are hidden.

In real-world blue team environments, detecting unauthorized file uploads or exfiltrations (especially images, executables, or documents) is critical for DLP and insider threat programs.

---

## 📁 PCAP File Used

`ftp-png-gif.pcap`

---

## 🔧 Objective

Write rules that detect PNG and GIF image transfers by matching their known file signatures (magic bytes) inside the packet payload. Then investigate what software or image types are embedded.

---

## 📜 Rule 1 – Detect PNG File Signature

```snort
alert tcp any any -> any any (msg:"PNG file detected"; content:"|89 50 4E 47 0D 0A 1A 0A|"; sid:1000001; rev:1;)
```

**Command:**

```bash
sudo snort -c local.rules -l . -r ftp-png-gif.pcap
```

Then use `strings` to analyze the resulting alert log:

```bash
sudo strings snort.log.* | grep -i png
```

✅ **Embedded Software Name Detected:** `Adobe ImageReady`

---

## 📜 Rule 2 – Detect GIF File Signature

```snort
alert tcp any any -> any any (msg:"GIF file detected"; content:"GIF8"; sid:1000002; rev:1;)
```

**Command:**

```bash
sudo snort -c local.rules -l . -r ftp-png-gif.pcap
```

Then analyze the logs:

```bash
sudo strings snort.log.* | grep -i gif
```

✅ **Image Format Detected:** `GIF89a`

---

## 🧠 Lessons Learned

- Magic bytes are consistent patterns at the beginning of file types. For PNGs, it's `89 50 4E 47...`; for GIFs, it's `GIF89a` or `GIF87a`.
- File signature detection is powerful for finding hidden or unauthorized uploads, even when filenames are obfuscated.
- Always assign a **unique SID** per rule to prevent Snort startup failures.
- You can reuse the same `rev` number across rules, but never reuse `sid`.

---

## 💡 Bonus Tip: Magic Byte Examples

| File Type | Hex Signature                  | Snort Content Match                          |
|-----------|--------------------------------|----------------------------------------------|
| PNG       | `89 50 4E 47 0D 0A 1A 0A`       | `content:"|89 50 4E 47 0D 0A 1A 0A|";`        |
| GIF       | `47 49 46 38 39 61` (GIF89a)    | `content:"GIF8";`                             |
| EXE       | `4D 5A`                         | `content:"|4D 5A|";`                          |

---

## ✅ Summary

By the end of this task, we learned how to:
- Detect file types using content matching
- Identify embedded image tools or formats
- Use Snort for data loss prevention (DLP) and forensic investigation

Magic byte detection is a versatile technique that extends beyond just PNGs and GIFs — it applies to executables, documents, archives, and malware payloads.
