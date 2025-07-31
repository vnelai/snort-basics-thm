# 🧪 Task 5 – Writing IDS Rules (Torrent Metafile Detection)

This task focused on detecting BitTorrent `.torrent` files by inspecting PCAP payloads for known headers and metadata. While torrenting itself isn't inherently malicious, it’s commonly associated with data exfiltration, pirated content, or malware delivery in enterprise environments.

---

## 📁 PCAP File Used

`torrent.pcap`

---

## 🔧 Objective

Write a Snort rule that detects torrent metafiles based on file content, then extract key metadata such as application name, MIME type, and tracker hostname.

---

## 📜 Rule – Detect `.torrent` Metafile Header

```snort
alert tcp any any <> any any (msg:"BitTorrent metafile detected"; content:".torrent"; sid:1000004; rev:1;)
```

**Command:**

```bash
sudo snort -c local.rules -l . -r torrent.pcap
```

✅ **Answer:** 2 packets detected

---

## 🔍 Metadata Analysis Using Strings

To investigate the alert contents, run:

```bash
sudo strings snort.log.* | grep -i torrent
```

---

### 📌 Answers

- **Torrent Application Name:** `bittorrent`
- **MIME Type of Metafile:** `application/x-bittorrent`
- **Hostname of the Tracker:** `tracker2.torrentbox.com`

---

## 🧠 Lessons Learned

- BitTorrent files typically contain the `.torrent` keyword and the header `d8:announce` — both are valid indicators for detection.
- The MIME type `application/x-bittorrent` is a solid passive signature to look for in IDS logs.
- Hostnames of torrent trackers can help identify outbound connections to potentially risky P2P services.

---

## 🛡️ Use Case in Blue Teaming

Organizations may want to monitor or block torrent traffic to prevent:

- Unauthorized P2P sharing
- Bandwidth abuse
- Exfiltration over unmonitored channels

Snort can help detect these early by flagging `.torrent` file signatures or common tracker domains before a full connection is established.

---

## ✅ Summary

This task taught us to:
- Write a rule to detect torrent metafiles
- Extract metadata from triggered alerts
- Understand the value of passive application fingerprinting
- Recognize how torrent usage can indicate policy violations or shadow IT

Snort rules like this are useful for identifying not only malicious activity, but also violations of acceptable use policies or potential insider threats.
