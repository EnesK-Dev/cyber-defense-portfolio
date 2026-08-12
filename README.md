# Cyber Defense Portfolio

Incident response investigations, threat hunting reports, and detection engineering
notes — documented security analysis workflows and technical deep-dives into
real-world threats.

Each write-up is deliberately structured as a **reasoning trail** rather than a
findings list: which filter was applied, why it was chosen, what each result ruled
out, and where the evidence stops short of proof.

## About Me

I am a cybersecurity student focused on Security Operations Center (SOC) processes,
log analysis, and threat intelligence. My core objective is to decode complex attack
patterns and strengthen defensive posture.

## 📋 Write-ups

<!-- REPORTS:BEGIN -->
| Date | Write-up | Category | Tags |
| :--- | :--- | :--- | :--- |
| 2026-09-06 | [Hunting a STRRAT C2 Channel in a PCAP: A Step-by-Step Traffic Analysis](reports/2026-09-06-strrat-c2-analysis/report.md) | Malware Analysis | `pcap`, `wireshark`, `command-and-control`, `strrat` |
| 2026-08-06 | [APT28 vs APT29: Two Russian APTs, Two Doctrines, One ATT&CK Lens](reports/2026-08-06-apt28-vs-apt29/report.md) | Threat Intelligence | `apt28`, `apt29`, `mitre-attack`, `ttp-analysis` |
| 2026-07-16 | [Triaging Windows Attacks in Wazuh: Where rule.level Lies](reports/2026-07-16-wazuh-sysmon-triage/report.md) | Detection Engineering | `wazuh`, `sysmon`, `siem`, `alert-triage` |
| 2026-07-15 | [auth2.log: When the Raw Counts Lie (message repeated & invalid user)](reports/2026-07-15-linux-auth2log-bruteforce/report.md) | Log Analysis | `linux`, `auth-log`, `ssh`, `brute-force` |
| 2026-07-14 | [IOC vs IOA: Fingerprints of a Crime vs Someone Picking the Lock](reports/2026-07-14-ioc-vs-ioa/report.md) | Fundamentals | `ioc`, `ioa`, `detection-engineering`, `threat-intelligence` |
| 2026-07-14 | [Reading auth.log by Hand: SSH Forensics Without a SIEM](reports/2026-07-14-linux-authlog-analysis/report.md) | Log Analysis | `linux`, `auth-log`, `ssh`, `brute-force` |
<!-- REPORTS:END -->

## 🛠 Tools & Methodologies

- **Network Analysis:** Wireshark, tcpdump
- **Log Analysis:** grep, awk, sed
- **SIEM / Detection:** Wazuh
- **Threat Intelligence:** VirusTotal, OpenCTI, MITRE ATT&CK
- **OSINT:** Passive DNS, WHOIS

## 📦 Repository Structure

This repo doubles as the content source for my blog — the write-ups live here, and
the site reads them from [`index.json`](index.json). See
[`CONTENT_SCHEMA.md`](CONTENT_SCHEMA.md) for the front-matter contract and consumption
model.

```
reports/<YYYY-MM-DD>-<slug>/report.md   # front matter + body
reports/<YYYY-MM-DD>-<slug>/assets/     # screenshots, referenced relatively
scripts/docx2md.py                      # .docx → report scaffold
scripts/build_index.py                  # regenerates index.json + the table above
```

Adding a write-up:

```bash
python3 scripts/docx2md.py ~/path/to/report.docx --slug my-analysis --date 2026-09-20
# edit front matter, rename assets, write alt text, set status: published
python3 scripts/build_index.py
```

---

*[LinkedIn](https://www.linkedin.com/in/eneskucukkaya/) · eneskucukkaya0@gmail.com*
