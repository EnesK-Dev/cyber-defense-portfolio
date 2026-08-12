# Incident Report: APT-Style Malware Analysis (STRRAT)

**Date:** 2026-09-06  
**Analyst:** Enes Küçükkaya  
**Source:** malware-traffic-analysis.net  

## 1. Executive Summary
This report documents the analysis of a PCAP file containing malicious activity. A Windows 11 workstation was infected with the **STRRAT** Remote Access Trojan (RAT). The malware was delivered via a likely phishing vector (payload download from GitHub) and established C2 communication to exfiltrate system data and monitor user activity.

## 2. Victim Details
| Property | Value |
| :--- | :--- |
| **IP Address** | 172.16.1.66 |
| **Hostname** | DESKTOP-SKBR25F |
| **User** | ccollier |
| **MAC** | 00:1e:64:ec:f3:08 |

## 3. Analysis Findings
### C2 Infrastructure
- **C2 IP:** 141.98.10.79
- **C2 Port:** 12132 (Non-standard)
- **Protocol:** Raw TCP (Beaconing pattern observed)

### Malware Delivery
- **Initial Access:** Likely Phishing (Associated with "Invoice & Packing List.eml")
- **Payload Source:** `objects.githubusercontent.com` (185.199.110.133)

## 4. MITRE ATT&CK Mapping
- **T1566 (Phishing):** Probable initial access vector.
- **T1071 (Application Layer Protocol):** C2 communication via port 12132.
- **T1105 (Ingress Tool Transfer):** Downloading payload from GitHub.
- **T1056 (Input Capture):** Monitoring active window titles.

## 5. Remediation Recommendations
1. **Isolation:** Isolate the infected host (172.16.1.66) from the network.
2. **Blocking:** Block IP `141.98.10.79` and associated `plesk.page` domains at the perimeter.
3. **Identity:** Reset credentials for user `ccollier`.
4. **Hunting:** Scan network for lateral movement towards this C2 IP.

---
*For full technical steps and PCAP screenshots, please contact the author.*