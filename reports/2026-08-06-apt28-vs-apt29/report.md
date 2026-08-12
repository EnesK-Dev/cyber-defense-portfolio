---
slug: apt28-vs-apt29
title: "APT28 vs APT29: Two Russian APTs, Two Doctrines, One ATT&CK Lens"
date: 2026-08-06
updated: 2026-08-06
lang: en
status: published
category: Threat Intelligence
subcategory: Adversary Analysis
tags:
  - apt28
  - apt29
  - mitre-attack
  - ttp-analysis
  - threat-intelligence
  - fancy-bear
  - cozy-bear
summary: >-
  A SOC-analyst comparison of APT28 (Fancy Bear, GRU) and APT29 (Cozy Bear, SVR)
  through MITRE ATT&CK — where their TTPs overlap, where they diverge, and how
  each group's intelligence-agency doctrine drives a different detection strategy.
reading_time: 9
difficulty: intermediate
author:
  name: Enes Küçükkaya
  url: https://www.linkedin.com/in/eneskucukkaya/
source:
  name: MITRE ATT&CK
  reference: "Groups G0007, G0016; Campaigns C0024, C0051"
  url: https://attack.mitre.org/
tools:
  - MITRE ATT&CK
mitre_attack:
  - id: T1566
    name: Phishing
    tactic: Initial Access
    confidence: confirmed
  - id: T1195.002
    name: "Supply Chain Compromise: Software Supply Chain"
    tactic: Initial Access
    confidence: confirmed
  - id: T1199
    name: Trusted Relationship
    tactic: Initial Access
    confidence: confirmed
  - id: T1606.002
    name: "Forge Web Credentials: SAML Tokens"
    tactic: Credential Access
    confidence: confirmed
  - id: T1134
    name: Access Token Manipulation
    tactic: Defense Evasion
    confidence: confirmed
  - id: T1059.001
    name: "Command and Scripting Interpreter: PowerShell"
    tactic: Execution
    confidence: confirmed
  - id: T1071
    name: Application Layer Protocol
    tactic: Command and Control
    confidence: confirmed
  - id: T1041
    name: Exfiltration Over C2 Channel
    tactic: Exfiltration
    confidence: confirmed
---

# APT28 vs APT29: Two Russian APTs, Two Doctrines, One ATT&CK Lens

> **Scope note.** A comparative TTP study built for a SOC-analyst perspective. The
> point is not to catalogue every technique, but to show how two state-sponsored
> groups fill the *same* attack chain with *different* techniques — and what that
> means for defence.

---

## 1. Introduction and Purpose

This report compares the Tactics, Techniques and Procedures (TTP) profiles of two
prominent Russia-linked Advanced Persistent Threat groups — **APT28 (Fancy Bear)**
and **APT29 (Cozy Bear)** — through the MITRE ATT&CK framework. Both run
state-sponsored cyber-espionage operations, but they answer to different
intelligence agencies, and that produces a marked difference in operational
philosophy.

The goal is to show, from a SOC analyst's viewpoint, where the two groups overlap
in technique, where they diverge, and how those differences translate into
detection and defence strategy. TTP mappings are given with ATT&CK technique IDs,
each justified by its attribution to the group.

> **Source note.** Technique mappings are based on MITRE ATT&CK's official group
> pages (G0007, G0016) and related campaign records (SolarWinds C0024, Nearest
> Neighbor C0051), corroborated with public threat-intelligence reporting
> (Mandiant, CrowdStrike, Microsoft, CISA).

---

## 2. APT28 (Fancy Bear) Profile

| Attribute | Detail |
| :--- | :--- |
| MITRE ID | G0007 |
| Aliases | Fancy Bear, Sofacy, Sednit, Pawn Storm, STRONTIUM, Forest Blizzard |
| Attribution | Russian Military Intelligence (GRU) — 85th Special Service Center, unit 26165 |
| Active since | At least 2004 |
| Operational style | Aggressive, fast, high-volume; comparatively "noisy" |
| Typical targets | Government, military, defence, political organisations, media, sports bodies |
| Notable incident | 2016 DNC / Hillary Clinton campaign breach |

### 2.1 APT28 — ATT&CK TTP Mapping

| Tactic | Technique (ID) | APT28 usage (rationale) |
| :--- | :--- | :--- |
| Reconnaissance | Active Scanning: Vulnerability Scanning (T1595.002) | Vulnerability scanning of target systems |
| Resource Development | Acquire Infrastructure (T1583) | Standing up spoofed domains and C2 infrastructure |
| Initial Access | Phishing: Spearphishing Link/Attachment (T1566.001/.002) | The group's signature vector; targeted lure emails |
| Initial Access | Exploit Public-Facing Application (T1190) | Exploiting vulnerabilities in internet-facing apps |
| Initial Access | Valid Accounts / Brute Force: Password Spraying (T1110.003) | Logging in after credential harvesting |
| Execution | Command and Scripting Interpreter: PowerShell (T1059.001) | Payload execution (e.g. Sofacy/Carberp) |
| Privilege Escalation | Exploitation for Privilege Escalation (T1068) | SYSTEM via CVE-2015-1701 and similar |
| Defense Evasion | Access Token Manipulation (T1134) | Token copying for escalation/concealment |
| Credential Access | Gather Victim Identity: Credentials (T1589.001) | Credential collection, fake login pages |
| Command & Control | Application Layer Protocol (T1071) | C2 via X-Tunnel (S0117), X-Agent, Cannon |
| Exfiltration | Exfiltration Over C2 Channel (T1041) | Exfiltrating collected data over C2 |

**Known tooling:** X-Agent, X-Tunnel (S0117), Zebrocy, Sofacy/Carberp, Cannon
(S0351), CHOPSTICK. Recent: CVE-2022-38028 zero-day and access via neighbouring
Wi-Fi networks (Nearest Neighbor campaign, C0051), with a living-off-the-land trend.

---

## 3. APT29 (Cozy Bear) Profile

| Attribute | Detail |
| :--- | :--- |
| MITRE ID | G0016 |
| Aliases | Cozy Bear, The Dukes, Midnight Blizzard, NOBELIUM, UNC2452, Dark Halo, CozyDuke |
| Attribution | Russian Foreign Intelligence Service (SVR) |
| Active since | At least 2008 |
| Operational style | Ultra-stealthy, patient, long dwell time (months/years), living-off-the-land |
| Typical targets | Government, NATO, diplomacy, think-tanks, healthcare (COVID vaccine), tech |
| Notable incident | 2020 SolarWinds (SUNBURST) supply-chain attack; 2024 Microsoft breach |

### 3.1 APT29 — ATT&CK TTP Mapping

| Tactic | Technique (ID) | APT29 usage (rationale) |
| :--- | :--- | :--- |
| Initial Access | Supply Chain Compromise (T1195.002) | SUNBURST injected into the SolarWinds Orion update |
| Initial Access | Trusted Relationship (T1199) | Abusing trusted supplier/partner accounts |
| Initial Access | Phishing: Spearphishing (T1566) | Early campaigns, targeted email |
| Execution | Command and Scripting Interpreter: PowerShell (T1059.001) | Living-off-the-land, execution via legitimate tools |
| Execution | Windows Management Instrumentation (T1047) | Remote command execution, lateral movement |
| Persistence | Multiple implants / redundant access | Persistence via multiple backdoors (SUNBURST, TEARDROP) |
| Defense Evasion | Forge Web Credentials: SAML Tokens (T1606.002) | Golden SAML; token forging with the ADFS cert, MFA bypass |
| Credential Access | Cloud/Identity abuse (Azure AD, M365) | Cloud identity abuse via Microsoft Graph API |
| Lateral Movement | Remote Services: RDP/SMB/WinRM (T1021.001/.002/.006) | Lateral movement inside the network |
| Command & Control | Application Layer Protocol (T1071) | Covert C2 via SUNBURST/SUNSHUTTLE, HAMMERTOSS |
| Collection | Data from Information Repositories (T1213) | Collecting from email and document stores |

**Known tooling:** SUNBURST, TEARDROP, Raindrop, SUNSHUTTLE, WellMess, WellMail,
HAMMERTOSS, MiniDuke, CozyDuke. Standout capability: cloud-native operations (Azure
AD, M365, AWS IAM) and identity/trust manipulation.

---

## 4. Comparative Analysis

### 4.1 The Doctrinal Difference

The most fundamental difference between the two groups comes from the doctrine of
the agency they serve. APT28 (GRU) answers to military intelligence; speed,
operational tempo, and effect take priority — hence a more aggressive, "noisier"
posture. APT29 (SVR) answers to foreign intelligence; the objective is long-term,
quiet, undetected collection — patient, low-profile, stealth-first.

| Dimension | APT28 (Fancy Bear) | APT29 (Cozy Bear) |
| :--- | :--- | :--- |
| Agency | GRU (military intelligence) | SVR (foreign intelligence) |
| Operational tempo | Fast, aggressive | Slow, patient |
| Stealth | Relatively noisy | Ultra-stealthy, long dwell time |
| Signature vector | Spearphishing, credential harvesting | Supply chain, trusted relationship, cloud identity |
| Standout capability | Custom malware (X-Agent/X-Tunnel) | SAML forging, cloud-native, living-off-the-land |

### 4.2 Shared Techniques (Overlap)

Because both run state-sponsored espionage, they overlap on some core techniques:

| Technique (ID) | Shared usage |
| :--- | :--- |
| Phishing (T1566) | Both use targeted email (especially early on) |
| Command and Scripting Interpreter: PowerShell (T1059.001) | Both execute code via legitimate tools |
| Application Layer Protocol (T1071) | Both use application-layer protocols for C2 |
| Valid Accounts (T1078) | Both gain legitimate access with stolen credentials |
| Exfiltration Over C2 Channel (T1041) | Both exfiltrate over the C2 channel |

### 4.3 Diverging Techniques (Difference)

| Area | APT28-specific | APT29-specific |
| :--- | :--- | :--- |
| Initial Access | Wi-Fi proximity (C0051), password spraying | Supply chain (SolarWinds), trusted relationship |
| Defense Evasion | Access Token Manipulation (T1134) | Golden SAML token forging (T1606.002) |
| Environment | Traditional endpoint / on-prem | Cloud-native (Azure AD, M365, Graph API) |
| Persistence style | Custom implant (X-Agent) | Redundant access, multiple backdoors |

### 4.4 Comparison Across the Cyber Kill Chain

How the two groups fill the same attack-chain stages with different techniques:

| Kill chain stage | APT28 | APT29 |
| :--- | :--- | :--- |
| Delivery / Initial Access | Spearphishing, exploit | Supply chain, trusted relationship |
| Exploitation / Execution | PowerShell, CVE exploitation | PowerShell, WMI (living-off-the-land) |
| Installation / Persistence | X-Agent implant | Multiple backdoors (SUNBURST/TEARDROP) |
| C2 | X-Tunnel, Cannon | SUNSHUTTLE, HAMMERTOSS (covert) |
| Actions / Exfiltration | Fast exfil over C2 | Slow, selective, long-running exfil |

---

## 5. Detection and Defence from a SOC Perspective

The two groups' differing TTP profiles require differing defensive strategies:

### 5.1 Against APT28

- **Email security** (spearphishing filtering, attachment/URL analysis) up front.
- **Patch management** — closing known CVE exploits (e.g. privilege escalation).
- Monitoring for **anomalous PowerShell execution and token manipulation** (T1059, T1134).
- Detection rules for **known X-Agent/X-Tunnel IOCs and C2 patterns**.

### 5.2 Against APT29

- **Supply-chain integrity** — verifying third-party software updates.
- **Cloud/identity monitoring** (Azure AD, M365) — anomalous SAML tokens, service-principal activity.
- **MFA + conditional access**; protecting the ADFS certificate against Golden SAML.
- **Behavioural (IOA) detection** to catch long dwell time — IOCs alone are not enough.

> **General principle.** APT28 is caught more at the endpoint/email layer; APT29 at
> the cloud/identity layer. Because both abuse legitimate tooling
> (living-off-the-land), behaviour-based (IOA) detection is critical — not just
> signature-based (IOC).

---

## 6. Conclusion

APT28 and APT29 serve the same nation, yet their operational identities are
distinctly different. APT28's aggressive, speed-focused, endpoint-centric approach
reflects the GRU's military-tactical doctrine. APT29's patient, stealthy,
cloud/identity-centric approach is the product of the SVR's long-term
intelligence-collection doctrine. The MITRE ATT&CK framework makes it possible to
compare the two objectively — through their shared and divergent techniques — and to
build layered defence accordingly.

---

## References

- MITRE ATT&CK — APT28, Group [G0007](https://attack.mitre.org/groups/G0007)
- MITRE ATT&CK — APT29, Group [G0016](https://attack.mitre.org/groups/G0016)
- MITRE ATT&CK — SolarWinds Compromise, Campaign C0024
- MITRE ATT&CK — APT28 Nearest Neighbor Campaign, Campaign C0051
- CISA, Microsoft (Midnight Blizzard), Mandiant, CrowdStrike threat-intelligence reporting
