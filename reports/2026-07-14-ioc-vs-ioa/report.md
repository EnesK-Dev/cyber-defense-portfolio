---
slug: ioc-vs-ioa
title: "IOC vs IOA: Fingerprints of a Crime vs Someone Picking the Lock"
date: 2026-07-14
updated: 2026-07-14
lang: en
status: published
category: Fundamentals
subcategory: SOC Operations
tags:
  - ioc
  - ioa
  - detection-engineering
  - threat-intelligence
  - soc-fundamentals
summary: >-
  The difference between an Indicator of Compromise and an Indicator of Attack,
  worked through with real values and behaviours pulled from my own log analyses —
  why IOCs go stale, why IOAs survive a tooling change, and why a SOC needs both.
reading_time: 7
difficulty: beginner
author:
  name: Enes Küçükkaya
  url: https://www.linkedin.com/in/eneskucukkaya/
related:
  - linux-auth2log-bruteforce
  - wazuh-sysmon-triage
---

# IOC vs IOA: Fingerprints of a Crime vs Someone Picking the Lock

> **Scope note.** A concepts write-up from a SOC internship, grounded in indicators
> drawn from my own investigations (the [auth2.log analysis](../2026-07-15-linux-auth2log-bruteforce/report.md)
> and the [Wazuh triage](../2026-07-16-wazuh-sysmon-triage/report.md)) rather than
> textbook examples.

---

## 1. Why These Two Concepts Matter

A SOC (Security Operations Center) analyst's job comes down to two questions: *"Has
the system been attacked?"* and *"Is it being attacked right now?"* Two concepts let
us handle those questions separately: **IOC** and **IOA**.

In short: an IOC looks at the past; an IOA looks at the present / future intent.
Finding the *trace* of an event (IOC) is collecting evidence after it has already
happened. Catching a *behaviour* (IOA) is sensing intent before the attack completes.
Good defence uses both.

> **One-liner.** IOC = "A crime was committed — here's the fingerprint."
> IOA = "Someone is picking the lock — they haven't got in yet."

---

## 2. IOC — Indicator of Compromise

An IOC is concrete, technical evidence left behind that a system has been
compromised. It's usually a fixed value: an IP address, a file hash, a domain, a
file path. These values are kept as a *searchable list* and logs/systems are scanned
for their presence.

**Key property: an IOC is reactive** — it's useful *after* the event. It works on
the logic of "if you've seen this IP, you were probably already breached." Its value
is definite (present or absent), which makes it well suited to automated scanning.

### 2.1 Common IOC Types and Examples

| IOC type | Example | What it indicates |
| :--- | :--- | :--- |
| Malicious IP | `185.220.101.45` | A known attacker / C2 server |
| File hash (SHA256) | `1C84C86...4B020F9A94` | A known malware file |
| Malicious domain | `evil-c2-server.xyz` | An address the malware connects to |
| File path / name | `C:\Temp\backdoor.exe` | Executable in a suspicious location |
| Registry key | `...\Run\EvilBackdoor` | A persistence trace |
| URL | `http://x.com/payload.ps1` | A malicious-content download address |
| Email indicator | `invoice@fake-bank.co` | A phishing sender address |

### 2.2 Real IOCs From My Own Analysis

Some values found in the auth2.log analysis are IOCs directly — because they are
concrete values that can be *searched for* in logs after the event:

> - **IOC (IP):** `24.151.103.17` → the IP that successfully accessed `elastic_user_0`
> - **IOC (IP):** `49.4.143.105` → the IP that hit `root` 120 times
> - **IOC (user):** `elastic_user_0` → the compromised account
> - **IOC (registry):** `...\Run\EvilBackdoor` (from the Windows scenario)
> - **IOC (file):** `C:\Users\...\backdoor.exe`

Next, these IOCs can go into a blocklist: these IPs get blocked at the firewall, and
this registry key gets hunted for across other machines.

---

## 3. IOA — Indicator of Attack

An IOA is a behavioural sign that an attack is *in progress*. Unlike an IOC, it's not
a fixed value — it's a sequence of actions / an intent. It focuses on *what is being
done*, not *who* or *which file*.

**Key property: an IOA is proactive** — it aims to catch the attack *before it
completes*. Whatever IP or tool the attacker uses, the *behaviour* stays the same.
For example, "hundreds of failed logins in a short window" is an IOA; even if the
attacker changes IP, the behaviour pattern doesn't change.

### 3.1 Common IOA Examples

- A large number of failed login attempts in a short time (brute-force behaviour).
- An account active at an hour it normally never is (anomalous timing).
- A user logging in normally, then immediately attempting privilege escalation.
- PowerShell running an obfuscated (Base64-encoded) command.
- A process trying to read `lsass.exe` memory (credential-dumping behaviour).
- Many accounts created back-to-back in a short window (bulk provisioning / persistence).

### 3.2 Real IOAs From My Own Analysis

Some findings from auth2.log are IOAs — because they are not a *value* but a
*behaviour pattern*:

> - **IOA:** 147 consecutive failed attempts against `elastic_user_0`, roughly one
>   every 3 seconds (→ brute-force behaviour; the pattern is the same regardless of IP)
> - **IOA:** 10 accounts (`elastic_user_0-9`) created back-to-back within a single
>   second (→ script-based bulk account creation)
> - **IOA (Windows):** running an obfuscated command via `powershell.exe -EncodedCommand`
>   (→ obfuscation / defense-evasion behaviour)

---

## 4. IOC vs IOA Compared

| IOC (Indicator of Compromise) | IOA (Indicator of Attack) |
| :--- | :--- |
| Looks at the past — "did it happen?" | Looks at the present — "is it happening?" |
| Reactive (after the event) | Proactive (during the event) |
| Fixed value (IP, hash, domain) | Behaviour / intent pattern |
| Useless once the attacker changes the value | Still valid even if the attacker changes tools |
| Well suited to automated scanning | Requires correlation and behavioural analysis |
| e.g. IP `24.151.103.17` | e.g. 147 consecutive failed logins |

**A simple analogy.** Picture a burglar breaking into a house. **IOC** = the broken
window, the footprint on the floor, the serial number of the stolen item (the event
is over, you're collecting evidence). **IOA** = someone forcing the door lock at
midnight, peering in through the window (the event hasn't happened yet, you're seeing
the intent). A good security system uses both the alarm (IOA) and the evidence record
afterwards (IOC).

---

## 5. Why You Need Both

IOC and IOA are complements, not rivals. Relying on IOCs alone is dangerous because:

- **IOCs go stale:** the moment the attacker uses a new IP or a new file, the old IOC
  list is useless. Because new malware is produced every day, IOC lists can never be
  complete.
- **IOCs are always late:** to see an IOC at all, the attack must already have
  happened.

An IOA is more durable because it targets the attacker's *behaviour* — an attacker
can't easily change the fundamental method of brute-forcing or dumping credentials.
But IOAs can produce false positives too, which is why the analyst must weigh the
context.

> **Practical upshot.** Catch the attack early with IOAs; confirm the event and hunt
> it across other systems with IOCs. When triaging as a SOC analyst, asking "Is this
> an IOA (behaviour) or an IOC (value)?" helps you classify the event correctly and
> take the right action.

**Summary:** IOC is the "what did we find" question; IOA is the "what is happening"
question. In my own log analysis I used both — IPs like `24.151.103.17` were my IOCs,
while patterns like 147 consecutive failed attempts were my IOAs.
