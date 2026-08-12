---
slug: linux-authlog-analysis
title: "Reading auth.log by Hand: SSH Forensics Without a SIEM"
date: 2026-07-14
updated: 2026-07-14
lang: en
status: published
category: Log Analysis
subcategory: DFIR
tags:
  - linux
  - auth-log
  - ssh
  - brute-force
  - log-forensics
  - grep
  - incident-response
summary: >-
  A manual forensic read of an SSH auth.log using nothing but grep/sort/uniq —
  answering three assigned questions with an evidence chain, then documenting the
  awkward parts: a command mistake that returned a false zero, an odd
  multi-account session burst, and log entries too inconsistent to trust.
reading_time: 13
difficulty: intermediate
author:
  name: Enes Küçükkaya
  url: https://www.linkedin.com/in/eneskucukkaya/
tools:
  - grep
  - sort
  - uniq
target:
  system: ubuntuvm (desktop/workstation)
  artifact: auth.log (324 lines)
iocs:
  - type: ipv4
    value: 13.148.162.206
    context: 17 failed SSH attempts, all against root (targeted brute-force)
    confidence: confirmed
  - type: ipv4
    value: 172.16.8.1
    context: Source of a suspicious multi-account session sequence
    confidence: probable
related:
  - linux-auth2log-bruteforce
  - ioc-vs-ioa
---

# Reading auth.log by Hand: SSH Forensics Without a SIEM

> **Scope note.** Week 2, Scenario 1 of a SOC internship. Deliberately done with
> only command-line tools — no Wazuh, no automated alerts — to exercise the base
> skill of reading a raw log and building an evidence chain. The assignment named
> `auth.log` and `auditd`; no auditd data was available, so the analysis rests
> entirely on `auth.log`.

---

## 1. Purpose and Scope

This report covers the "Scenario 1: unauthorized access analysis on a Linux system"
part of the week-2 assignment, specifically for the `auth.log` file. The goal is to
derive evidence-based findings from raw SSH authentication logs — without any SIEM or
automated alerting — answer the three assigned questions with an evidence chain, and
transparently report the additional findings encountered along the way (data-quality
problems, suspicious-but-unprovable events).

Even with a SIEM like Wazuh installed, a SOC L1 analyst is expected to read and
interpret a raw log by hand — because not every environment has a SIEM, because the
raw data underneath any SIEM alert always has to be verified (triage), and because
SIEM rules are ultimately just automation of logic a human wrote. This report
demonstrates that base skill using only `grep`, `sort`, and `uniq`.

---

## 2. Background

The core concepts used in the analysis, which underpin the method and findings in
Sections 3 and 4.

### 2.1 syslog Format

`auth.log` uses the standard syslog line format:

```
<Month Day Time> <hostname> <process[PID]>: <message>
```

Example: `Mar 04 17:13:26 ubuntuvm sshd[2846]: Failed password for user1 from 192.168.1.1 port 22`
consists of a timestamp (`Mar 04 17:13:26`), hostname (`ubuntuvm`), process and PID
(`sshd[2846]`), and the message body. Knowing this structure is a precondition for
deciding which field to filter on and why.

### 2.2 SSH Authentication Event Types

An SSH login attempt can end three ways, each producing a different log line:

| Event | Meaning |
| :--- | :--- |
| `Accepted password` | The user logged in successfully with the correct password. |
| `Accepted publickey` | The user authenticated with an SSH key pair (private/public key), sending no password. The password never crosses the network. |
| `Failed password` | A wrong password (or rejected key) attempt. |

Some `Failed password` lines contain "invalid user"; this means the attempted
username is not defined on the system (not in `/etc/passwd`) and usually signals an
automated attack tool trying common usernames (`admin`, `test`, `demo`, …).

### 2.3 Recognising a Brute-force Pattern

A single `Failed password` line is normal. What distinguishes brute-force is the
*pattern* of consecutive attempts:

- Attempts repeating at very short intervals from the same IP — the signature of an automated tool.
- Different usernames tried from the same IP — credential stuffing / dictionary attack.
- Dozens of attempts against a single user from the same IP — targeted brute-force.
- A sudden `Accepted` after a long failed streak — the moment the attack succeeds, the most critical finding.

### 2.4 PAM, Session, and Disconnect Concepts

`sshd` does not perform authentication itself; it calls the PAM (Pluggable
Authentication Modules) layer. So some events appear in both `sshd` and `pam_unix`
lines, from two different layers. On SSH connection closes, a `[preauth]` tag means
the connection dropped before authentication completed; the numeric code in
"disconnected by user" (e.g. `:11`) means the client closed the connection
deliberately and cleanly. These distinctions are used directly in the line-by-line
review in Section 6.

---

## 3. Methodology — Step by Step

This section presents the steps in chronological order, *including* the mistakes made
and how they were corrected — because the point is to show not just the results but
the process of reaching them as part of the evidence chain.

### 3.1 Getting to Know the File

Before touching the questions, the file's general character was examined — you have to
know what the data *is* before deciding which pattern to search for.

| Property | Value |
| :--- | :--- |
| Line count | 324 |
| Date range | A few isolated Sep 28 lines, plus the main Jan–Mar data block |
| Dominant process | `sshd` (mostly SSH authentication events) |
| System type | Desktop/workstation — GDM, gnome-keyring, polkitd, and `su` usage present in the log, indicating a workstation rather than a server |

### 3.2 Filtering the SSH Result Types

Each result type was filtered separately with `grep`:

```bash
grep "Failed password" auth.log
grep "Accepted password" auth.log
grep "Accepted publickey" auth.log
```

During this, a command-execution mistake occurred: the terminal prompt line
(`➜ hafta-2-logAnalizi`) was accidentally copied as part of the command, producing
`zsh: command not found: hafta-2-logAnalizi` and causing `wc -l` to print `0` on empty
input. This is a practical example that a zero result does **not** always mean "the
thing searched for isn't there" — the command itself must also be verified. After
correcting it, the right counts came back:

```bash
grep "Failed password" auth.log | wc -l    # → 156
grep "Accepted password" auth.log | wc -l   # → 3
grep "Accepted publickey" auth.log | wc -l  # → 1
```

### 3.3 Extraction

The 156-line `Failed password` list alone doesn't answer "which user/IP was tried
most" — the relevant field (username or IP) has to be extracted from each line. For
this, `grep`'s `-o` (only-matching) and `-P` (Perl-compatible regex, supporting `\K`)
options were used together:

```bash
grep "Failed password" auth.log | grep -oP "for \K\S+"   # username
grep "Failed password" auth.log | grep -oP "from \K\S+"  # IP address
```

`\K` means "don't include what precedes this in the match, capture only what follows";
`\S+` captures the next whitespace-free token (the username or IP).

### 3.4 Grouping and Counting

The extracted values form an unordered list. Since `uniq` only collapses *adjacent*
identical lines, they must first be `sort`ed (so equal values sit together), then
counted with `uniq -c`, then ordered high-to-low with `sort -rn` (`-n`: numeric, `-r`:
reverse):

```bash
grep "Failed password" auth.log | grep -oP "for \K\S+"  | sort | uniq -c | sort -rn
grep "Failed password" auth.log | grep -oP "from \K\S+" | sort | uniq -c | sort -rn
```

### 3.5 Targeted Verification

After identifying the top user (`root`) and top IP (`13.148.162.206`), a query specific
to that IP was run to verify whether the two findings were related. This step kept the
"most frequent" finding from being left as an isolated number and instead interpreted
it within the whole event (see Section 4.3).

---

## 4. Findings

### Question 1 — SSH Access Without a Password

**Q:** Which user accessed SSH by a method other than a password?

**Finding:** User `john` logged in with publickey (RSA key-based) authentication. This
is the only `Accepted publickey` record in the file.

```
Mar 04 21:26:16 ubuntuvm sshd[3886]: Accepted publickey for john from 172.16.8.1 port 53995 ssh2: RSA SHA256:nIFEtPTkmfKWpSVq+yQ4Oy0knlmp+ALf0GSP2kvq59Q
```

**Evidence assessment:** "Accepted publickey" shows authentication was by key pair, not
password; the RSA SHA256 fingerprint on the line is concrete evidence of the key used.
The wider event sequence behind this finding is examined in depth in Section 6.

### Question 2 — Most Failed SSH Attempts (by User)

**Q:** Which user was the target of the most failed SSH login attempts?

**Finding:** `root`, with 54 failed attempts, is the most-targeted account.

```
     54 root
     26 test
     24 user2
     18 admin
     18 user1
     16 demo
```

**Evidence assessment:** `root` (UID 0) is the one account guaranteed to exist on every
Linux system, so it's the most common attacker target and carries no "invalid user"
risk. The other names (`admin`, `test`, `demo`, `user1`, `user2`) are generic usernames
typical of dictionary attacks, tried without knowing whether they exist.

### Question 3 — Most Failed SSH Attempts (by IP)

**Q:** Which IP address made the most failed SSH login attempts?

**Finding:** `13.148.162.206`, with 17 failed attempts, is the most active source IP.

```
     17 13.148.162.206
     13 149.160.103.244
     12 121.81.195.1
      8 111.68.215.146
      4 192.168.1.1
      4 172.16.0.1
```

To verify this IP's target, a focused query was run:

```bash
grep "13.148.162.206" auth.log
# → all 17 lines: Failed password for root from 13.148.162.206
```

**Evidence assessment:** All 17 attempts from `13.148.162.206` target only the `root`
account — direct evidence linking the Q2 and Q3 findings, showing a single source
running a targeted brute-force against root. An additional observation about the
reliability of this IP's data is covered in Section 7.

---

## 5. Deep Dive: John's Dual Authentication Event

While examining the Q1 finding, `john` was found to have *two* separate `Accepted`
records in the file:

```
21:26:10  Accepted password  for john from 172.16.8.1 (PID 3524, port 53992)
21:26:16  Accepted publickey for john from 172.16.8.1 (PID 3886, port 53995)
```

That these two lines are not the same connection logged twice is clear from the
different PIDs (3524 / 3886) and ports (53992 / 53995) — these are two separate,
independent SSH connections from the same user and IP, opened 6 seconds apart.

**Assessment.** A log cannot, by itself, prove "who was at the keyboard"; it only tells
us "authentication succeeded by this method." So this report makes no definitive
"real/impostor" call and instead sticks to the observable fact: `john` logged in
successfully by two different methods from the same IP within a short interval, and
this does not affect the Q1 answer (that the publickey user is `john`). Plausible
explanations for the double login include a sequential terminal + file-transfer
(scp/sftp) session, or a script/automation opening a second connection; the exact cause
cannot be determined from the log data.

---

## 6. Deep Dive: The 172.16.8.1 / 131.101.100.68 Session Sequence

Hours after the main brute-force wave (04 Mar, 16:06–17:45, many distributed IPs), a
differently-shaped sequence of events was found between 21:26 and 21:28. It was
examined line by line across these nine lines:

```
Mar 04 21:26:10 sshd[3524]: Accepted password for john from 172.16.8.1 port 53992 ssh2
Mar 04 21:26:16 sshd[3886]: Accepted publickey for john from 172.16.8.1 port 53995 ssh2
Mar 04 21:28:28 sshd[3926]: Disconnected from user john 172.16.8.1 port 53995
Mar 04 21:28:31 sshd[3994]: Accepted password for jakup from 131.101.100.68 port 54010 ssh2
Mar 04 21:28:31 sshd[3994]: Accepted password for admin from 172.16.8.1 port 54010 ssh2
Mar 04 21:28:33 sshd[4034]: Received disconnect from 172.16.8.1 port 54010:11: disconnected by user
Mar 04 21:28:33 sshd[4034]: Disconnected from user admin 172.16.8.1 port 54010
Mar 04 21:28:37 sshd[4043]: pam_unix(sshd:auth): authentication failure; rhost=172.16.8.1 user=root
Mar 04 21:28:40 sshd[4043]: Failed password for root from 172.16.8.1 port 54011 ssh2
Mar 04 21:28:40 sshd[4043]: Connection closed by authenticating user root 172.16.8.1 port 54011 [preauth]
```

### 6.1 Line-by-line analysis

1. **21:26:10 — Accepted password for john (port 53992):** John logged in with a
   password. PID 3524, port 53992 is this connection's unique identity.
2. **21:26:16 — Accepted publickey for john (port 53995):** 6 seconds later, the same
   user and IP open a second, independent connection with a different PID (3886) and
   port (53995) (see Section 5).
3. **21:28:28 — Disconnected from user john (port 53995):** The connection that closes
   is 53995, i.e. the second (publickey) one. There is *no* log record of when the
   first connection (53992, password) closed; this could be a missing record, or the
   connection may have stayed open beyond this window.
4. **21:28:31 — Accepted password for jakup (131.101.100.68, port 54010):** 3 seconds
   after john's publickey connection closes, a successful password login for user
   `jakup` is recorded from a different IP (131.101.100.68).
5. **21:28:31 — Accepted password for admin (172.16.8.1, port 54010):** A second line
   with the *exact same* timestamp, PID (3994), and port (54010) as the previous, but a
   different user (`admin`) and IP (172.16.8.1). This collision is evaluated in detail
   in Section 7.
6. **21:28:33 — Received disconnect ...:11 disconnected by user:** The connection (port
   54010) closed with disconnect reason code `:11`, indicating the client ended it
   deliberately and cleanly — not a drop or error.
7. **21:28:33 — Disconnected from user admin (port 54010):** The sshd-level confirmation
   of the previous line; admin's session is formally closed.
8. **21:28:37 — pam_unix(sshd:auth): authentication failure (user=root):** 4 seconds
   after admin's connection closes, an authentication attempt for `root` begins from the
   same IP (172.16.8.1) and is marked failed at the PAM layer. This line is the PAM-level
   counterpart of the next `Failed password` line — the same event seen from two layers
   (PAM and sshd).
9. **21:28:40 — Failed password for root + Connection closed [preauth]:** The sshd-level
   confirmation of the same event, then the connection dropping before authentication
   completed (preauth); the root attempt ended in a single try, not retried.

### 6.2 Synthesis

Within roughly 2.5 minutes, a single IP (172.16.8.1) tried three different usernames in
sequence (`john` by two methods, `admin`, `root`). The first two (`john`, `admin`)
succeeded on the first try every time — there are no preceding failed records, so this
is *not* a brute-force. But multiple different accounts tried back-to-back from the same
source, followed by a root attempt, looks more like systematic account enumeration than
legitimate admin activity. A definitive True Positive / False Positive call needs
additional context (the normal owner of 172.16.8.1, whether john/admin are expected to
be working at this hour); no such context exists within this report's scope, so the
finding is classified as "a suspicious observation requiring further investigation."

---

## 7. Overall Assessment and Conclusion

The `auth.log` file contains three chronologically distinct kinds of event:

- **Jan–Feb:** isolated failed attempts from private IPs (192.168.1.1, 172.16.0.1,
  10.0.0.1) — insignificant background noise from a SOC standpoint.
- **04 Mar 16:06–17:45:** an intense brute-force scan from many distributed public IPs
  against generic usernames (especially `root`) — a True Positive attack attempt, but
  inconclusive since the file holds no successful login from any attacker IP.
- **04 Mar 21:26–21:28:** successful logins to multiple accounts in sequence from a
  single source (172.16.8.1), followed by a failed root attempt — a differently-shaped
  event that warrants close watching but can't be resolved conclusively due to
  data-quality problems.

> **On data quality.** Line 5 in Section 6.1 shows a genuine anomaly: two log lines
> sharing the identical timestamp, PID, and port but differing in user and IP. A single
> connection cannot legitimately belong to two users/IPs at once, so at least one of
> these records is unreliable — likely a logging artifact or corruption. This is exactly
> why raw data must be read sceptically: a finding is only as good as the record it
> rests on.

The answers to Questions 1, 2, and 3 are, respectively, `john` (publickey), `root` (54
failed attempts), and `13.148.162.206` (17 failed attempts), with the three findings
linked by evidence (all of 13.148.162.206's attempts targeting root). In addition, two
findings outside the questions' scope but surfaced during analysis — the separate
172.16.8.1 session sequence and the file-wide data-quality problems — are reported in
their own sections in the interest of transparency.

This report was produced entirely by manual command-line analysis, without Wazuh or any
other SIEM; the mistakes encountered in the process (Section 3.2) and the sceptical
approach to the raw data (Section 7) are documented as inseparable parts of building a
sound evidence chain.
