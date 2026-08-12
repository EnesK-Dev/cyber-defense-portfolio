# Adding a Report — Workflow / Runbook

This is the exact, repeatable process for turning a `.docx` report (Turkish, with
embedded screenshots) into a published, blog-ready English write-up in this repo.
Follow it top to bottom for each new report.

> **Contract:** the output format is defined in [`../CONTENT_SCHEMA.md`](../CONTENT_SCHEMA.md).
> This document is the *procedure*; that one is the *spec*. Read both.

---

## TL;DR — the loop

For each `.docx`:

1. **Inventory** it (word count, image count) → decide: real report, or draft/scratch to skip.
2. **Scaffold** with `scripts/docx2md.py` → creates the report dir, extracts text + images.
3. **Read** the scaffolded `report.md`.
4. **Verify every screenshot visually** (open each PNG) and confirm it matches the prose.
5. **Rename** each `NN-TODO.png` to a descriptive name.
6. **Rewrite** `report.md`: translate to English, write real frontmatter, fix image alts, convert single-cell tables to code blocks / blockquotes.
7. **Build** with `scripts/build_index.py` → regenerates `index.json` + README table, validates.
8. **Commit + push** (one commit per report, or per logical group).

Do all of a report before moving to the next — don't batch half-finished reports.

---

## 0. Prerequisites

- Python 3 with PyYAML (`python3 -c "import yaml"` should succeed).
- No pandoc/libreoffice needed — `docx2md.py` is pure stdlib (a `.docx` is a zip of XML).
- Work from the repo root: `/home/ryuk/cyber-defense-portfolio`.
- Source docs live under `~/Desktop/hafta{1..4}/` and `~/Downloads/`.

---

## 1. Inventory the candidate docs

Before converting anything, list candidates with their word/image counts so you can
tell real reports from drafts and screenshot dumps:

```bash
for f in ~/Desktop/hafta*/*.docx; do
  imgs=$(unzip -l "$f" 2>/dev/null | grep -c 'media/')
  words=$(unzip -p "$f" word/document.xml 2>/dev/null | sed 's/<[^>]*>/ /g' | wc -w)
  printf "%4s imgs %6s words  %s\n" "$imgs" "$words" "$(basename "$f")"
done
```

**Decision rules (learned from experience):**

- **Near-zero words + many images** (e.g. 19 words / 16 images) = a **draft or screenshot
  dump**. Skip it. These are usually the raw source for a polished report.
- **A "Yaptıklarım / Kurulum Aşaması" (what-I-did / setup-phase) note** = a work log, not a
  report. Skip.
- **Two files on the same topic** (e.g. `auth.log` and `auth2.log`) are usually **two
  separate reports** — keep both with distinct slugs, don't merge.
- Everything with real prose + a coherent structure = convert it.

To preview a doc's title/date/topic without converting, extract its first paragraphs:

```bash
python3 - <<'EOF'
import zipfile
from xml.etree import ElementTree as ET
W='{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
p='/home/ryuk/Desktop/haftaX/FILE.docx'
root=ET.fromstring(zipfile.ZipFile(p).read('word/document.xml').decode())
for para in list(root.iter(W+'p'))[:8]:
    t=''.join(x.text or '' for x in para.iter(W+'t')).strip()
    if t: print(' ', t[:110])
EOF
```

---

## 2. Scaffold with docx2md.py

```bash
python3 scripts/docx2md.py "/home/ryuk/Desktop/haftaX/FILE.docx" \
  --slug my-report-slug --date YYYY-MM-DD
```

- `--slug` must be lowercase, hyphen-separated, and unique. **Never change it after publishing** (it's the permalink).
- `--date` is `YYYY-MM-DD`. Take it from the doc's content, not the file mtime. The report
  directory is named `<date>-<slug>`.
- Output: `reports/<date>-<slug>/report.md` (placeholder frontmatter + extracted body) and
  `reports/<date>-<slug>/assets/NN-TODO.png` (images, in document order).

The converter handles two things that broke naively-written extractors — keep them in mind
if you ever touch the script:

- **Heading styles** are resolved through `styles.xml` (Google Docs exports use opaque
  numeric style ids like `706` whose name is "Heading 1").
- **Images inside table cells** are extracted (several reports put *all* screenshots in
  tables) and emitted as figures right after the table.

The scaffold reports how many headings and images it found — sanity-check that image count
against the inventory from step 1.

---

## 3. Read the scaffold

```
Read reports/<date>-<slug>/report.md
```

Get the full structure in your head before writing. Note where each `![...](assets/NN-TODO.png)`
sits relative to the prose — that tells you what each screenshot must show.

---

## 4. Verify EVERY screenshot visually — do not skip this

Open each PNG and confirm it matches the surrounding text. This is the step that catches
mislabeled/misordered images and lets you write accurate alt text.

```
Read reports/<date>-<slug>/assets/01-TODO.png
Read reports/<date>-<slug>/assets/02-TODO.png
...
```

Batch several Read calls per turn for speed. For a 17-image report that's ~3 turns.
**Never name or describe an image you haven't looked at.**

---

## 5. Rename assets to descriptive names

Once verified, rename each `NN-TODO.png` to `NN-short-description.png` (keep the numeric
prefix so document order is preserved):

```bash
cd reports/<date>-<slug>/assets
mv 01-TODO.png 01-wireshark-conversations-ipv4.png
mv 02-TODO.png 02-http-request-filter.png
# ...one per image
```

---

## 6. Rewrite report.md

Overwrite the scaffold with the finished report. Checklist:

**Frontmatter** (see `CONTENT_SCHEMA.md` for the full field list):
- Required: `slug`, `title`, `date`, `lang: en`, `status: published`, `category`, `tags`, `summary`.
- Set a `cover` + `cover_alt` (pick the single most representative screenshot).
- Add the **structured** blocks so the blog can render without parsing prose:
  `mitre_attack` (`{id, name, tactic, confidence}`), `iocs` (`{type, value, context, confidence}`),
  and report-specific ones like `scenarios`, `cves`, `lab`, `target`. Keep them in sync with
  the tables in the body.
- Use `related: [slug, ...]` to cross-link reports.
- Categories in use so far: `Malware Analysis`, `Detection Engineering`, `Threat Intelligence`,
  `Log Analysis`, `Penetration Testing`, `Fundamentals`. Reuse before inventing new ones.

**Body:**
- **Translate to English.** Faithful, technical, keep the analyst's reasoning and the
  "methodology note" / caveat callouts — those are the most valuable part, not the findings list.
- Convert the scaffold's **single-cell tables** (docx callout boxes / command blocks) into
  proper Markdown: commands → fenced code blocks, log excerpts → code blocks, prose callouts
  → blockquotes.
- Every image: real alt text (describe what's in the screenshot) + an italic caption line
  under it.
- Open with a `> **Scope note.**` blockquote framing what the report is (e.g. a training
  exercise) and honest about its limits.

---

## 7. Build + validate

```bash
python3 scripts/build_index.py          # regenerate index.json + README table
python3 scripts/build_index.py --check   # must print "ok — N published report(s)"
```

`--check` fails on: missing required fields, duplicate slugs, missing alt text, absolute
image paths, broken image references, unreferenced assets. Fix any warning before committing.

Sanity grep for leftovers:

```bash
grep -rl "TODO" reports/ ; find reports -name '*TODO*'   # both should be empty
```

---

## 8. Commit + push

One commit per report (or per logical group). Stage the report dir + the regenerated files:

```bash
git add reports/<date>-<slug> index.json README.md
git commit   # message: what the report is + "Regenerates index.json (N published)"
git push origin main
```

This repo is a solo portfolio; committing straight to `main` is fine here. End commit
messages with the `Co-Authored-By:` trailer.

**Verify live** (raw CDN can lag a few seconds — a first 404 then 200 on retry is normal,
not a real failure):

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  "https://raw.githubusercontent.com/EnesK-Dev/cyber-defense-portfolio/main/index.json"
```

---

## Gotchas seen so far

- **`cd` in a compound Bash command** can reset the shell's working dir mid-session — if a
  later `python3 scripts/...` fails with "No such file", prefix it with the repo root.
- **`.claude/settings.local.json.tmp.*`** temp files may appear untracked; don't stage them.
- **A raw.githubusercontent 404 immediately after push** is CDN cache lag. Confirm the file
  is in `origin/main` (`git ls-tree -r --name-only origin/main | grep ...`) and retry — it'll
  be 200.
- **Dates:** when a doc has no explicit report date, place it in the same week as its
  sibling reports; the directory name is the permalink, so decide before publishing.

---

## Still to do / backlog

- Wire the blog to consume `index.json` (the contract in `CONTENT_SCHEMA.md` is ready).
- Remaining source docs, if any new ones appear under `~/Desktop/hafta*/`, follow this same loop.
