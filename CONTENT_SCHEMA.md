# Content Schema

This repository is the **single source of truth** for the write-ups. The blog is a
consumer: it reads `index.json` and the raw Markdown, and never stores its own copy
of the content.

## Repository layout

```
cyber-defense-portfolio/
├── index.json                          # generated — the blog's entry point
├── CONTENT_SCHEMA.md                   # this file (the contract)
├── README.md                           # generated table between index markers
├── reports/
│   └── <YYYY-MM-DD>-<slug>/            # one directory per write-up
│       ├── report.md                   # front matter + body
│       └── assets/                     # screenshots, referenced relatively
│           └── 01-....png
└── scripts/
    ├── docx2md.py                      # .docx → report.md + assets scaffold
    └── build_index.py                  # regenerates index.json + README table
```

**Rules:**

1. One directory per write-up, named `<date>-<slug>`. The directory name is the
   permalink segment; renaming it breaks published URLs.
2. Images live in `assets/` next to `report.md` and are referenced **relatively**
   (`assets/01-foo.png`). Never hardcode `raw.githubusercontent.com` URLs — the
   consumer resolves the base path (see below).
3. Every image needs meaningful alt text. It is the accessibility layer *and* the
   figure caption fallback.
4. Run `python3 scripts/build_index.py` before committing. It regenerates
   `index.json` and the README table.

## Front matter

`report.md` opens with a YAML front-matter block delimited by `---`.

### Required fields

| Field | Type | Notes |
| :--- | :--- | :--- |
| `slug` | string | URL-safe, unique across the repo. Must not change once published. |
| `title` | string | Full title, sentence case. |
| `date` | date | `YYYY-MM-DD`. Publication/analysis date; drives sort order. |
| `lang` | string | ISO 639-1 (`en`). |
| `status` | enum | `draft` \| `published`. Only `published` is exported to `index.json`. |
| `category` | string | Top-level grouping, e.g. `Malware Analysis`, `Detection Engineering`. |
| `tags` | string[] | Lowercase, hyphenated. |
| `summary` | string | 1–3 sentences. Used for listing cards, meta description, OG description. |

### Optional fields

| Field | Type | Notes |
| :--- | :--- | :--- |
| `updated` | date | Last substantive edit. |
| `subcategory` | string | Secondary grouping. |
| `cover` | path | Relative path to the hero image. |
| `cover_alt` | string | Alt text for the cover. Required whenever `cover` is set. |
| `reading_time` | int | Minutes. Estimated by `build_index.py` if omitted. |
| `difficulty` | enum | `beginner` \| `intermediate` \| `advanced`. |
| `author` | object | `{ name, url }`. |
| `source` | object | `{ name, exercise, url }` — provenance for public exercises/datasets. |
| `tools` | string[] | Tooling used. |
| `mitre_attack` | object[] | `{ id, name, tactic, confidence }`. `confidence`: `confirmed` \| `probable`. |
| `iocs` | object[] | `{ type, value, context, confidence }`. `type`: `ipv4` \| `ipv6` \| `domain` \| `url` \| `port` \| `sha256` \| `md5` \| `filename` \| `malware`. |
| `victim` | object | Free-form affected-asset details. |

### Why the structured `iocs` and `mitre_attack` blocks

They exist so the blog can render an ATT&CK matrix, a filterable IOC table, and
cross-report "all reports touching T1071" views **without parsing prose**. Keep
them in sync with the tables in the body — the body is for humans, the front
matter is for machines.

## `index.json`

Generated. Do not hand-edit.

```jsonc
{
  "generated_at": "2026-08-12T00:00:00Z",
  "count": 1,
  "base_url": "https://raw.githubusercontent.com/EnesK-Dev/cyber-defense-portfolio/main/",
  "categories": ["Malware Analysis"],
  "tags": ["pcap", "wireshark", "..."],
  "reports": [
    {
      "slug": "strrat-c2-analysis",
      "title": "...",
      "path": "reports/2026-09-06-strrat-c2-analysis/report.md",
      "dir": "reports/2026-09-06-strrat-c2-analysis",
      "asset_base": "https://raw.githubusercontent.com/.../reports/2026-09-06-strrat-c2-analysis/",
      "content_url": "https://raw.githubusercontent.com/.../report.md",
      "html_url": "https://github.com/.../report.md",
      "...": "all front-matter fields, passed through"
    }
  ]
}
```

## How the blog consumes this

1. Fetch `index.json` (from the raw URL, or vendored at build time).
2. For a listing page, render straight from `index.json` — no Markdown parsing needed.
3. For a detail page, fetch `content_url`, strip the front matter, render the Markdown.
4. **Rewrite relative image paths** by prefixing `asset_base`. This is the one
   transformation the consumer must perform:

   ```js
   html = html.replace(/(src=")(?!https?:|\/)/g, `$1${report.asset_base}`);
   ```

5. Route the detail page at `/reports/<slug>`.

Because assets are addressed relatively, the same `report.md` renders correctly on
GitHub, in a local editor, and on the blog — with no duplicated content.
