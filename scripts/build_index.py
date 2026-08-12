#!/usr/bin/env python3
"""Regenerate index.json and the README report table from reports/*/report.md.

The blog consumes index.json; see CONTENT_SCHEMA.md for the contract.

Usage:
    python3 scripts/build_index.py           # write index.json + patch README
    python3 scripts/build_index.py --check    # exit 1 if anything is out of date
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO / "reports"
INDEX_PATH = REPO / "index.json"
README_PATH = REPO / "README.md"

RAW_BASE = "https://raw.githubusercontent.com/EnesK-Dev/cyber-defense-portfolio/main/"
BLOB_BASE = "https://github.com/EnesK-Dev/cyber-defense-portfolio/blob/main/"

REQUIRED = ("slug", "title", "date", "lang", "status", "category", "tags", "summary")
WORDS_PER_MINUTE = 200

BEGIN = "<!-- REPORTS:BEGIN -->"
END = "<!-- REPORTS:END -->"

FRONT_MATTER = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n", re.DOTALL)


class ValidationError(Exception):
    pass


def split_front_matter(text: str) -> tuple[dict, str]:
    match = FRONT_MATTER.match(text)
    if not match:
        raise ValidationError("missing YAML front matter")
    meta = yaml.safe_load(match.group(1))
    if not isinstance(meta, dict):
        raise ValidationError("front matter is not a mapping")
    return meta, text[match.end():]


def estimate_reading_time(body: str) -> int:
    prose = re.sub(r"```.*?```", "", body, flags=re.DOTALL)
    prose = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", prose)
    return max(1, round(len(prose.split()) / WORDS_PER_MINUTE))


def check_assets(meta: dict, body: str, report_dir: Path) -> list[str]:
    """Return problems with image references (missing files, absolute URLs, no alt)."""
    problems = []
    for alt, target in re.findall(r"!\[([^\]]*)\]\(([^)]+)\)", body):
        if target.startswith(("http://", "https://", "/")):
            problems.append(f"absolute image path: {target}")
            continue
        if not alt.strip():
            problems.append(f"image missing alt text: {target}")
        if not (report_dir / target).exists():
            problems.append(f"image not found on disk: {target}")

    cover = meta.get("cover")
    if cover:
        if not (report_dir / cover).exists():
            problems.append(f"cover not found on disk: {cover}")
        if not meta.get("cover_alt"):
            problems.append("cover is set but cover_alt is missing")

    orphans = sorted(
        p.name
        for p in (report_dir / "assets").glob("*")
        if p.is_file() and f"assets/{p.name}" not in body and f"assets/{p.name}" != cover
    ) if (report_dir / "assets").is_dir() else []
    problems += [f"unreferenced asset: assets/{name}" for name in orphans]
    return problems


def load_report(report_dir: Path) -> tuple[dict, list[str]]:
    path = report_dir / "report.md"
    meta, body = split_front_matter(path.read_text(encoding="utf-8"))

    problems = [f"missing required field: {f}" for f in REQUIRED if f not in meta]
    if meta.get("status") not in (None, "draft", "published"):
        problems.append(f"invalid status: {meta['status']!r}")
    problems += check_assets(meta, body, report_dir)

    rel_dir = report_dir.relative_to(REPO).as_posix()
    entry = dict(meta)
    entry["date"] = str(meta.get("date", ""))
    if "updated" in meta:
        entry["updated"] = str(meta["updated"])
    entry.setdefault("reading_time", estimate_reading_time(body))
    entry.update(
        dir=rel_dir,
        path=f"{rel_dir}/report.md",
        asset_base=f"{RAW_BASE}{rel_dir}/",
        content_url=f"{RAW_BASE}{rel_dir}/report.md",
        html_url=f"{BLOB_BASE}{rel_dir}/report.md",
    )
    return entry, [f"{rel_dir}: {p}" for p in problems]


def collect() -> tuple[list[dict], list[str]]:
    entries, problems = [], []
    for report_dir in sorted(REPORTS_DIR.iterdir()):
        if not (report_dir / "report.md").is_file():
            continue
        try:
            entry, issues = load_report(report_dir)
        except (ValidationError, yaml.YAMLError) as exc:
            problems.append(f"{report_dir.relative_to(REPO).as_posix()}: {exc}")
            continue
        entries.append(entry)
        problems += issues

    slugs = [e["slug"] for e in entries if "slug" in e]
    problems += [f"duplicate slug: {s}" for s in {s for s in slugs if slugs.count(s) > 1}]

    entries.sort(key=lambda e: e["date"], reverse=True)
    return entries, problems


def build_index(entries: list[dict]) -> dict:
    published = [e for e in entries if e.get("status") == "published"]
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(published),
        "base_url": RAW_BASE,
        "categories": sorted({e["category"] for e in published if e.get("category")}),
        "tags": sorted({t for e in published for t in e.get("tags", [])}),
        "reports": published,
    }


def build_table(entries: list[dict]) -> str:
    rows = [
        "| Date | Write-up | Category | Tags |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for e in entries:
        if e.get("status") != "published":
            continue
        tags = ", ".join(f"`{t}`" for t in e.get("tags", [])[:4])
        rows.append(f"| {e['date']} | [{e['title']}]({e['path']}) | {e.get('category', '')} | {tags} |")
    if len(rows) == 2:
        rows.append("| — | _No published write-ups yet._ | | |")
    return "\n".join(rows)


def patch_readme(table: str) -> str:
    text = README_PATH.read_text(encoding="utf-8")
    if BEGIN not in text or END not in text:
        raise SystemExit(f"README.md is missing the {BEGIN} / {END} markers")
    return re.sub(
        re.escape(BEGIN) + r".*?" + re.escape(END),
        f"{BEGIN}\n{table}\n{END}",
        text,
        flags=re.DOTALL,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify without writing")
    args = parser.parse_args()

    entries, problems = collect()
    for problem in problems:
        print(f"warning: {problem}", file=sys.stderr)

    index = build_index(entries)
    index_text = json.dumps(index, indent=2, ensure_ascii=False) + "\n"
    readme_text = patch_readme(build_table(entries))

    if args.check:
        stale = []
        # generated_at always differs; compare everything else.
        if INDEX_PATH.exists():
            current = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
            current.pop("generated_at", None)
            fresh = dict(index)
            fresh.pop("generated_at", None)
            if current != fresh:
                stale.append("index.json")
        else:
            stale.append("index.json (missing)")
        if README_PATH.read_text(encoding="utf-8") != readme_text:
            stale.append("README.md")
        if stale or problems:
            print(f"out of date: {', '.join(stale) or 'none'}", file=sys.stderr)
            return 1
        print(f"ok — {index['count']} published report(s)")
        return 0

    INDEX_PATH.write_text(index_text, encoding="utf-8")
    README_PATH.write_text(readme_text, encoding="utf-8")
    print(f"wrote index.json ({index['count']} published) and patched README.md")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
