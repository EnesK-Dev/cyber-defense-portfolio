#!/usr/bin/env python3
"""Scaffold a report directory from a .docx file.

Extracts text (headings, paragraphs, tables, lists) and embedded images into the
repo layout described in CONTENT_SCHEMA.md. The output is a *starting point*, not
a finished report: images get placeholder names, front matter gets placeholder
values, and the prose still needs editing.

Usage:
    python3 scripts/docx2md.py <input.docx> --slug <slug> --date YYYY-MM-DD [--force]

Depends only on the standard library (a .docx is a zip of XML).
"""

from __future__ import annotations

import argparse
import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

REPO = Path(__file__).resolve().parent.parent

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"

FRONT_MATTER_TEMPLATE = """---
slug: {slug}
title: "TODO — full title"
date: {date}
lang: en
status: draft
category: TODO
tags:
  - todo
summary: >-
  TODO — one to three sentences for listing cards and meta description.
difficulty: intermediate
author:
  name: Enes Küçükkaya
  url: https://www.linkedin.com/in/eneskucukkaya/
tools:
  - TODO
---

"""


def para_text(para: ET.Element) -> str:
    """Concatenate runs, mapping <w:br>/<w:tab> to whitespace."""
    parts = []
    for node in para.iter():
        if node.tag == W + "t":
            parts.append(node.text or "")
        elif node.tag == W + "tab":
            parts.append(" ")
        elif node.tag == W + "br":
            parts.append(" ")
    return re.sub(r"\s+", " ", "".join(parts)).strip()


def load_heading_styles(zf: zipfile.ZipFile) -> dict[str, int]:
    """Map style id -> heading level.

    Word writes ids like "Heading2", but Google Docs exports use opaque numeric
    ids ("706") whose <w:name> is "Heading 1". Resolve through styles.xml so both
    shapes work.
    """
    levels: dict[str, int] = {}
    try:
        styles = ET.fromstring(zf.read("word/styles.xml").decode("utf-8"))
    except KeyError:
        return levels
    for style in styles.findall(W + "style"):
        style_id = style.get(W + "styleId")
        if not style_id:
            continue
        name_el = style.find(W + "name")
        name = name_el.get(W + "val", "") if name_el is not None else ""
        for candidate in (name, style_id):
            match = re.fullmatch(r"(?i)heading\s*([1-6])", candidate.strip())
            if match:
                levels[style_id] = int(match.group(1))
                break
    return levels


def heading_level(para: ET.Element, style_levels: dict[str, int]) -> int:
    """Return 1-6 for a heading paragraph, else 0."""
    p_pr = para.find(W + "pPr")
    if p_pr is None:
        return 0
    style = p_pr.find(W + "pStyle")
    if style is not None:
        val = style.get(W + "val", "")
        if val in style_levels:
            return style_levels[val]
        match = re.fullmatch(r"(?i)heading\s*([1-6])", val)
        if match:
            return int(match.group(1))
    outline = p_pr.find(W + "outlineLvl")
    if outline is not None:
        try:
            return min(6, int(outline.get(W + "val", "9")) + 1)
        except ValueError:
            return 0
    return 0


def is_list_item(para: ET.Element) -> bool:
    p_pr = para.find(W + "pPr")
    return p_pr is not None and p_pr.find(W + "numPr") is not None


def image_ids(element: ET.Element) -> list[str]:
    """Relationship ids of every embedded image under `element`, in document order.

    Covers both DrawingML (<a:blip>) and legacy VML (<v:imagedata>); documents
    exported from Google Docs emit both for the same picture, so de-duplicate
    while preserving order.
    """
    ids: list[str] = []
    for node in element.iter():
        rid = None
        if node.tag == A + "blip":
            rid = node.get(R + "embed")
        elif node.tag.endswith("}imagedata"):
            rid = node.get(R + "id")
        if rid and rid not in ids:
            ids.append(rid)
    return ids


def render_table(tbl: ET.Element) -> list[str]:
    rows = []
    for tr in tbl.findall(W + "tr"):
        cells = [
            " ".join(para_text(p) for p in tc.findall(W + "p")).strip()
            for tc in tr.findall(W + "tc")
        ]
        rows.append([c.replace("|", "\\|") for c in cells])
    if not rows:
        return []
    width = max(len(r) for r in rows)
    rows = [r + [""] * (width - len(r)) for r in rows]
    out = ["| " + " | ".join(rows[0]) + " |", "| " + " | ".join([":---"] * width) + " |"]
    out += ["| " + " | ".join(r) + " |" for r in rows[1:]]
    return out


def convert(docx: Path, out_dir: Path, slug: str, date: str) -> tuple[int, int]:
    zf = zipfile.ZipFile(docx)
    rels_xml = zf.read("word/_rels/document.xml.rels").decode("utf-8")
    rel_target = {
        m.group(1): m.group(2)
        for m in re.finditer(r'Id="(rId\d+)"[^>]*Target="([^"]+)"', rels_xml)
    }

    assets_dir = out_dir / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)

    saved: dict[str, str] = {}
    lines: list[str] = []
    style_levels = load_heading_styles(zf)
    body = ET.fromstring(zf.read("word/document.xml").decode("utf-8")).find(W + "body")

    def emit_images(element: ET.Element) -> None:
        for rid in image_ids(element):
            target = rel_target.get(rid)
            if not target:
                continue
            if target not in saved:
                name = f"{len(saved) + 1:02d}-TODO{Path(target).suffix}"
                (assets_dir / name).write_bytes(zf.read("word/" + target.lstrip("/")))
                saved[target] = name
            lines.extend(["", f"![TODO — describe this screenshot](assets/{saved[target]})", ""])

    for child in body:
        if child.tag == W + "tbl":
            lines += ["", *render_table(child), ""]
            # Markdown tables cannot hold block images, so pictures embedded in
            # cells are emitted as figures immediately after the table.
            emit_images(child)
            continue
        if child.tag != W + "p":
            continue

        emit_images(child)

        text = para_text(child)
        if not text:
            continue
        level = heading_level(child, style_levels)
        if level:
            lines += ["", "#" * min(level + 1, 6) + " " + text, ""]
        elif is_list_item(child):
            lines.append(f"- {text}")
        else:
            lines += ["", text, ""]

    # collapse runs of blank lines
    md, blank = [], False
    for line in lines:
        if line.strip():
            md.append(line)
            blank = False
        elif not blank:
            md.append("")
            blank = True

    front = FRONT_MATTER_TEMPLATE.format(slug=slug, date=date)
    (out_dir / "report.md").write_text(front + "\n".join(md).strip() + "\n", encoding="utf-8")
    return len(saved), sum(1 for line in md if line.startswith("#"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("docx", type=Path)
    parser.add_argument("--slug", required=True, help="URL-safe slug, e.g. wazuh-agent-setup")
    parser.add_argument("--date", required=True, help="YYYY-MM-DD")
    parser.add_argument("--force", action="store_true", help="overwrite an existing directory")
    args = parser.parse_args()

    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.date):
        parser.error("--date must be YYYY-MM-DD")
    if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", args.slug):
        parser.error("--slug must be lowercase, hyphen-separated")

    out_dir = REPO / "reports" / f"{args.date}-{args.slug}"
    if (out_dir / "report.md").exists() and not args.force:
        parser.error(f"{out_dir.relative_to(REPO)} already exists (use --force to overwrite)")

    images, headings = convert(args.docx, out_dir, args.slug, args.date)
    rel = out_dir.relative_to(REPO)
    print(f"created {rel}/report.md  ({headings} headings, {images} images)")
    print("\nNext:")
    print(f"  1. Fill in the TODO front matter in {rel}/report.md (status: draft -> published)")
    print(f"  2. Rename {rel}/assets/NN-TODO.png to describe each screenshot")
    print("  3. Replace every 'TODO — describe this screenshot' alt text")
    print("  4. python3 scripts/build_index.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
