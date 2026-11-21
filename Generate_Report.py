#!/usr/bin/env python3
"""
Professional security assessment PDF generator.

Usage:
  python security_report.py findings.json
  python security_report.py findings.zip
  python security_report.py findings.zip --json-member Output/output_before.json
  python security_report.py findings.json -o Client_Assessment_Report.pdf

Dependency:
  pip install reportlab

Input is expected to be JSON containing a list of findings, commonly:
  {"total_findings": 3, "findings": [{...}, ...]}

The parser also accepts a root-level list and several common wrapper keys.
Missing fields are handled gracefully. AI-generated findings are reported as
provided; this tool does not independently validate exploitability.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, Preformatted, HRFlowable
)
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics


# Palette: restrained navy / slate with severity accents.
NAVY = colors.HexColor("#14243A")
BLUE = colors.HexColor("#245B86")
INK = colors.HexColor("#202B38")
MUTED = colors.HexColor("#647386")
PALE = colors.HexColor("#F2F5F8")
LINE = colors.HexColor("#D9E0E7")
WHITE = colors.white
SEVERITY = {
    "CRITICAL": colors.HexColor("#8E2430"),
    "HIGH": colors.HexColor("#C45135"),
    "MEDIUM": colors.HexColor("#B77A18"),
    "LOW": colors.HexColor("#397A67"),
    "INFO": colors.HexColor("#52677D"),
    "INFORMATIONAL": colors.HexColor("#52677D"),
}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL", "UNKNOWN"]


def clean(value: Any, fallback: str = "Not provided") -> str:
    """Convert arbitrary JSON values to safe, readable text."""
    if value is None or value == "":
        return fallback
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value)


def normalize_severity(value: Any) -> str:
    s = clean(value, "UNKNOWN").strip().upper()
    aliases = {"INFORMATION": "INFO", "INFORMATIONAL": "INFORMATIONAL",
               "MODERATE": "MEDIUM", "WARNING": "MEDIUM"}
    s = aliases.get(s, s)
    return s if s in SEVERITY else "UNKNOWN"


def find_findings(obj: Any) -> tuple[list[dict], dict]:
    """Accept common model-output shapes without assuming one exact schema."""
    metadata = {}
    if isinstance(obj, list):
        raw = obj
    elif isinstance(obj, dict):
        metadata = {k: v for k, v in obj.items()
                    if k not in {"findings", "vulnerabilities", "issues", "results", "data"}}
        raw = None
        for key in ("findings", "vulnerabilities", "issues", "results"):
            if isinstance(obj.get(key), list):
                raw = obj[key]
                break
        if raw is None and isinstance(obj.get("data"), list):
            raw = obj["data"]
        if raw is None and isinstance(obj.get("data"), dict):
            return find_findings(obj["data"])
        if raw is None:
            # A single finding object is also accepted.
            if any(k in obj for k in ("finding_type", "title", "vulnerability", "severity")):
                raw = [obj]
            else:
                raise ValueError("Could not locate a findings array. Expected keys such as "
                                 "'findings', 'vulnerabilities', 'issues' or 'results'.")
    else:
        raise ValueError("JSON root must be an object or an array.")

    findings = [x for x in raw if isinstance(x, dict)]
    if not findings:
        raise ValueError("The JSON contains no finding objects.")
    return findings, metadata


def load_input(path: Path, member: str | None) -> tuple[Any, str]:
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as zf:
            candidates = [n for n in zf.namelist()
                          if n.lower().endswith(".json") and not n.endswith("/")]
            if not candidates:
                raise ValueError("No .json file was found inside the ZIP archive.")
            if member:
                if member not in candidates:
                    raise ValueError(f"'{member}' is not a JSON member in this ZIP. "
                                     f"Available: {', '.join(candidates)}")
                chosen = member
            else:
                # Prefer a final/normal output over files marked before, old, or raw.
                def score(name: str) -> tuple[int, int]:
                    low = name.lower()
                    penalty = int("before" in low or "old" in low or "raw" in low)
                    return (penalty, len(name))
                chosen = sorted(candidates, key=score)[0]
            return json.loads(zf.read(chosen).decode("utf-8-sig")), chosen
    return json.loads(path.read_text(encoding="utf-8-sig")), path.name


def make_styles():
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle("CoverTitle", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=27, leading=32, textColor=NAVY, alignment=TA_LEFT, spaceAfter=10),
        "cover_sub": ParagraphStyle("CoverSub", parent=base["Normal"], fontName="Helvetica",
            fontSize=11, leading=17, textColor=MUTED, spaceAfter=5),
        "h1": ParagraphStyle("Section", parent=base["Heading1"], fontName="Helvetica-Bold",
            fontSize=17, leading=21, textColor=NAVY, spaceBefore=8, spaceAfter=10),
        "h2": ParagraphStyle("Subsection", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=10, leading=13, textColor=BLUE, spaceBefore=8, spaceAfter=4),
        "body": ParagraphStyle("BodyCustom", parent=base["BodyText"], fontName="Helvetica",
            fontSize=8.6, leading=12.4, textColor=INK, spaceAfter=5, splitLongWords=1),
        "small": ParagraphStyle("SmallCustom", parent=base["BodyText"], fontName="Helvetica",
            fontSize=7.3, leading=10, textColor=MUTED, spaceAfter=3),
        "label": ParagraphStyle("Label", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=7.1, leading=9, textColor=MUTED, spaceAfter=2),
        "finding_title": ParagraphStyle("FindingTitle", parent=base["Heading2"],
            fontName="Helvetica-Bold", fontSize=12.5, leading=16, textColor=NAVY,
            spaceBefore=2, spaceAfter=5),
        "code": ParagraphStyle("CodeCustom", parent=base["Code"], fontName="Courier",
            fontSize=7.1, leading=9.2, textColor=INK, backColor=PALE,
            borderColor=LINE, borderWidth=0.5, borderPadding=6, spaceBefore=2, spaceAfter=6),
        "white_small": ParagraphStyle("WhiteSmall", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=8, leading=10, textColor=WHITE),
    }


def esc(text: Any) -> str:
    s = clean(text)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace("\n", "<br/>"))


def code_block(value: Any, styles):
    s = clean(value)
    if s == "Not provided":
        return Paragraph("<i>Not provided</i>", styles["small"])
    # Preformatted preserves source/code indentation and wraps long lines safely.
    return Preformatted(s[:12000], styles["code"], maxLineLength=105)


def field(story, label, value, styles, code=False):
    story.append(Paragraph(esc(label).upper(), styles["label"]))
    story.append(code_block(value, styles) if code else Paragraph(esc(value), styles["body"]))


class NumberedCanvasDoc(BaseDocTemplate):
    pass


def page_decor(canvas, doc):
    canvas.saveState()
    w, h = A4
    if doc.page > 1:
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.5)
        canvas.line(18*mm, h-15*mm, w-18*mm, h-15*mm)
        canvas.setFont("Helvetica-Bold", 7)
        canvas.setFillColor(NAVY)
        canvas.drawString(18*mm, h-11.5*mm, "CONFIDENTIAL | SECURITY ASSESSMENT")
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawRightString(w-18*mm, h-11.5*mm, "FINDINGS & REMEDIATION")
    canvas.setStrokeColor(LINE)
    canvas.line(18*mm, 14*mm, w-18*mm, 14*mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(w-18*mm, 9*mm, f"Page {doc.page}")
    canvas.restoreState()


def build_report(findings: list[dict], metadata: dict, source_name: str, output: Path):
    styles = make_styles()
    doc = BaseDocTemplate(str(output), pagesize=A4, rightMargin=18*mm, leftMargin=18*mm,
                          topMargin=22*mm, bottomMargin=21*mm,
                          title="Application Security Assessment",
                          author="Security Assessment Reporting")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="normal")
    doc.addPageTemplates([PageTemplate(id="main", frames=frame, onPage=page_decor)])
    story = []

    counts = Counter(normalize_severity(f.get("severity")) for f in findings)
    total = len(findings)
    generated = datetime.now().astimezone().strftime("%d %B %Y, %H:%M %Z")
    report_id = "SAR-" + datetime.now().strftime("%Y%m%d-%H%M")

    # Cover
    story += [Spacer(1, 28*mm),
              Paragraph("APPLICATION SECURITY<br/>ASSESSMENT", styles["cover_title"]),
              HRFlowable(width="100%", thickness=2, color=BLUE, spaceBefore=5, spaceAfter=13),
              Paragraph("Vulnerability Findings &amp; Remediation Report", styles["cover_sub"]),
              Spacer(1, 18*mm)]
    cover_rows = [
        [Paragraph("<b>REPORT ID</b>", styles["small"]), Paragraph(esc(report_id), styles["body"])],
        [Paragraph("<b>GENERATED</b>", styles["small"]), Paragraph(esc(generated), styles["body"])],
        [Paragraph("<b>SOURCE FILE</b>", styles["small"]), Paragraph(esc(source_name), styles["body"])],
        [Paragraph("<b>FINDINGS</b>", styles["small"]), Paragraph(str(total), styles["body"])],
        [Paragraph("<b>ASSESSMENT BASIS</b>", styles["small"]),
         Paragraph("Structured findings supplied in JSON format", styles["body"])],
    ]
    t = Table(cover_rows, colWidths=[43*mm, 115*mm], hAlign="LEFT")
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),PALE),("BOX",(0,0),(-1,-1),0.6,LINE),
                           ("INNERGRID",(0,0),(-1,-1),0.35,LINE),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                           ("LEFTPADDING",(0,0),(-1,-1),9),("RIGHTPADDING",(0,0),(-1,-1),9),
                           ("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8)]))
    story += [t, Spacer(1, 23*mm),
              Paragraph("CONFIDENTIAL", ParagraphStyle("Conf", parent=styles["h2"], textColor=SEVERITY["HIGH"])),
              Paragraph("This document may contain security-sensitive technical details. "
                        "Distribute only to authorized stakeholders.", styles["small"]),
              PageBreak()]

    # Executive summary
    story.append(Paragraph("01 | Executive Summary", styles["h1"]))
    story.append(Paragraph(
        f"This report presents <b>{total}</b> structured security finding(s) extracted from "
        f"<b>{esc(source_name)}</b>. Severity values below are reproduced from the supplied "
        "data and have not been independently re-scored by this reporting utility.", styles["body"]))
    sev_rows = [["SEVERITY", "COUNT"]]
    for sev in SEVERITY_ORDER:
        if counts.get(sev, 0):
            sev_rows.append([sev, str(counts[sev])])
    sev_table = Table(sev_rows, colWidths=[65*mm, 30*mm], hAlign="LEFT")
    ts = [("BACKGROUND",(0,0),(-1,0),NAVY),("TEXTCOLOR",(0,0),(-1,0),WHITE),
          ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
          ("GRID",(0,0),(-1,-1),0.4,LINE),("ALIGN",(1,0),(1,-1),"CENTER"),
          ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,PALE]),("TOPPADDING",(0,0),(-1,-1),6),
          ("BOTTOMPADDING",(0,0),(-1,-1),6)]
    for i, row in enumerate(sev_rows[1:], start=1):
        color = SEVERITY.get(row[0], MUTED)
        ts.append(("TEXTCOLOR",(0,i),(0,i),color))
        ts.append(("FONTNAME",(0,i),(0,i),"Helvetica-Bold"))
    sev_table.setStyle(TableStyle(ts))
    story += [sev_table, Spacer(1, 8)]
    high_critical = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
    story.append(Paragraph(
        f"<b>Priority indicator:</b> {high_critical} finding(s) are marked Critical or High "
        "in the input. These should be triaged first, with exploitability and business impact "
        "confirmed during technical validation.", styles["body"]))
    story.append(Paragraph("Severity distribution", styles["h2"]))
    # Compact visual bar chart made from a table (portable in PDF viewers).
    bar_cells = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = counts.get(sev, 0) + (counts.get("INFORMATIONAL", 0) if sev == "INFO" else 0)
        if c:
            bar_cells.append(Paragraph(f"<b>{sev}</b><br/>{c}", ParagraphStyle(
                "bar"+sev, parent=styles["small"], alignment=TA_CENTER, textColor=SEVERITY.get(sev,MUTED))))
    if bar_cells:
        bar = Table([bar_cells], colWidths=[doc.width/len(bar_cells)]*len(bar_cells))
        bar.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),PALE),("BOX",(0,0),(-1,-1),0.5,LINE),
                                 ("INNERGRID",(0,0),(-1,-1),0.5,LINE),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                                 ("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8)]))
        story.append(bar)

    story += [Spacer(1, 8), Paragraph("Report interpretation", styles["h2"]),
              Paragraph("The findings are presented as supplied by the upstream analysis pipeline. "
                        "A finding is not proof of a working exploit by itself. Confirm the affected "
                        "asset, reachable attack path, preconditions, reproducibility, and business "
                        "impact before treating a finding as a verified vulnerability.", styles["body"]),
              PageBreak()]

    # Methodology and data notes
    story.append(Paragraph("02 | Scope, Method & Data Notes", styles["h1"]))
    notes = [
        ("Input source", source_name),
        ("Records processed", str(total)),
        ("Declared total_findings", clean(metadata.get("total_findings"), "Not present")),
        ("Processing date", generated),
        ("Normalization", "Common JSON finding containers are supported; absent fields are shown as Not provided."),
    ]
    nt = Table([[Paragraph(f"<b>{esc(k)}</b>", styles["small"]), Paragraph(esc(v), styles["body"])]
                for k,v in notes], colWidths=[43*mm, 115*mm])
    nt.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),PALE),("GRID",(0,0),(-1,-1),0.35,LINE),
                            ("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),7),
                            ("RIGHTPADDING",(0,0),(-1,-1),7),("TOPPADDING",(0,0),(-1,-1),6),
                            ("BOTTOMPADDING",(0,0),(-1,-1),6)]))
    story += [nt, Spacer(1, 10),
              Paragraph("Validation caveat", styles["h2"]),
              Paragraph("This PDF generator formats and organizes supplied data. It does not scan "
                        "the target, execute proof-of-concept payloads, verify source-code context, "
                        "deduplicate findings, calculate CVSS, or confirm OWASP/CWE mappings. "
                        "AI-generated descriptions may contain assumptions or false positives. "
                        "Review each issue manually and record validation evidence before external "
                        "distribution.", styles["body"]),
              Paragraph("Suggested validation workflow", styles["h2"]),
              Paragraph("1. Confirm the asset and affected component.<br/>"
                        "2. Reproduce safely in an authorized test environment.<br/>"
                        "3. Verify exploit preconditions and practical impact.<br/>"
                        "4. Remove duplicates and correlate related findings.<br/>"
                        "5. Agree remediation, owner, and retest criteria.", styles["body"]),
              PageBreak()]

    # Findings index
    story.append(Paragraph("03 | Findings Register", styles["h1"]))
    index_rows = [["ID", "FINDING", "SEVERITY", "CWE"]]
    for i, f in enumerate(findings, 1):
        fid = clean(f.get("id"), f"F-{i:03d}")
        title = clean(f.get("finding_type") or f.get("title") or f.get("vulnerability"), "Untitled finding")
        sev = normalize_severity(f.get("severity"))
        cwe = clean(f.get("cwe_id"), "—")
        index_rows.append([Paragraph(esc(fid), styles["small"]),
                           Paragraph(esc(title), styles["small"]),
                           Paragraph(f"<b>{esc(sev)}</b>", styles["small"]),
                           Paragraph(esc(cwe), styles["small"])])
    idx = Table(index_rows, colWidths=[23*mm, 83*mm, 27*mm, 25*mm], repeatRows=1)
    idx_style = [("BACKGROUND",(0,0),(-1,0),NAVY),("TEXTCOLOR",(0,0),(-1,0),WHITE),
                 ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("GRID",(0,0),(-1,-1),0.35,LINE),
                 ("VALIGN",(0,0),(-1,-1),"TOP"),("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,PALE]),
                 ("LEFTPADDING",(0,0),(-1,-1),5),("RIGHTPADDING",(0,0),(-1,-1),5),
                 ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5)]
    for r in range(1, len(index_rows)):
        sev = normalize_severity(findings[r-1].get("severity"))
        idx_style.append(("TEXTCOLOR",(2,r),(2,r),SEVERITY.get(sev,MUTED)))
    idx.setStyle(TableStyle(idx_style))
    story += [idx, PageBreak()]

    # Individual detailed findings
    story.append(Paragraph("04 | Detailed Findings", styles["h1"]))
    for i, f in enumerate(findings, 1):
        fid = clean(f.get("id"), f"F-{i:03d}")
        title = clean(f.get("finding_type") or f.get("title") or f.get("vulnerability"), "Untitled finding")
        sev = normalize_severity(f.get("severity"))
        badge = Table([[Paragraph(f"<b>{esc(sev)}</b>", styles["white_small"])]], colWidths=[27*mm])
        badge.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),SEVERITY.get(sev,MUTED)),
                                   ("LEFTPADDING",(0,0),(-1,-1),6),("RIGHTPADDING",(0,0),(-1,-1),6),
                                   ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4)]))
        story.append(KeepTogether([
            Paragraph(f"{i:02d}. {esc(title)}", styles["finding_title"]),
            badge, Spacer(1, 5)
        ]))
        meta = [
            ("Finding ID", fid), ("Severity", sev),
            ("CWE", clean(f.get("cwe_id"), "Not mapped")),
            ("OWASP", clean(f.get("owasp_category"), "Not mapped")),
            ("Source file", clean(f.get("source_file"))),
            ("Line", clean(f.get("line_number"))),
            ("Function", clean(f.get("function_name"))),
            ("Chunk", clean(f.get("chunk_id") or f.get("chunk_file"))),
        ]
        meta = [(k,v) for k,v in meta if v != "Not provided"]
        rows = []
        for j in range(0, len(meta), 2):
            left = meta[j]
            right = meta[j+1] if j+1 < len(meta) else ("", "")
            rows.append([Paragraph(f"<b>{esc(left[0])}</b><br/>{esc(left[1])}", styles["small"]),
                         Paragraph(f"<b>{esc(right[0])}</b><br/>{esc(right[1])}" if right[0] else "", styles["small"])])
        mt = Table(rows, colWidths=[doc.width/2]*2)
        mt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),PALE),("GRID",(0,0),(-1,-1),0.3,LINE),
                                ("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),6),
                                ("RIGHTPADDING",(0,0),(-1,-1),6),("TOPPADDING",(0,0),(-1,-1),5),
                                ("BOTTOMPADDING",(0,0),(-1,-1),5)]))
        story.append(mt)
        for key, label, is_code in [
            ("impact_description", "Impact", False),
            ("proof_of_concept", "Proof of Concept / Evidence (as supplied)", False),
            ("code_vulnerable", "Vulnerable Code / Location", True),
            ("code_remediation", "Recommended Remediation (as supplied)", False),
        ]:
            if f.get(key) not in (None, ""):
                field(story, label, f[key], styles, code=is_code)
        # Include additional upstream fields rather than silently dropping unknown schema data.
        known = {"id","finding_type","title","vulnerability","severity","cwe_id","owasp_category",
                 "source_file","line_number","function_name","chunk_id","chunk_file",
                 "impact_description","proof_of_concept","code_vulnerable","code_remediation"}
        extras = [(k,v) for k,v in f.items() if k not in known and v not in (None, "")]
        if extras:
            story.append(Paragraph("ADDITIONAL INPUT FIELDS", styles["label"]))
            for k,v in extras:
                story.append(Paragraph(f"<b>{esc(k)}:</b> {esc(v)}", styles["small"]))
        story.append(Spacer(1, 10))
        if i < total:
            story.append(HRFlowable(width="100%", thickness=0.5, color=LINE, spaceBefore=2, spaceAfter=8))

    story += [Spacer(1, 8), Paragraph("05 | Closing Note", styles["h1"]),
              Paragraph("Prioritize remediation according to validated risk, exposure, exploitability, "
                        "and business criticality. After fixes are deployed, perform targeted retesting "
                        "and retain evidence of closure. Severity labels in this report reflect the "
                        "input data and should be revisited if validation changes the risk assessment.",
                        styles["body"])]
    doc.build(story)


def main():
    parser = argparse.ArgumentParser(description="Convert AI security findings JSON/ZIP into a polished PDF report.")
    parser.add_argument("input", help="Path to a .json or .zip file")
    parser.add_argument("-o", "--output", help="Output PDF path (default: <input>_security_report.pdf)")
    parser.add_argument("--json-member", help="Exact JSON path inside ZIP when archive contains multiple JSON files")
    args = parser.parse_args()

    source = Path(args.input)
    if not source.exists():
        parser.error(f"Input file not found: {source}")
    out = Path(args.output) if args.output else source.with_name(source.stem + "_security_report.pdf")
    try:
        obj, source_name = load_input(source, args.json_member)
        findings, metadata = find_findings(obj)
        build_report(findings, metadata, source_name, out)
        print(f"[+] PDF report created: {out.resolve()}")
        print(f"[+] Findings processed: {len(findings)}")
    except (ValueError, OSError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
