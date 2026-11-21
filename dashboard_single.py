#!/usr/bin/env python3
"""Single-file Streamlit dashboard for Output/Final_JSON.json."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).resolve().parent
REPORT_PATH = ROOT / "Output" / "Final_JSON.json"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
SEVERITY_COLORS = {
    "CRITICAL": "#ff4d6d",
    "HIGH": "#ff8c42",
    "MEDIUM": "#ffd23f",
    "LOW": "#4cc9f0",
    "INFO": "#8d99ae",
    "UNKNOWN": "#6b7280",
}
SEVERITY_ICONS = {
    "CRITICAL": "[CRIT]",
    "HIGH": "[HIGH]",
    "MEDIUM": "[MED]",
    "LOW": "[LOW]",
    "INFO": "[INFO]",
    "UNKNOWN": "[UNK]",
}
SEVERITY_ALIASES = {"CRIT": "CRITICAL", "MODERATE": "MEDIUM", "INFORMATIONAL": "INFO", "WARNING": "MEDIUM"}

CSS = """
<style>
.block-container{padding-top:1.2rem;max-width:1400px}
[data-testid="stSidebar"]{border-right:1px solid #1f2a44}
.cs-brand{font-size:1.2rem;font-weight:700;color:#e6edf7}
.cs-brand span{color:#22d3ee}
.cs-tag{font-size:.72rem;color:#8b98b8;letter-spacing:.08em;text-transform:uppercase;margin-bottom:.8rem}
.cs-card{background:linear-gradient(145deg,#111a2b,#0d1524);border:1px solid #1f2a44;border-left:4px solid var(--c);border-radius:12px;padding:14px 18px;height:100%}
.cs-label{font-size:.7rem;letter-spacing:.1em;text-transform:uppercase;color:#8b98b8;font-weight:600}
.cs-value{font-size:2rem;font-weight:800;color:var(--c);line-height:1.15}
.cs-sub{font-size:.72rem;color:#8b98b8;margin-top:2px}
.cs-chip{display:inline-block;padding:2px 10px;border-radius:6px;background:#162036;border:1px solid #1f2a44;font-size:.78rem;color:#c9d4ea;margin:0 6px 6px 0}
.cs-chip b{color:#8b98b8;font-weight:600;margin-right:4px}
.cs-box{border:1px solid #1f2a44;border-left:3px solid var(--c);border-radius:8px;padding:10px 14px;margin:8px 0}
.cs-box-title{font-size:.72rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;margin-bottom:4px}
.cs-box-body{font-size:.92rem;line-height:1.55;color:#dbe4f5}
.cs-file{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85rem;color:#22d3ee;margin:6px 0}
</style>
"""


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    cwe: str
    owasp: str
    line: str
    poc: str
    code_vulnerable: str
    code_fix: str
    impact: str
    function: str
    source_file: str
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def file_name(self) -> str:
        if not self.source_file:
            return ""
        return Path(self.source_file).name


@dataclass
class Report:
    findings: list[Finding]
    meta: dict[str, Any]
    raw: dict[str, Any]

    def severity_counts(self) -> dict[str, int]:
        counter = Counter(f.severity for f in self.findings)
        return {sev: counter[sev] for sev in SEVERITY_ORDER if counter.get(sev)}


def _txt(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value).strip()


def _severity(value: Any) -> str:
    sev = _txt(value).upper()
    sev = SEVERITY_ALIASES.get(sev, sev)
    return sev if sev in SEVERITY_ORDER else "UNKNOWN"


def load_report(path: Path = REPORT_PATH) -> Report:
    if not path.exists():
        raise FileNotFoundError(f"Missing report file: {path}")

    content = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(content, dict):
        raise ValueError("Final_JSON.json must be a JSON object.")

    findings_raw = content.get("findings", [])
    if not isinstance(findings_raw, list):
        raise ValueError("Final_JSON.json must contain a 'findings' array.")

    findings: list[Finding] = []
    for item in findings_raw:
        if not isinstance(item, dict):
            continue
        findings.append(
            Finding(
                id=_txt(item.get("id")),
                title=_txt(item.get("finding_type") or item.get("title") or "Untitled finding"),
                severity=_severity(item.get("severity")),
                cwe=_txt(item.get("cwe_id") or item.get("cwe")),
                owasp=_txt(item.get("owasp_category") or item.get("owasp")),
                line=_txt(item.get("line_number") or item.get("line")),
                poc=_txt(item.get("proof_of_concept") or item.get("poc")),
                code_vulnerable=_txt(item.get("code_vulnerable") or item.get("vulnerable_code")),
                code_fix=_txt(item.get("code_remediation") or item.get("remediation") or item.get("fix")),
                impact=_txt(item.get("impact_description") or item.get("impact")),
                function=_txt(item.get("function_name") or item.get("function")),
                source_file=_txt(item.get("source_file") or item.get("file") or item.get("path")),
                raw=item,
            )
        )

    if not findings:
        raise ValueError("No findings were found in Final_JSON.json")

    meta = {k: v for k, v in content.items() if k != "findings"}
    return Report(findings=findings, meta=meta, raw=content)


def metric_card(label: str, value: Any, color: str, sub: str = "") -> str:
    sub_html = f'<div class="cs-sub">{sub}</div>' if sub else ""
    return (
        f'<div class="cs-card" style="--c:{color}">'
        f'<div class="cs-label">{label}</div>'
        f'<div class="cs-value">{value}</div>'
        f"{sub_html}"
        "</div>"
    )


def text_box(title: str, body: str, color: str) -> str:
    safe = body.replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")
    return (
        f'<div class="cs-box" style="--c:{color};background:{color}18">'
        f'<div class="cs-box-title" style="color:{color}">{title}</div>'
        f'<div class="cs-box-body">{safe}</div>'
        "</div>"
    )


def severity_donut(counts: dict[str, int]) -> go.Figure:
    labels = list(counts)
    fig = go.Figure(
        go.Pie(
            labels=labels,
            values=[counts[s] for s in labels],
            hole=0.62,
            sort=False,
            marker=dict(colors=[SEVERITY_COLORS[s] for s in labels], line=dict(color="#0a0f1c", width=3)),
            textinfo="value",
            hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
        )
    )
    fig.add_annotation(text=f"<b>{sum(counts.values())}</b><br><span style='font-size:11px'>findings</span>", showarrow=False)
    fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=330)
    return fig


def stacked_bar(report: Report, getter: Callable[[Finding], str], title: str, top: int = 10) -> go.Figure:
    table: dict[str, Counter] = defaultdict(Counter)
    for f in report.findings:
        key = getter(f)
        if key:
            table[key][f.severity] += 1

    keys = sorted(table, key=lambda k: sum(table[k].values()))[-top:]
    fig = go.Figure()
    for sev in SEVERITY_ORDER:
        vals = [table[k][sev] for k in keys]
        if any(vals):
            fig.add_bar(y=keys, x=vals, name=sev, orientation="h", marker_color=SEVERITY_COLORS[sev])
    fig.update_layout(
        barmode="stack",
        title=title,
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=max(250, 60 + 35 * len(keys)),
    )
    fig.update_xaxes(dtick=1)
    return fig


def to_table(report: Report) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "ID": f.id,
                "Severity": f.severity,
                "Title": f.title,
                "CWE": f.cwe,
                "OWASP": f.owasp,
                "File": f.source_file,
                "Function": f.function,
                "Line": f.line,
                "Impact": f.impact,
                "Proof of concept": f.poc,
                "Vulnerable code": f.code_vulnerable,
                "Remediation": f.code_fix,
            }
            for f in report.findings
        ]
    )


def render_overview(report: Report) -> None:
    st.markdown("## Security Analysis Overview")
    counts = report.severity_counts()
    fs = report.findings

    cards = [("Total findings", len(fs), "#22d3ee", "")]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"):
        if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") or counts.get(sev):
            n = counts.get(sev, 0)
            pct = f"{(n / len(fs)):.0%} of total" if fs else ""
            cards.append((sev.title(), n, SEVERITY_COLORS[sev], pct))

    for col, (label, value, color, sub) in zip(st.columns(len(cards)), cards):
        col.markdown(metric_card(label, value, color, sub), unsafe_allow_html=True)

    st.write("")
    c1, c2 = st.columns([1, 1.4])
    c1.plotly_chart(severity_donut(counts), width='stretch')
    c2.plotly_chart(stacked_bar(report, lambda f: f.owasp, "Findings by OWASP category"), width='stretch')

    c3, c4 = st.columns(2)
    c3.plotly_chart(stacked_bar(report, lambda f: f.file_name, "Findings by file"), width='stretch')
    c4.plotly_chart(stacked_bar(report, lambda f: f.cwe, "Findings by CWE"), width='stretch')


def render_vulnerabilities(report: Report) -> None:
    st.markdown("## Vulnerability Details")
    fs = report.findings
    present = [s for s in SEVERITY_ORDER if any(f.severity == s for f in fs)]

    c1, c2 = st.columns([2, 3])
    query = c1.text_input("Search by ID or title", placeholder="e.g. OWASP-003")
    selected = c2.multiselect("Severity", present, default=present)

    c3, c4 = st.columns(2)
    files = c3.multiselect("File", sorted({f.file_name for f in fs if f.file_name}))
    owasp = c4.multiselect("OWASP category", sorted({f.owasp for f in fs if f.owasp}))

    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    shown = [
        f
        for f in fs
        if f.severity in selected
        and (not query or query.lower() in f.id.lower() or query.lower() in f.title.lower())
        and (not files or f.file_name in files)
        and (not owasp or f.owasp in owasp)
    ]
    shown.sort(key=lambda f: (rank[f.severity], f.id))

    st.caption(f"Showing {len(shown)} of {len(fs)} findings")
    for f in shown:
        label = f"{SEVERITY_ICONS[f.severity]} {f.id or '-'} | {f.title}"
        with st.expander(label, expanded=False):
            parts = []
            for key, value in [("CWE", f.cwe), ("OWASP", f.owasp), ("Function", f.function), ("Line", f.line), ("File", f.file_name)]:
                if value:
                    parts.append(f'<span class="cs-chip"><b>{key}</b> {value}</span>')
            if parts:
                st.markdown("".join(parts), unsafe_allow_html=True)
            if f.source_file:
                st.markdown(f'<div class="cs-file">{f.source_file.replace("<", "&lt;")}</div>', unsafe_allow_html=True)
            if f.impact:
                st.markdown(text_box("Impact", f.impact, "#ff8c42"), unsafe_allow_html=True)
            if f.poc:
                st.markdown(text_box("Proof of concept", f.poc, "#7c8cff"), unsafe_allow_html=True)
            if f.code_vulnerable:
                st.markdown("### Vulnerable code")
                st.code(f.code_vulnerable, wrap_lines=True)
            if f.code_fix:
                st.markdown(text_box("Recommended remediation", f.code_fix, "#3fb950"), unsafe_allow_html=True)


def render_locations(report: Report) -> None:
    st.markdown("## Code Locations")
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in report.findings:
        by_file[f.source_file or "(unknown)"] .append(f)

    rows = []
    for path, items in by_file.items():
        row = {"File": path, "Findings": len(items), "Functions": ", ".join(sorted({i.function for i in items if i.function}))}
        for sev in SEVERITY_ORDER:
            if any(i.severity == sev for i in report.findings):
                row[sev.title()] = sum(1 for i in items if i.severity == sev)
        rows.append(row)
    rows.sort(key=lambda r: -r["Findings"])
    st.dataframe(rows, width='stretch', hide_index=True)


def render_raw(report: Report) -> None:
    st.markdown("## Data Explorer")
    df = to_table(report)
    t1, t2 = st.tabs(["Table", "Raw JSON"])
    with t1:
        st.dataframe(df, width='stretch', hide_index=True)
        st.download_button("Download CSV", df.to_csv(index=False).encode("utf-8-sig"), "clientsec_findings.csv", "text/csv")
    with t2:
        st.json(report.raw, expanded=1)
        st.download_button(
            "Download JSON",
            json.dumps(report.raw, indent=2, ensure_ascii=False).encode("utf-8"),
            "clientsec_report.json",
            "application/json",
        )


def main() -> None:
    st.set_page_config(page_title="ClientSec AI", page_icon="shield", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)

    with st.sidebar:
        st.markdown('<div class="cs-brand">Client<span>Sec</span> AI</div><div class="cs-tag">Local report dashboard</div>', unsafe_allow_html=True)
        st.caption(f"JSON source: {REPORT_PATH}")

    try:
        report = load_report(REPORT_PATH)
    except Exception as exc:
        st.error(f"Failed to load report: {exc}")
        st.info("Run the scan first to generate Output/Final_JSON.json, then refresh the page.")
        st.stop()

    pages: dict[str, Callable[[Report], None]] = {
        "Overview": render_overview,
        "Vulnerabilities": render_vulnerabilities,
        "Code Locations": render_locations,
        "Data Explorer": render_raw,
    }

    with st.sidebar:
        page = st.radio("Navigation", list(pages), label_visibility="collapsed")
        st.divider()
        st.caption(f"Findings loaded: {len(report.findings)}")

    pages[page](report)


if __name__ == "__main__":
    main()
