"""JSON serialization of crawl results."""

from __future__ import annotations

import html as _html
import json
import re
from pathlib import Path


def to_json(result: dict, *, indent: int | None = 2) -> str:
    """Serialize a crawl result to a JSON string (UTF-8 safe)."""
    return json.dumps(result, indent=indent, ensure_ascii=False)


def write_json(result: dict, path: str | Path, *, indent: int | None = 2) -> Path:
    """Write the result as UTF-8 JSON to a caller-chosen path (nothing is written by default)."""
    target = Path(path)
    target.write_text(to_json(result, indent=indent), encoding="utf-8")
    return target


# ---------------------------------------------------------------------------------------------
# Extraction helpers: write what was collected as real files, or as lighter-weight exports.


def _slug(text: str, limit: int = 48) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._-")
    return (cleaned or "item")[:limit]


def without_contents(result: dict) -> dict:
    """Copy of the result with raw HTML/JS/CSS removed (sizes are kept) - small summary export."""
    out = json.loads(json.dumps(result))
    for endpoint in out["endpoints"]:
        endpoint["html_chars"] = len(endpoint["html"]) if endpoint["html"] is not None else None
        endpoint["html"] = None
        for block in endpoint["inline_scripts"] + endpoint["inline_styles"]:
            block["content"] = None
    for asset in out["assets"]:
        asset["content"] = None
    out["contents_omitted"] = True
    return out


def url_list(result: dict) -> str:
    """Plain text: one line per discovered page, asset and out-of-scope URL."""
    lines = [f"PAGE\t{e['url']}" for e in result["endpoints"]]
    lines += [f"{a['type'].upper()}\t{a['url']}" for a in result["assets"]]
    lines += [f"OUT-OF-SCOPE\t{o['url']}" for o in result["out_of_scope"]]
    return "\n".join(lines) + "\n"


def export_folder(result: dict, directory: str | Path) -> dict:
    """Write everything collected as files under ``directory`` and return the manifest.

    Layout: ``pages/*.html``, ``js/*.js``, ``css/*.css``, ``inline/*``, ``result.json`` (full
    result) and ``manifest.json`` (maps each file to its source URL). File names are sanitized
    and prefixed with an index/asset id, so hostile URLs cannot escape ``directory``.
    """
    root = Path(directory).resolve()
    files: list[dict] = []

    def write(rel: str, text: str, source: str, kind: str) -> None:
        path = (root / rel).resolve()
        if root not in path.parents:  # defence in depth; names are already sanitized
            raise ValueError(f"refusing to write outside {root}: {rel}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="")
        files.append({"file": rel.replace("\\", "/"), "kind": kind, "source": source})

    for i, e in enumerate(result["endpoints"], 1):
        label = _slug(e["url"].split("://", 1)[-1])
        if e["html"] is not None:
            write(f"pages/{i:03d}-{label}.html", e["html"], e["url"], "page")
        for kind, blocks, default_ext in (
            ("inline_script", e["inline_scripts"], ".js"),
            ("inline_style", e["inline_styles"], ".css"),
        ):
            for b in blocks:
                ext = ".json" if "json" in b["attributes"].get("type", "") else default_ext
                write(
                    f"inline/{i:03d}-{label}-{kind}-{b['index']}{ext}", b["content"], e["url"], kind
                )
    for a in result["assets"]:
        if a["content"] is None:
            continue
        folder = "js" if a["type"] == "javascript" else "css"
        name = _slug(a["url"].rsplit("/", 1)[-1].split("?")[0] or "asset")
        write(f"{folder}/{a['asset_id']}-{name}", a["content"], a["url"], a["type"])
    write("result.json", to_json(result), result["target"], "full_result")
    manifest = {"target": result["target"], "crawl_status": result["crawl_status"], "files": files}
    (root / "manifest.json").write_text(to_json(manifest), encoding="utf-8")
    return manifest


def html_report(result: dict) -> str:
    """Self-contained HTML report (no raw page content). Every value is HTML-escaped."""
    esc = lambda value: _html.escape("" if value is None else str(value), quote=True)  # noqa: E731
    s = result["summary"]
    cards = "".join(
        '<div class="card">'
        f'<div class="k">{esc(k.replace("_", " "))}</div><div class="v">{esc(v)}</div></div>'
        for k, v in s.items()
    )

    def table(headers, rows):
        head = "".join(f"<th>{esc(h)}</th>" for h in headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{esc(c)}</td>" for c in row) + "</tr>" for row in rows
        )
        return f"<table><tr>{head}</tr>{body}</table>"

    pages = table(
        ["URL", "HTTP", "Depth", "Title", "Fetch status"],
        [
            (e["url"], e["status_code"], e["depth"], e["title"], e["fetch_status"])
            for e in result["endpoints"]
        ],
    )
    assets = table(
        ["URL", "Type", "State", "Bytes", "Used by pages"],
        [
            (
                a["url"],
                a["type"],
                a["fetch_status"] + (f" ({a['skip_reason']})" if a["skip_reason"] else ""),
                a["size_bytes"],
                len(a["referenced_by"]),
            )
            for a in result["assets"]
        ],
    )
    inline = table(
        ["Page", "Inline scripts", "Inline styles"],
        [
            (e["url"], len(e["inline_scripts"]), len(e["inline_styles"]))
            for e in result["endpoints"]
        ],
    )
    issues = table(
        ["Type", "URL", "Code / reason", "Detail"],
        [("error", x["url"], x["code"], x["message"]) for x in result["errors"]]
        + [
            ("out of scope", o["url"], o["reason"], "not requested") for o in result["out_of_scope"]
        ],
    )
    notes = "".join(f"<li>{esc(x)}</li>" for x in result["limitations"])
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f"<title>Crawl report - {esc(result['target'])}</title><style>"
        "body{font:14px system-ui,sans-serif;margin:2rem;background:#0e1620;color:#e6edf3}"
        "h1{color:#4cd7a6}h2{margin-top:2rem;color:#4aa3ff}table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #26364a;padding:4px 8px;text-align:left;word-break:break-all}"
        "th{background:#1b2937}.cards{display:flex;gap:.6rem;flex-wrap:wrap}"
        ".card{background:#15202b;border:1px solid #26364a;padding:.6rem 1rem;min-width:8rem}"
        ".k{color:#8b9bab;font-size:11px;text-transform:uppercase}.v{font-size:24px;color:#4cd7a6}"
        "</style></head><body>"
        f"<h1>Crawl report</h1><p>Target: <code>{esc(result['target'])}</code> &middot; status: "
        f"<b>{esc(result['crawl_status'])}</b> &middot; {esc(result['started_at'])} "
        f"&middot; {esc(result['duration_seconds'])} s &middot; limits reached: "
        f"{esc(', '.join(result['limits_reached']) or 'none')}</p>"
        f'<div class="cards">{cards}</div><h2>Pages</h2>{pages}<h2>Assets</h2>{assets}'
        f"<h2>Inline code</h2>{inline}<h2>Errors and out-of-scope URLs</h2>{issues}"
        f"<h2>Limitations</h2><ul>{notes}</ul>"
        "<p><small>Raw page and asset content is in the JSON export or the extracted files."
        "</small></p>"
        "</body></html>"
    )
