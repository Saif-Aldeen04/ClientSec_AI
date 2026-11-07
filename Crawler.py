#!/usr/bin/env python3
"""Minimal terminal crawler wrapper.

Usage:
    python main.py --url https://example.com --confirm-authorized --depth 2 --max-pages 50
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / "clientsec-crawler" / ".venv"
if sys.platform.startswith("win"):
    VENV_PYTHON = VENV_DIR / "Scripts" / "python.exe"
else:
    VENV_PYTHON = VENV_DIR / "bin" / "python"

if VENV_PYTHON.exists() and Path(sys.prefix).resolve() != VENV_DIR.resolve():
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), str(Path(__file__).resolve()), *sys.argv[1:]])

SRC = ROOT / "clientsec-crawler" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:
    from clientsec_crawler import CrawlConfig, crawl_sync
except ImportError:
    raise SystemExit(
        "Could not import clientsec_crawler.\n"
        "Make sure the project is available in the workspace or installed in the active venv."
    )


def extract_js_data(result: dict) -> list[dict]:
    deduped: dict[tuple[str, str], dict] = {}

    def add_record(key: tuple[str, str], record: dict) -> None:
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = record
            return

        pages = set(existing.get("pages", []))
        for page in record.get("pages", []):
            pages.add(page)
        existing["pages"] = sorted(pages)
        if not existing.get("page") and record.get("page"):
            existing["page"] = record["page"]

    for page in result.get("endpoints", []):
        page_url = page.get("url")
        if not page_url:
            continue
        for script in page.get("inline_scripts", []) or []:
            if not isinstance(script, str) or not script.strip():
                continue
            script_preview = script[:300]
            key = ("inline", f"{page_url}|{script_preview}")
            add_record(
                key,
                {
                    "page": page_url,
                    "pages": [page_url],
                    "type": "inline",
                    "url": None,
                    "script_preview": script_preview,
                },
            )

    for asset in result.get("assets", []):
        asset_type = (asset.get("type") or "").lower()
        if "javascript" not in asset_type and "script" not in asset_type:
            continue
        url = asset.get("url")
        if not url:
            continue
        pages = list(dict.fromkeys(asset.get("referenced_by") or []))
        if not pages:
            pages = [asset.get("page")]
        add_record(
            ("external", url),
            {
                "page": pages[0] if pages else None,
                "pages": pages,
                "type": "external",
                "url": url,
                "script_preview": None,
                "fetch_status": asset.get("fetch_status"),
            },
        )

    return list(deduped.values())


def write_output(output_path: str | Path, rows: list[dict]) -> Path:
    path = Path(output_path)
    if not path.is_absolute():
        path = ROOT / path

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def build_parser() -> argparse.ArgumentParser:
    default_output = ROOT / "Output" / "crawler_result.json"
    parser = argparse.ArgumentParser(
        description="Run the project crawler from the terminal and export JavaScript references as JSON."
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Required confirmation that you are authorized to assess this target",
    )
    parser.add_argument("--depth", type=int, help="Crawl depth (default: full crawl)")
    parser.add_argument(
        "--max-pages",
        type=int,
        help="Maximum pages to crawl (default: full crawl)",
    )
    parser.add_argument(
        "--output",
        default=str(default_output),
        help="Output JSON file (default: Output/crawler_result.json)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.confirm_authorized:
        parser.error("--confirm-authorized is required")

    depth = args.depth if args.depth is not None else 10
    max_pages = args.max_pages if args.max_pages is not None else 1000

    config = CrawlConfig(
        max_depth=depth,
        max_pages=max_pages,
        max_concurrency=5,
        request_timeout=10,
        fetch_js=True,
        fetch_css=True,
    )

    result = crawl_sync(args.url, config)
    js_rows = extract_js_data(result)

    output_path = write_output(args.output, js_rows)

    print(f"crawl_status: {result.get('crawl_status')}")
    print(f"pages_fetched: {result.get('summary', {}).get('pages_fetched')}")
    print(f"js_found_unique: {len(js_rows)}")
    print(f"saved_to: {output_path.resolve()}")

    return 0 if result.get("crawl_status") != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())