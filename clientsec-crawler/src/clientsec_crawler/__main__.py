"""Command line entry point.

    python -m clientsec_crawler --url http://127.0.0.1:8000/ --confirm-authorized ...

A readable summary is printed to the terminal; the full structured result (which contains the
raw HTML/JS/CSS) is saved to a JSON file, by default ``crawl_output/crawl_result.json``.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .config import CrawlConfig
from .crawler import crawl_sync
from .exporter import export_folder, html_report, to_json, write_json

DEFAULT_OUTPUT = Path("crawl_output") / "crawl_result.json"
_MAX_LISTED = 25


def format_summary(result: dict, output_path: Path | None) -> str:
    """Human-readable summary. Never includes page or asset contents."""
    s = result["summary"]
    lines = [
        f"Target:        {result['target']}",
        f"Status:        {result['crawl_status']}"
        + (
            f"  (limits reached: {', '.join(result['limits_reached'])})"
            if result["limits_reached"]
            else ""
        ),
        f"Pages:         {s['pages_fetched']} fetched, {s['pages_failed']} failed, "
        f"{s['pages_discovered']} discovered",
        f"Assets:        {s['assets_fetched']} fetched, {s['assets_skipped']} skipped, "
        f"{s['assets_discovered']} discovered",
        f"Out of scope:  {s['out_of_scope_urls']} URLs (recorded, not fetched)",
        f"Errors:        {s['errors_count']}",
        f"Duration:      {result['duration_seconds']}s",
    ]

    def section(title: str, rows: list[str]) -> None:
        if rows:
            lines.append("")
            lines.append(title)
            lines.extend(f"  {row}" for row in rows[:_MAX_LISTED])
            if len(rows) > _MAX_LISTED:
                lines.append(f"  ... and {len(rows) - _MAX_LISTED} more (see JSON)")

    section(
        "Pages:",
        [
            f"[{e['fetch_status']}] depth={e['depth']} status={e['status_code']} {e['url']}"
            + (f"  title={e['title']!r}" if e["title"] else "")
            for e in result["endpoints"]
        ],
    )
    section(
        "Assets:",
        [
            f"[{a['fetch_status']}] {a['type']} {a['url']}"
            + (f"  ({a['size_bytes']} bytes)" if a["size_bytes"] is not None else "")
            + (f"  skipped: {a['skip_reason']}" if a["skip_reason"] else "")
            + f"  referenced_by={len(a['referenced_by'])} page(s)"
            for a in result["assets"]
        ],
    )
    section(
        "Out-of-scope URLs (not crawled):",
        [f"{o['url']}  ({o['reason']})" for o in result["out_of_scope"]],
    )
    section(
        "Errors:",
        [f"{e['code']}  {e['operation']}  {e['url']}  {e['message']}" for e in result["errors"]],
    )
    lines.append("")
    lines.append(
        f"Full JSON output: {output_path.resolve()}" if output_path else "Full JSON output: stdout"
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m clientsec_crawler",
        description=(
            "Passive same-origin crawler. Only use on targets you are authorized to assess."
        ),
    )
    p.add_argument("--url", dest="url", help="target URL (http or https)")
    p.add_argument("target", nargs="?", help="target URL (same as --url)")
    p.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="required: confirms you are authorized to assess the target",
    )
    p.add_argument("--max-pages", type=int, default=CrawlConfig.max_pages)
    p.add_argument("--max-depth", type=int, default=CrawlConfig.max_depth)
    p.add_argument("--concurrency", type=int, default=CrawlConfig.max_concurrency)
    p.add_argument(
        "--timeout", type=float, default=CrawlConfig.request_timeout, help="seconds per request"
    )
    p.add_argument("--max-response-bytes", type=int, default=CrawlConfig.max_response_bytes)
    p.add_argument("--max-asset-bytes", type=int, default=CrawlConfig.max_asset_bytes)
    p.add_argument("--delay", type=float, default=0.0, help="minimum seconds between requests")
    p.add_argument("--allow-host", action="append", default=[], help="extra in-scope hostname")
    p.add_argument(
        "--allow-asset-origin",
        action="append",
        default=[],
        help="origin allowed for cross-origin asset downloads",
    )
    p.add_argument("--no-assets", action="store_true", help="record assets but do not download")
    p.add_argument("--no-js", action="store_true", help="do not download JavaScript assets")
    p.add_argument("--no-css", action="store_true", help="do not download CSS assets")
    p.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="REGEX",
        help="only follow page links whose path?query matches (repeatable)",
    )
    p.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="REGEX",
        help="skip page links whose path?query matches (repeatable)",
    )
    p.add_argument(
        "--html-report",
        metavar="FILE",
        help="also write a self-contained HTML report",
    )
    p.add_argument(
        "--export-dir",
        metavar="DIR",
        help="also write pages/js/css/inline files + manifest.json to this folder",
    )
    p.add_argument(
        "--unsafe-allow-private-networks",
        action="store_true",
        help="TEST ONLY: allow loopback/private destinations (local fixtures)",
    )
    p.add_argument(
        "-o",
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"JSON output file (default: {DEFAULT_OUTPUT})",
    )
    p.add_argument(
        "--stdout-json",
        action="store_true",
        help="print the full JSON to stdout instead of saving a file",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="log progress to stderr")
    return p


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)

    url = args.url or args.target
    if args.url and args.target and args.url != args.target:
        p.error("give the target once: --url URL")
    if not url:
        p.error("a target is required: --url URL")
    if not args.confirm_authorized:
        p.error("refusing to run without --confirm-authorized (only crawl targets you may assess)")
    if args.verbose:
        # Only our own logger: root-level INFO would also enable third-party request logging.
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        pkg_logger = logging.getLogger("clientsec_crawler")
        pkg_logger.addHandler(handler)
        pkg_logger.setLevel(logging.INFO)
    if args.unsafe_allow_private_networks:
        print("WARNING: private-network protection disabled (test use only)", file=sys.stderr)
    try:
        config = CrawlConfig(
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            max_concurrency=args.concurrency,
            request_timeout=args.timeout,
            max_response_bytes=args.max_response_bytes,
            max_asset_bytes=args.max_asset_bytes,
            crawl_delay=args.delay,
            additional_allowed_hosts=tuple(args.allow_host),
            asset_origin_allowlist=tuple(args.allow_asset_origin),
            fetch_assets=not args.no_assets,
            fetch_js=not args.no_js,
            fetch_css=not args.no_css,
            include_patterns=tuple(args.include),
            exclude_patterns=tuple(args.exclude),
            unsafe_allow_private_networks=args.unsafe_allow_private_networks,
        )
    except ValueError as exc:
        p.error(str(exc))

    try:
        result = crawl_sync(url, config)
    except KeyboardInterrupt:
        print("Interrupted; no output written.", file=sys.stderr)
        return 130

    if args.stdout_json:
        print(to_json(result))
        print(format_summary(result, None), file=sys.stderr)
    else:
        out = Path(args.output)
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            write_json(result, out)
        except OSError as exc:
            print(f"ERROR: could not write {out}: {exc}", file=sys.stderr)
            return 3
        print(format_summary(result, out))
    if args.html_report:
        try:
            Path(args.html_report).write_text(html_report(result), encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: could not write report: {exc}", file=sys.stderr)
            return 3
        print(f"HTML report: {Path(args.html_report).resolve()}")
    if args.export_dir:
        try:
            manifest = export_folder(result, args.export_dir)
        except (OSError, ValueError) as exc:
            print(f"ERROR: could not export files: {exc}", file=sys.stderr)
            return 3
        print(f"Extracted {len(manifest['files'])} files to {Path(args.export_dir).resolve()}")
    return 1 if result["crawl_status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
