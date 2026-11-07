#!/usr/bin/env python3
"""Thin launcher for the crawler.

Rules:
- If the user does not pass --confirm-authorized, we treat it as authorized for this local script.
- If the user does not pass --depth or --max-pages, we crawl the whole site without artificial limits.
- Output is always saved to Output/crawler_result.json.
- This file is meant to be extended later with more stages.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = ROOT / "Output"
DEFAULT_OUTPUT = OUTPUT_DIR / "crawler_result.json"
INPUT_FILES_DIR = OUTPUT_DIR / "InputFiles"
CRAWLER = ROOT / "Crawler.py"
VENV_PYTHON = ROOT / "clientsec-crawler" / ".venv" / ("Scripts/python.exe" if sys.platform.startswith("win") else "bin/python")


def run_cmd(args: list[str]) -> int:
    if VENV_PYTHON.exists():
        cmd = [str(VENV_PYTHON), str(CRAWLER), *args]
    else:
        cmd = [sys.executable, str(CRAWLER), *args]
    return subprocess.call(cmd, cwd=str(ROOT))


def download_input_files(output_path: str | Path = DEFAULT_OUTPUT) -> list[Path]:
    output_file = Path(output_path)
    if not output_file.is_absolute():
        output_file = ROOT / output_file

    INPUT_FILES_DIR.mkdir(parents=True, exist_ok=True)

    for old_file in INPUT_FILES_DIR.iterdir():
        if old_file.is_file() or old_file.is_symlink():
            old_file.unlink()
        elif old_file.is_dir():
            shutil.rmtree(old_file, ignore_errors=True)

    if not output_file.exists():
        print(f"No output file found at {output_file}. Nothing to download.")
        return []

    try:
        data = json.loads(output_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON in {output_file}: {exc}")
        return []

    if not isinstance(data, list):
        print(f"Expected a list of JS records in {output_file}.")
        return []

    downloaded: list[Path] = []
    seen: set[str] = set()

    for item in data:
        if not isinstance(item, dict):
            continue

        js_url = item.get("url")
        if not isinstance(js_url, str) or not js_url:
            continue

        parsed = urlparse(js_url)
        if parsed.scheme not in {"http", "https"}:
            continue

        if js_url in seen:
            continue
        seen.add(js_url)

        file_name = Path(parsed.path).name or "script.js"
        if not file_name.lower().endswith(".js"):
            file_name = f"{file_name}.js"

        dest = INPUT_FILES_DIR / file_name
        counter = 1
        while dest.exists():
            stem = Path(file_name).stem
            suffix = Path(file_name).suffix or ".js"
            dest = INPUT_FILES_DIR / f"{stem}_{counter}{suffix}"
            counter += 1

        try:
            req = Request(js_url, headers={"User-Agent": "Mozilla/5.0"})
            with urlopen(req, timeout=30) as response, open(dest, "wb") as out_file:
                shutil.copyfileobj(response, out_file)
            downloaded.append(dest)
            print(f"Downloaded: {js_url} -> {dest}")
        except Exception as exc:
            print(f"Failed to download {js_url}: {exc}")

    return downloaded


def main() -> int:
    argv = sys.argv[1:]
    if "--url" not in argv:
        print("Usage: python3 Program.py --url https://example.com [--depth 2] [--max-pages 50] [--confirm-authorized]")
        return 2

    if "--confirm-authorized" not in argv:
        argv.append("--confirm-authorized")

    if "--depth" not in argv:
        argv.extend(["--depth", "999999"])

    if "--max-pages" not in argv:
        argv.extend(["--max-pages", "999999"])

    output_path = DEFAULT_OUTPUT
    if "--output" in argv:
        output_index = argv.index("--output")
        if output_index + 1 < len(argv):
            output_path = Path(argv[output_index + 1])
    else:
        argv.extend(["--output", str(output_path)])

    result = run_cmd(argv)
    if result == 0:
        download_input_files(output_path)
    return result


if __name__ == "__main__":
    raise SystemExit(main())