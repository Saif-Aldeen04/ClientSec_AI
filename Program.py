#!/usr/bin/env python3
"""Thin launcher for the crawler.

Rules:
- If the user does not pass --confirm-authorized, we treat it as authorized for this local script.
- If the user does not pass --depth or --max-pages, we crawl the whole site without artificial limits.
- Output is always saved to Output/crawler_result.json.
- This file is meant to be extended later with more stages.
"""

from __future__ import annotations

import argparse
import getpass
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
CHUNKS_DIR = OUTPUT_DIR / "Chunks"
AI_RESULTS_DIR = OUTPUT_DIR / "AI_Results"
DEPI_DIR = ROOT
CRAWLER = ROOT / "Crawler.py"
JS_EXTRACTOR = ROOT / "js_extractor.py"
VENV_PYTHON = ROOT / "clientsec-crawler" / ".venv" / ("Scripts/python.exe" if sys.platform.startswith("win") else "bin/python")


def rename_js_files_in_order(folder_path: str | Path = INPUT_FILES_DIR) -> list[Path]:
    """Rename JS files in a folder as 1.name.js, 2.name.js, ... without creating new files."""
    js_dir = Path(folder_path)
    if not js_dir.exists():
        return []

    js_files = sorted(
        [p for p in js_dir.iterdir() if p.is_file() and p.suffix.lower() == ".js"],
        key=lambda p: p.name.lower(),
    )

    renamed: list[Path] = []
    for index, file_path in enumerate(js_files, start=1):
        new_name = f"{index}.{file_path.name}"
        new_path = file_path.with_name(new_name)
        counter = 1
        while new_path.exists() and new_path != file_path:
            new_path = file_path.with_name(f"{index}_{counter}.{file_path.name}")
            counter += 1

        if new_path != file_path:
            file_path.rename(new_path)
        renamed.append(new_path)

    return renamed


def run_cmd(args: list[str]) -> int:
    if VENV_PYTHON.exists():
        cmd = [str(VENV_PYTHON), str(CRAWLER), *args]
    else:
        cmd = [sys.executable, str(CRAWLER), *args]
    return subprocess.call(cmd, cwd=str(ROOT))


def run_js_extractor_for_input_files(input_dir: str | Path = INPUT_FILES_DIR,
                                   output_dir: str | Path = CHUNKS_DIR) -> list[Path]:
    """Run js_extractor.py on all InputFiles and store the generated chunks in Output/Chunks."""
    in_dir = Path(input_dir)
    out_dir = Path(output_dir)
    if not in_dir.is_absolute():
        in_dir = ROOT / in_dir
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir

    out_dir.mkdir(parents=True, exist_ok=True)
    for old_file in out_dir.iterdir():
        if old_file.is_file() or old_file.is_symlink():
            old_file.unlink()
        elif old_file.is_dir():
            shutil.rmtree(old_file, ignore_errors=True)

    if not in_dir.exists():
        print(f"Input folder not found: {in_dir}")
        return []

    cmd = [str(VENV_PYTHON), str(JS_EXTRACTOR), str(in_dir), "-o", str(out_dir), "--semantic-only"]
    if not VENV_PYTHON.exists():
        cmd = [sys.executable, str(JS_EXTRACTOR), str(in_dir), "-o", str(out_dir), "--semantic-only"]

    result = subprocess.call(cmd, cwd=str(ROOT))
    if result != 0:
        print(f"js_extractor.py failed with exit code {result}.")
        return []

    created = [p for p in out_dir.rglob("*.js")]
    return created


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


def run_ai_auditors(chunks_dir: str | Path = CHUNKS_DIR,
                    results_dir: str | Path = AI_RESULTS_DIR) -> list[Path]:
    """Run all three DEPI auditors and collect their JSON reports."""
    chunks_path = Path(chunks_dir)
    results_path = Path(results_dir)
    if not chunks_path.is_absolute():
        chunks_path = ROOT / chunks_path
    if not results_path.is_absolute():
        results_path = ROOT / results_path

    results_path.mkdir(parents=True, exist_ok=True)

    if not chunks_path.exists():
        print(f"Chunks folder not found: {chunks_path}")
        return []

    auditor_jobs = (
        ("secret_auditor.py", results_path / "secret_findings.json"),
        ("owasp_auditor.py", results_path / "owasp_findings.json"),
        ("logic_auditor.py", results_path / "logic_findings.json"),
    )

    python = str(DEPI_DIR / ".venv" / ("Scripts/python.exe" if sys.platform.startswith("win") else "bin/python"))
    if not Path(python).exists():
        python = str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable
    reports: list[Path] = []

    for script_name, report_path in auditor_jobs:
        script_path = DEPI_DIR / script_name
        cmd = [python, str(script_path), str(chunks_path), str(report_path)]
        print(f"Running: {script_name}")
        result = subprocess.call(cmd, cwd=str(DEPI_DIR))
        if result != 0:
            print(f"{script_name} failed with exit code {result}.")
            continue
        if report_path.exists():
            reports.append(report_path)

    return reports


def main() -> int:
    argv = sys.argv[1:]

    if not argv:
        try:
            groq_api_key = getpass.getpass("Enter your Groq API key: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return 130

        if not groq_api_key:
            print("Groq API key is required.")
            return 2

        url = input("Enter target URL: ").strip()
        if not url:
            print("Target URL is required.")
            return 2

        os.environ["GROQ_API_KEY"] = groq_api_key
        argv = ["--url", url]

    if "--url" not in argv:
        print("Usage: python3 Program.py --url https://example.com [--depth 2] [--max-pages 50] [--confirm-authorized]")
        print("Interactive mode: python3 Program.py")
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
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        download_input_files(output_path)
        rename_js_files_in_order(INPUT_FILES_DIR)
        run_js_extractor_for_input_files(INPUT_FILES_DIR, CHUNKS_DIR)
        AI_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        ai_reports = run_ai_auditors(CHUNKS_DIR, AI_RESULTS_DIR)
        print(f"Pipeline complete. Output folder: {OUTPUT_DIR}")
        print(f"JS files: {INPUT_FILES_DIR}")
        print(f"Chunks: {CHUNKS_DIR}")
    return result


if __name__ == "__main__":
    raise SystemExit(main())