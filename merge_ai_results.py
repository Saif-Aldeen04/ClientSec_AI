from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parent
INPUT_DIR = PROJECT_DIR / "Output" / "AI_Results"
OUTPUT_FILE = PROJECT_DIR / "Output" / "Final_JSON.json"
INPUT_FILES = (
    "logic_findings.json",
    "owasp_findings.json",
    "secret_findings.json",
)


class MergeError(Exception):
    pass


def load_report(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as source:
            data = json.load(source)
    except FileNotFoundError as exc:
        raise MergeError(f"Missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise MergeError(
            f"Invalid JSON in {path} at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    except OSError as exc:
        raise MergeError(f"Could not read {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise MergeError(f"{path}: root JSON must be an object")

    findings = data.get("findings")
    if not isinstance(findings, list):
        raise MergeError(f"{path}: 'findings' must be an array")

    return data


def merge_reports() -> dict[str, Any]:
    merged_findings: list[Any] = []
    source_reports: list[dict[str, Any]] = []

    for filename in INPUT_FILES:
        report_path = INPUT_DIR / filename
        report = load_report(report_path)
        source_reports.append(
            {
                "file": filename,
                "agent": report.get("agent"),
                "status": report.get("status"),
                "total_chunks_scanned": report.get("total_chunks_scanned"),
                "findings_count": len(report["findings"]),
            }
        )
        merged_findings.extend(report["findings"])

    return {
        "status": "COMPLETED",
        "source_reports": source_reports,
        "total_findings": len(merged_findings),
        "findings": merged_findings,
    }


def write_output(data: dict[str, Any]) -> None:
    try:
        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with OUTPUT_FILE.open("w", encoding="utf-8") as destination:
            json.dump(data, destination, ensure_ascii=False, indent=2)
            destination.write("\n")
    except OSError as exc:
        raise MergeError(f"Could not write {OUTPUT_FILE}: {exc}") from exc


def main() -> int:
    try:
        final_data = merge_reports()
        write_output(final_data)
    except MergeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Merged {final_data['total_findings']} findings into: {OUTPUT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
