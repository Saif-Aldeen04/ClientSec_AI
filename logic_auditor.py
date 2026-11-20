import json
import logging
import asyncio
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

from groq import AsyncGroq


logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")


def load_groq_api_key() -> str:
    env_key = os.getenv("GROQ_API_KEY", "").strip()
    if env_key:
        return env_key

    dotenv_path = Path(".env")
    if dotenv_path.exists():
        for line in dotenv_path.read_text(encoding="utf-8").splitlines():
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#"):
                continue
            if cleaned.startswith("GROQ_API_KEY="):
                key = cleaned.split("=", 1)[1].strip().strip('"').strip("'")
                if key:
                    return key

    api_path = Path("api.txt")
    if api_path.exists():
        for line in api_path.read_text(encoding="utf-8").splitlines():
            if line.strip().lower().startswith("groq:"):
                key = line.split(":", 1)[1].strip()
                if key:
                    return key

    return ""


def format_code_with_line_numbers(code_str: str) -> str:
    lines = code_str.splitlines()
    return "\n".join([f"Line {i + 1}: {line}" for i, line in enumerate(lines)])


LOGIC_AUDITOR_PROMPT = """
You are a Client-Side Business Logic Auditor focused on real business-logic flaws in JavaScript.
Analyze the supplied code snippet and identify concrete logic vulnerabilities only.

Focus on:
1) Missing or bypassable validation of trusted/untrusted inputs.
2) Authorization, role, or privilege bypasses in client-side workflows.
3) Unchecked state transitions such as duplicate actions, race conditions, or bypassable payment/approval logic.
4) Unsafe workflow logic that accepts invalid values, skips critical checks, or trusts client state.
5) Business rules that are enforced only in the front end while the backend remains vulnerable.
6) Hidden or unexpected logic branches triggered by crafted inputs or malformed states.

STRICT ANTI-HALLUCINATION RULES:
- Only report issues that are actually visible in the source snippet.
- Do not invent variables, functions, or business rules that are not present.
- If no explicit business logic flaw is present, return EXACTLY: {"findings": []}

Return STRICT JSON ONLY with this shape:
{
  "findings": [
    {
      "finding_type": "Bypassable validation in registration workflow",
      "severity": "HIGH",
      "cwe_id": "CWE-840",
      "owasp_category": "A01:2021-Broken Access Control",
      "line_number": 8,
      "proof_of_concept": "A required business gate is skipped when the submitted data is empty or malformed.",
      "code_vulnerable": "Line 8: if (!user || !user.email) return;",
      "code_remediation": "Enforce server-side validation and add explicit checks for required business-state transitions.",
      "impact_description": "Attackers may bypass critical approval or validation steps and trigger unauthorized behavior."
    }
  ]
}
"""


class InputLoader:
    def __init__(self, input_dir: str = "input"):
        self.input_path = Path(input_dir)
        self.map_file = self.input_path / "numbering_map.json"
        self.variables_file = self.input_path / "variables.txt"
        self.comments_file = self.input_path / "comments.txt"

    def load_chunks(self) -> List[Dict[str, Any]]:
        if not self.input_path.exists():
            raise FileNotFoundError(f"Directory '{self.input_path}' does not exist.")

        chunks: List[Dict[str, Any]] = []

        if self.variables_file.exists():
            with open(self.variables_file, "r", encoding="utf-8") as f:
                vars_content = f.read().strip()
                if vars_content:
                    chunks.append(
                        {
                            "chunk_id": "global_vars",
                            "function_name": "<global_scope>",
                            "source_file": "variables.txt",
                            "file_name": "variables.txt",
                            "code": vars_content,
                        }
                    )

        if self.comments_file.exists():
            with open(self.comments_file, "r", encoding="utf-8") as f:
                comments_content = f.read().strip()
                if comments_content:
                    chunks.append(
                        {
                            "chunk_id": "global_comments",
                            "function_name": "<code_comments>",
                            "source_file": "comments.txt",
                            "file_name": "comments.txt",
                            "code": comments_content,
                        }
                    )

        map_file = self.map_file
        if map_file.exists():
            with open(map_file, "r", encoding="utf-8") as f:
                map_data = json.load(f)

            for page in map_data.get("pages", []):
                source_file = page.get("source_file", "unknown")
                for fn in page.get("functions", []):
                    raw_output_path = fn.get("output_file", "")
                    output_filename = raw_output_path.replace("\\", "/").split("/")[-1]
                    file_target = self.input_path / output_filename

                    if file_target.exists():
                        code_content = file_target.read_text(encoding="utf-8").strip()
                        chunks.append(
                            {
                                "chunk_id": fn.get("id") or output_filename,
                                "function_name": fn.get("name", "<unknown>"),
                                "source_file": source_file,
                                "file_name": output_filename,
                                "code": code_content,
                            }
                        )

        else:
            summary_file = self.input_path / "semantic_chunks_summary.json"
            if summary_file.exists():
                summary = json.loads(summary_file.read_text(encoding="utf-8"))
                for page in summary.get("pages", []):
                    source_file = page.get("source_file", "unknown")
                    for chunk in page.get("chunks", []):
                        raw_output_path = chunk.get("output_file", "")
                        output_filename = raw_output_path.replace("\\", "/").split("/")[-1]
                        file_target = self.input_path / output_filename
                        if not file_target.exists():
                            continue
                        code_content = file_target.read_text(encoding="utf-8").strip()
                        chunk_id = f"{page.get('page', 1)}.{chunk.get('index', len(chunks) + 1)}"
                        chunks.append(
                            {
                                "chunk_id": chunk_id,
                                "function_name": chunk.get("name", "full"),
                                "source_file": source_file,
                                "file_name": output_filename,
                                "code": code_content,
                            }
                        )

        return chunks


class GroqModelRouter:
    def __init__(self, groq_api_key: str):
        self.groq_client = AsyncGroq(api_key=groq_api_key)
        self.task_model_chains: Dict[str, List[str]] = {
            "secret_hunter": ["allam-2-7b", "openai/gpt-oss-20b"],
            "owasp_auditor": ["qwen/qwen3.8-27b", "openai/gpt-oss-20b"],
            "business_logic": ["openai/gpt-oss-120b", "qwen/qwen3.8-27b"],
        }

    async def execute_task_with_fallback(self, task_name: str, system_prompt: str, user_payload: str) -> Dict[str, Any]:
        models = self.task_model_chains[task_name]
        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    "Analyze this JavaScript business logic context and return valid json only.\n\n"
                    f"{user_payload}"
                ),
            },
        ]

        for index, model_name in enumerate(models):
            logging.info(f"[*] Task [{task_name}] -> Attempt {index + 1}/{len(models)} via GROQ ({model_name})")
            try:
                response = await self.groq_client.chat.completions.create(
                    model=model_name,
                    messages=messages,
                    response_format={"type": "json_object"},
                    temperature=0.0,
                )
                raw_content = response.choices[0].message.content
                parsed_json = json.loads(raw_content)
                logging.info(f"[+] Successfully generated logic findings via {model_name}")
                return parsed_json
            except Exception as exc:
                logging.warning(f"[!] GROQ model '{model_name}' failed: {str(exc)}")
                continue

        return {"findings": [], "error": "All Groq models failed to process chunk."}


class BusinessLogicAuditorPipeline:
    CWE_LOGIC_MAP = {
        "CWE-840": "A01:2021-Broken Access Control",
        "CWE-285": "A01:2021-Broken Access Control",
        "CWE-639": "A01:2021-Broken Access Control",
        "CWE-362": "A05:2021-Security Misconfiguration",
        "CWE-345": "A05:2021-Security Misconfiguration",
    }

    def __init__(self, groq_api_key: str, input_dir: str = "input"):
        self.loader = InputLoader(input_dir=input_dir)
        self.router = GroqModelRouter(groq_api_key=groq_api_key)

    def _build_user_payload(self, chunk: Dict[str, Any], numbered_code: str) -> str:
        payload = {
            "task": "business_logic",
            "chunk_metadata": {
                "chunk_id": chunk["chunk_id"],
                "function_name": chunk["function_name"],
                "source_file": chunk["source_file"],
                "chunk_file": chunk["file_name"],
            },
            "analysis_rules": {
                "line_numbers_are_authoritative": True,
                "report_only_real_findings": True,
                "return_json_only": True,
            },
            "numbered_code": numbered_code,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    def sanitize_and_enrich_findings(
        self, raw_findings: List[Dict[str, Any]], chunks_dict: Dict[str, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        cleaned: List[Dict[str, Any]] = []
        seen_keys: Set[str] = set()
        finding_counter = 1

        for finding in raw_findings:
            chunk_id = finding.get("chunk_id")
            chunk_info = chunks_dict.get(chunk_id)
            if not chunk_info:
                continue

            raw_code_lines = chunk_info["code"].splitlines()
            line_no = finding.get("line_number")

            try:
                line_idx = int(line_no) - 1
            except (ValueError, TypeError):
                line_idx = -1

            if line_idx < 0 or line_idx >= len(raw_code_lines):
                logging.warning(f"[!] Dropping logic finding with invalid line {line_no} in chunk {chunk_id}")
                continue

            snippet = raw_code_lines[line_idx].strip()
            dedup_key = f"{chunk_info['source_file']}_{line_idx}_{finding.get('finding_type', 'Business Logic Finding')}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            cwe_id = finding.get("cwe_id", "CWE-840")
            owasp_category = finding.get("owasp_category") or self.CWE_LOGIC_MAP.get(cwe_id, "A01:2021-Broken Access Control")

            cleaned.append(
                {
                    "id": f"LOGIC-{finding_counter:03d}",
                    "finding_type": finding.get("finding_type", "Business Logic Flaw"),
                    "severity": finding.get("severity", "HIGH"),
                    "cwe_id": cwe_id,
                    "owasp_category": owasp_category,
                    "line_number": line_idx + 1,
                    "proof_of_concept": finding.get(
                        "proof_of_concept",
                        "The snippet shows a business control or validation gap that can be triggered by crafted input.",
                    ),
                    "code_vulnerable": f"Line {line_idx + 1}: {snippet}",
                    "code_remediation": finding.get(
                        "code_remediation",
                        "Enforce the business rule on the server side and add explicit validation for each state transition.",
                    ),
                    "impact_description": finding.get(
                        "impact_description",
                        "An attacker may bypass intended rules, trigger unauthorized workflows, or abuse application logic.",
                    ),
                    "chunk_id": chunk_id,
                    "function_name": chunk_info["function_name"],
                    "source_file": chunk_info["source_file"],
                    "chunk_file": chunk_info["file_name"],
                }
            )
            finding_counter += 1

        return cleaned

    async def run(self, output_file: str = "logic_findings.json") -> Dict[str, Any]:
        chunks = self.loader.load_chunks()
        logging.info(f"[+] Loaded {len(chunks)} chunks for business logic scan.")

        chunks_dict = {c["chunk_id"]: c for c in chunks}
        raw_findings: List[Dict[str, Any]] = []

        for chunk in chunks:
            chunk_id = chunk["chunk_id"]
            logging.info(f"[*] Business logic scanning chunk [{chunk_id}] ({chunk['file_name']})")

            numbered_code = format_code_with_line_numbers(chunk["code"])
            user_payload = self._build_user_payload(chunk, numbered_code)

            result = await self.router.execute_task_with_fallback(
                task_name="business_logic",
                system_prompt=LOGIC_AUDITOR_PROMPT,
                user_payload=user_payload,
            )

            findings = result.get("findings", [])
            if isinstance(findings, list):
                for finding in findings:
                    finding["chunk_id"] = chunk_id
                    raw_findings.append(finding)

        sanitized_findings = self.sanitize_and_enrich_findings(raw_findings, chunks_dict)

        final_report = {
            "status": "COMPLETED",
            "agent": "business_logic",
            "total_chunks_scanned": len(chunks),
            "total_findings": len(sanitized_findings),
            "findings": sanitized_findings,
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(final_report, f, indent=2, ensure_ascii=False)

        logging.info(f"[✔] Business logic scan finished. Output saved to '{output_file}'.")
        return final_report


if __name__ == "__main__":
    groq_api_key = load_groq_api_key()
    if not groq_api_key:
        raise ValueError("GROQ_API_KEY is required. Set env var, or add it to .env, or add a 'Groq:' line in api.txt.")

    input_dir = sys.argv[1] if len(sys.argv) > 1 else "input"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "logic_findings.json"
    pipeline = BusinessLogicAuditorPipeline(groq_api_key=groq_api_key, input_dir=input_dir)
    asyncio.run(pipeline.run(output_file=output_file))
