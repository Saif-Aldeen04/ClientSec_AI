import os
import re
import json
import asyncio
import logging
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


OWASP_AUDITOR_PROMPT = """
You are the OWASP Client-Side Security Auditor Agent.
Analyze JavaScript snippets for REAL and EXPLICIT vulnerabilities only.

Focus areas:
1) DOM-based XSS
2) Insecure postMessage handlers (missing/weak origin checks)
3) Dangerous localStorage/sessionStorage handling of tokens/secrets
4) Open Redirect patterns
    - Inspect redirect parameters for protocol-relative bypasses (e.g., '//evil.com') that bypass naive startsWith('/') checks.
5) Source-to-sink taint paths from untrusted input to dangerous sinks
6) Client-side Prototype Pollution (unsafe dynamic/nested property assignment or object merges from untrusted input without blocking __proto__/constructor/prototype)

STRICT ANTI-HALLUCINATION RULES:
- Analyze ONLY the provided chunk and context.
- Do NOT invent lines, functions, or sinks.
- Scan for ALL distinct vulnerabilities present in the chunk. Do NOT stop after reporting the highest severity issue.
- If no valid issue exists, return EXACTLY: {"findings": []}

Return STRICT JSON ONLY with this shape:
{
  "findings": [
    {
      "finding_type": "DOM XSS via innerHTML",
      "severity": "HIGH",
      "cwe_id": "CWE-79",
      "owasp_category": "A03:2021-Injection",
      "line_number": 12,
      "proof_of_concept": "location.hash flows into innerHTML without sanitization.",
      "code_vulnerable": "Line 12: container.innerHTML = location.hash",
      "code_remediation": "Use textContent or sanitize untrusted content before rendering.",
      "impact_description": "Attacker-controlled script may execute in victim browser."
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
            vars_content = self.variables_file.read_text(encoding="utf-8").strip()
            if vars_content:
                chunks.append({"chunk_id": "global_vars", "function_name": "<global_scope>", "source_file": "variables.txt", "file_name": "variables.txt", "code": vars_content})

        if self.comments_file.exists():
            comments_content = self.comments_file.read_text(encoding="utf-8").strip()
            if comments_content:
                chunks.append({"chunk_id": "global_comments", "function_name": "<code_comments>", "source_file": "comments.txt", "file_name": "comments.txt", "code": comments_content})

        if self.map_file.exists():
            map_data = json.loads(self.map_file.read_text(encoding="utf-8"))
            for page in map_data.get("pages", []):
                source_file = page.get("source_file", "unknown")
                for fn in page.get("functions", []):
                    output_filename = fn.get("output_file", "").replace("\\", "/").split("/")[-1]
                    file_target = self.input_path / output_filename
                    if file_target.exists():
                        chunks.append({"chunk_id": fn.get("id") or output_filename, "function_name": fn.get("name", "<unknown>"), "source_file": source_file, "file_name": output_filename, "code": file_target.read_text(encoding="utf-8").strip()})
        else:
            summary_file = self.input_path / "semantic_chunks_summary.json"
            if summary_file.exists():
                summary = json.loads(summary_file.read_text(encoding="utf-8"))
                for page in summary.get("pages", []):
                    source_file = page.get("source_file", "unknown")
                    for chunk in page.get("chunks", []):
                        output_filename = chunk.get("output_file", "").replace("\\", "/").split("/")[-1]
                        file_target = self.input_path / output_filename
                        if not file_target.exists():
                            continue
                        chunk_id = f"{page.get('page', 1)}.{chunk.get('index', len(chunks) + 1)}"
                        chunks.append({"chunk_id": chunk_id, "function_name": chunk.get("name", "full"), "source_file": source_file, "file_name": output_filename, "code": file_target.read_text(encoding="utf-8").strip()})

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
                # Groq JSON constraint: user content must include the word "json"
                "content": (
                    "Analyze this JavaScript security context and return valid json only.\n\n"
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
                logging.info(f"[+] Successfully generated findings via {model_name}")
                return parsed_json
            except Exception as exc:
                logging.warning(f"[!] GROQ model '{model_name}' failed: {str(exc)}")
                continue

        return {"findings": [], "error": "All Groq models failed to process chunk."}


class OwaspShortTermMemory:
    SOURCE_PATTERNS = {
        "location.hash": re.compile(r"\blocation\.hash\b", re.IGNORECASE),
        "location.search": re.compile(r"\blocation\.search\b", re.IGNORECASE),
        "location.href": re.compile(r"\blocation\.href\b", re.IGNORECASE),
        "document.referrer": re.compile(r"\bdocument\.referrer\b", re.IGNORECASE),
        "window.name": re.compile(r"\bwindow\.name\b", re.IGNORECASE),
        "postMessage.data": re.compile(r"\bevent\.data\b", re.IGNORECASE),
    }

    SINK_PATTERNS = {
        "innerHTML": re.compile(r"\binnerHTML\b", re.IGNORECASE),
        "outerHTML": re.compile(r"\bouterHTML\b", re.IGNORECASE),
        "document.write": re.compile(r"\bdocument\.write\b", re.IGNORECASE),
        "eval": re.compile(r"\beval\s*\(", re.IGNORECASE),
        "Function": re.compile(r"\bnew\s+Function\s*\(", re.IGNORECASE),
        "setTimeout-string": re.compile(r"\bsetTimeout\s*\(\s*['\"]", re.IGNORECASE),
        "setInterval-string": re.compile(r"\bsetInterval\s*\(\s*['\"]", re.IGNORECASE),
    }

    POSTMESSAGE_PATTERNS = {
        "addEventListener-message": re.compile(r"addEventListener\s*\(\s*['\"]message['\"]", re.IGNORECASE),
        "no-origin-check": re.compile(r"\bevent\.origin\b", re.IGNORECASE),
    }

    STORAGE_PATTERNS = {
        "localStorage": re.compile(r"\blocalStorage\b", re.IGNORECASE),
        "sessionStorage": re.compile(r"\bsessionStorage\b", re.IGNORECASE),
        "token-key": re.compile(r"['\"][^'\"]*(token|jwt|auth|secret|password)[^'\"]*['\"]", re.IGNORECASE),
    }

    REDIRECT_PATTERNS = {
        "location-assign": re.compile(r"\b(location\.(href|assign|replace)|window\.location)\b", re.IGNORECASE),
        "url-param": re.compile(r"\b(redirect|returnUrl|next|target|url)\b", re.IGNORECASE),
    }

    def __init__(self):
        self.chunk_summary: Dict[str, Dict[str, Any]] = {}
        self.token_index: Dict[str, Set[str]] = {}

    def _extract_signals(self, code: str) -> Dict[str, List[str]]:
        signals = {
            "sources": [name for name, pat in self.SOURCE_PATTERNS.items() if pat.search(code)],
            "sinks": [name for name, pat in self.SINK_PATTERNS.items() if pat.search(code)],
            "postmessage": [name for name, pat in self.POSTMESSAGE_PATTERNS.items() if pat.search(code)],
            "storage": [name for name, pat in self.STORAGE_PATTERNS.items() if pat.search(code)],
            "redirect": [name for name, pat in self.REDIRECT_PATTERNS.items() if pat.search(code)],
        }
        return signals

    def _extract_tokens(self, code: str) -> Set[str]:
        token_matches = re.findall(r"[A-Za-z_][A-Za-z0-9_\.]{2,}", code)
        return set([tok.lower() for tok in token_matches][:400])

    def ingest_chunk(self, chunk: Dict[str, Any]) -> None:
        chunk_id = chunk["chunk_id"]
        code = chunk.get("code", "")
        signals = self._extract_signals(code)
        tokens = self._extract_tokens(code)

        self.chunk_summary[chunk_id] = {
            "chunk_id": chunk_id,
            "function_name": chunk.get("function_name", "<unknown>"),
            "source_file": chunk.get("source_file", "unknown"),
            "file_name": chunk.get("file_name", "unknown"),
            "signals": signals,
            "tokens": tokens,
        }

        for token in tokens:
            self.token_index.setdefault(token, set()).add(chunk_id)

    def related_context(self, current_chunk_id: str, seen_chunk_ids: Set[str], top_k: int = 4) -> List[Dict[str, Any]]:
        current = self.chunk_summary.get(current_chunk_id)
        if not current:
            return []

        candidates: Dict[str, int] = {}
        for token in current["tokens"]:
            for chunk_id in self.token_index.get(token, set()):
                if chunk_id == current_chunk_id:
                    continue
                if chunk_id not in seen_chunk_ids:
                    continue
                candidates[chunk_id] = candidates.get(chunk_id, 0) + 1

        ranked = sorted(candidates.items(), key=lambda item: item[1], reverse=True)[:top_k]
        context_items: List[Dict[str, Any]] = []
        for related_chunk_id, score in ranked:
            summary = self.chunk_summary[related_chunk_id]
            context_items.append(
                {
                    "chunk_id": related_chunk_id,
                    "function_name": summary["function_name"],
                    "source_file": summary["source_file"],
                    "file_name": summary["file_name"],
                    "relevance_score": score,
                    "signals": summary["signals"],
                }
            )

        return context_items


class OwaspAuditorPipeline:
    CWE_OWASP_MAP = {
        "CWE-79": "A03:2021-Injection",
        "CWE-1321": "A03:2021-Injection",
        "CWE-94": "A03:2021-Injection",
        "CWE-116": "A03:2021-Injection",
        "CWE-346": "A05:2021-Security Misconfiguration",
        "CWE-922": "A02:2021-Cryptographic Failures",
        "CWE-601": "A01:2021-Broken Access Control",
    }

    def __init__(self, groq_api_key: str, input_dir: str = "input"):
        self.loader = InputLoader(input_dir=input_dir)
        self.router = GroqModelRouter(groq_api_key=groq_api_key)
        self.memory = OwaspShortTermMemory()

    def _build_user_payload(self, chunk: Dict[str, Any], numbered_code: str, related_context: List[Dict[str, Any]]) -> str:
        payload = {
            "task": "owasp_auditor",
            "chunk_metadata": {
                "chunk_id": chunk["chunk_id"],
                "function_name": chunk["function_name"],
                "source_file": chunk["source_file"],
                "chunk_file": chunk["file_name"],
            },
            "memory_context": related_context,
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
                logging.warning(f"[!] Dropping hallucinated finding at invalid line {line_no} in chunk {chunk_id}")
                continue

            snippet = raw_code_lines[line_idx].strip()
            dedup_key = f"{chunk_info['source_file']}_{line_idx}_{finding.get('finding_type', 'OWASP Finding')}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            cwe_id = finding.get("cwe_id", "CWE-79")
            owasp_category = finding.get("owasp_category") or self.CWE_OWASP_MAP.get(cwe_id, "A05:2021-Security Misconfiguration")

            cleaned.append(
                {
                    "id": f"OWASP-{finding_counter:03d}",
                    "finding_type": finding.get("finding_type", "Client-side Security Finding"),
                    "severity": finding.get("severity", "HIGH"),
                    "cwe_id": cwe_id,
                    "owasp_category": owasp_category,
                    "line_number": line_idx + 1,
                    "proof_of_concept": finding.get(
                        "proof_of_concept", "Untrusted client-side data reaches a potentially dangerous browser sink."
                    ),
                    "code_vulnerable": f"Line {line_idx + 1}: {snippet}",
                    "code_remediation": finding.get(
                        "code_remediation", "Validate and sanitize untrusted input and avoid dangerous DOM APIs for direct rendering."
                    ),
                    "impact_description": finding.get(
                        "impact_description", "Can allow script injection, data leakage, or unsafe client-side control flow."
                    ),
                    "chunk_id": chunk_id,
                    "function_name": chunk_info["function_name"],
                    "source_file": chunk_info["source_file"],
                    "chunk_file": chunk_info["file_name"],
                }
            )
            finding_counter += 1

        return cleaned

    async def run(self, output_file: str = "owasp_findings.json") -> Dict[str, Any]:
        chunks = self.loader.load_chunks()
        logging.info(f"[+] Loaded {len(chunks)} chunks for OWASP scan.")

        chunks_dict = {c["chunk_id"]: c for c in chunks}
        seen_chunk_ids: Set[str] = set()
        raw_findings: List[Dict[str, Any]] = []

        # Pre-pass summaries enable fast cross-chunk retrieval when scanning later chunks.
        for chunk in chunks:
            self.memory.ingest_chunk(chunk)

        for chunk in chunks:
            chunk_id = chunk["chunk_id"]
            logging.info(f"[*] OWASP scanning chunk [{chunk_id}] ({chunk['file_name']})")

            numbered_code = format_code_with_line_numbers(chunk["code"])
            related_context = self.memory.related_context(chunk_id, seen_chunk_ids=seen_chunk_ids, top_k=4)
            user_payload = self._build_user_payload(chunk, numbered_code, related_context)

            result = await self.router.execute_task_with_fallback(
                task_name="owasp_auditor", system_prompt=OWASP_AUDITOR_PROMPT, user_payload=user_payload
            )

            findings = result.get("findings", [])
            if isinstance(findings, list):
                for finding in findings:
                    finding["chunk_id"] = chunk_id
                    raw_findings.append(finding)

            seen_chunk_ids.add(chunk_id)

        sanitized_findings = self.sanitize_and_enrich_findings(raw_findings, chunks_dict)

        final_report = {
            "status": "COMPLETED",
            "agent": "owasp_auditor",
            "memory_strategy": "short_term_memory_with_inverted_index",
            "total_chunks_scanned": len(chunks),
            "total_findings": len(sanitized_findings),
            "findings": sanitized_findings,
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(final_report, f, indent=2, ensure_ascii=False)

        logging.info(f"[✔] OWASP scan finished. Output saved to '{output_file}'.")
        return final_report


if __name__ == "__main__":
    groq_api_key = load_groq_api_key()
    if not groq_api_key:
        raise ValueError("GROQ_API_KEY is required. Set env var, or add it to .env, or add a 'Groq:' line in api.txt.")

    input_dir = sys.argv[1] if len(sys.argv) > 1 else "input"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "owasp_findings.json"
    pipeline = OwaspAuditorPipeline(groq_api_key=groq_api_key, input_dir=input_dir)
    asyncio.run(pipeline.run(output_file=output_file))