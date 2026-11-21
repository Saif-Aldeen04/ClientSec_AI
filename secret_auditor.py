import os
import json
import logging
import asyncio
import sys
from pathlib import Path
from typing import List, Dict, Any
from groq import AsyncGroq

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

def format_code_with_line_numbers(code_str: str) -> str:
    lines = code_str.splitlines()
    return "\n".join([f"Line {i + 1}: {line}" for i, line in enumerate(lines)])

SECRET_HUNTER_PROMPT = """
You are a high-speed Secret, Credential & Sensitive Endpoint Detection Agent.
Scan the provided JavaScript code/comments ONLY for explicit, real vulnerabilities:
1. Hardcoded Credentials & Secrets (API keys, JWT tokens, AWS keys, DB passwords, private keys).
2. Exposed Hidden Admin Endpoints & Sensitive URLs (e.g., obscure admin paths like 'https://Sate.com/admin-Rdsv5d9/').

STRICT ANTI-HALLUCINATION RULES:
- Analyze ONLY the provided text snippet. Do NOT invent endpoints, lines, or secrets that do not exist in the given chunk.
- If no explicit secret or hidden admin endpoint exists in this snippet, return EXACTLY: {"findings": []}

STRICT OWASP MAPPING:
- CWE-200 (Exposed Admin URL) -> owasp_category: "A01:2021-Broken Access Control"
- CWE-798 / CWE-259 (Hardcoded Secrets/Passwords) -> owasp_category: "A07:2021-Identification and Authentication Failures"

OUTPUT SCHEMA (STRICT JSON ONLY):
{
  "findings": [
    {
      "finding_type": "Exposed Hidden Admin Endpoint",
      "severity": "CRITICAL",
      "cwe_id": "CWE-200",
      "owasp_category": "A01:2021-Broken Access Control",
      "line_number": 7,
      "proof_of_concept": "Found unlinked admin path hardcoded in comments.",
      "code_vulnerable": "Line 7: [Page 1 | L7 | Line] // Admin panel https://Sate.com/admin-Rdsv5d9/",
      "code_remediation": "Remove hardcoded admin URLs from client-side scripts.",
      "impact_description": "Exposes administrative interface endpoints to unauthorized users."
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

        chunks = []

        if self.variables_file.exists():
            vars_content = self.variables_file.read_text(encoding='utf-8').strip()
            if vars_content:
                chunks.append({"chunk_id": "global_vars", "function_name": "<global_scope>", "source_file": "variables.txt", "file_name": "variables.txt", "code": vars_content})

        if self.comments_file.exists():
            comments_content = self.comments_file.read_text(encoding='utf-8').strip()
            if comments_content:
                chunks.append({"chunk_id": "global_comments", "function_name": "<code_comments>", "source_file": "comments.txt", "file_name": "comments.txt", "code": comments_content})

        if self.map_file.exists():
            map_data = json.loads(self.map_file.read_text(encoding='utf-8'))
            for page in map_data.get("pages", []):
                source_file = page.get("source_file", "unknown")
                for fn in page.get("functions", []):
                    output_filename = fn.get("output_file", "").replace('\\', '/').split('/')[-1]
                    file_target = self.input_path / output_filename
                    if file_target.exists():
                        chunks.append({"chunk_id": fn.get("id") or output_filename, "function_name": fn.get("name", "<unknown>"), "source_file": source_file, "file_name": output_filename, "code": file_target.read_text(encoding='utf-8').strip()})
        else:
            summary_file = self.input_path / "semantic_chunks_summary.json"
            if summary_file.exists():
                summary = json.loads(summary_file.read_text(encoding='utf-8'))
                for page in summary.get("pages", []):
                    source_file = page.get("source_file", "unknown")
                    for chunk in page.get("chunks", []):
                        output_filename = chunk.get("output_file", "").replace('\\', '/').split('/')[-1]
                        file_target = self.input_path / output_filename
                        if not file_target.exists():
                            continue
                        chunk_id = f"{page.get('page', 1)}.{chunk.get('index', len(chunks) + 1)}"
                        chunks.append({"chunk_id": chunk_id, "function_name": chunk.get("name", "full"), "source_file": source_file, "file_name": output_filename, "code": file_target.read_text(encoding='utf-8').strip()})

        return chunks

class GroqModelRouter:
    def __init__(self, groq_api_key: str):
        self.groq_client = AsyncGroq(api_key=groq_api_key)
        self.task_model_chains: Dict[str, List[str]] = {
            "secret_hunter": ["allam-2-7b", "openai/gpt-oss-20b"],
            "owasp_auditor": ["qwen/qwen3.8-27b", "openai/gpt-oss-20b"],
            "business_logic": ["openai/gpt-oss-120b", "qwen/qwen3.8-27b"]
        }

    async def execute_task_with_fallback(self, task_name: str, system_prompt: str, chunk_code: str) -> Dict[str, Any]:
        models = self.task_model_chains[task_name]
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze this code snippet and return the response in valid json format:\n\n{chunk_code}"}
        ]

        for index, model_name in enumerate(models):
            logging.info(f"[*] Task [{task_name}] -> Attempt {index + 1}/{len(models)} via GROQ ({model_name})")

            try:
                response = await self.groq_client.chat.completions.create(
                    model=model_name,
                    messages=messages,
                    response_format={"type": "json_object"},
                    temperature=0.0
                )
                
                raw_content = response.choices[0].message.content
                parsed_json = json.loads(raw_content)
                logging.info(f"[+] Successfully generated findings via {model_name}")
                return parsed_json

            except Exception as e:
                logging.warning(f"[!] GROQ model '{model_name}' failed: {str(e)}")
                continue

        return {"findings": [], "error": "All Groq models failed to process chunk."}

class SecretHunterPipeline:
    def __init__(self, groq_api_key: str, input_dir: str = "input"):
        self.loader = InputLoader(input_dir=input_dir)
        self.router = GroqModelRouter(groq_api_key=groq_api_key)

    def sanitize_and_enrich_findings(self, raw_findings: List[Dict[str, Any]], chunks_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        """تنقية النتائج، إزالة الهلوسة، وإعادة ضبط المعرفات واستخراج السطر المصدري"""
        cleaned = []
        seen_keys = set()
        finding_counter = 1

        for finding in raw_findings:
            chunk_id = finding.get("chunk_id")
            chunk_info = chunks_dict.get(chunk_id)

            if not chunk_info:
                continue

            raw_code_lines = chunk_info["code"].splitlines()
            line_no = finding.get("line_number")

            # 1. التحقق من صحة رقم السطر لمنع الهلوسة
            try:
                line_idx = int(line_no) - 1
            except (ValueError, TypeError):
                line_idx = -1

            if line_idx < 0 or line_idx >= len(raw_code_lines):
                logging.warning(f"[!] Dropping hallucinated finding at invalid line {line_no} in chunk {chunk_id}")
                continue

            # 2. استخراج سطر الكود المباشر إذا طنشه الموديل
            vulnerable_snippet = raw_code_lines[line_idx].strip()
            
            # فلترة خاصة لملفات JS العادية التي لا تحتوي أسراراً
            if chunk_id not in ["global_vars", "global_comments"]:
                if "admin" not in vulnerable_snippet.lower() and "key" not in vulnerable_snippet.lower() and "http" not in vulnerable_snippet.lower():
                    logging.warning(f"[!] Dropping false positive on line {line_no} in chunk {chunk_id}: '{vulnerable_snippet}'")
                    continue

            # 3. إزالة التكرار (Deduplication)
            dedup_key = f"{chunk_info['source_file']}_{line_idx}_{finding.get('finding_type')}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            # 4. بناء النتيجة النظيفة والمكتملة
            cleaned_finding = {
                "id": f"SEC-{finding_counter:03d}",
                "finding_type": finding.get("finding_type", "Hardcoded Secret / Sensitive Disclosure"),
                "severity": finding.get("severity", "CRITICAL"),
                "cwe_id": finding.get("cwe_id", "CWE-200"),
                "owasp_category": finding.get("owasp_category", "A01:2021-Broken Access Control"),
                "line_number": line_idx + 1,
                "proof_of_concept": finding.get("proof_of_concept", "Found sensitive data in source code."),
                "code_vulnerable": f"Line {line_idx + 1}: {vulnerable_snippet}",
                "code_remediation": finding.get("code_remediation", "Remove hardcoded credentials/URLs and use secure config."),
                "impact_description": finding.get("impact_description", "Exposes sensitive system data to unauthorized users."),
                "chunk_id": chunk_id,
                "function_name": chunk_info["function_name"],
                "source_file": chunk_info["source_file"],
                "chunk_file": chunk_info["file_name"]
            }

            cleaned.append(cleaned_finding)
            finding_counter += 1

        return cleaned

    async def run(self, output_file: str = "secret_findings.json"):
        chunks = self.loader.load_chunks()
        logging.info(f"[+] Loaded {len(chunks)} unique chunks for scan.\n")

        chunks_dict = {c["chunk_id"]: c for c in chunks}
        raw_findings = []

        for chunk in chunks:
            logging.info(f"[*] Scanning Chunk ID [{chunk['chunk_id']}] ({chunk['file_name']})...")

            numbered_code = format_code_with_line_numbers(chunk["code"])

            result = await self.router.execute_task_with_fallback(
                task_name="secret_hunter",
                system_prompt=SECRET_HUNTER_PROMPT,
                chunk_code=numbered_code
            )

            if "findings" in result and isinstance(result["findings"], list):
                for finding in result["findings"]:
                    finding["chunk_id"] = chunk["chunk_id"]
                    raw_findings.append(finding)

        # دالة التنقية والمعالجة البرمجية الصارمة
        sanitized_findings = self.sanitize_and_enrich_findings(raw_findings, chunks_dict)

        final_report = {
            "status": "COMPLETED",
            "agent": "secret_hunter",
            "total_chunks_scanned": len(chunks),
            "total_secrets_found": len(sanitized_findings),
            "findings": sanitized_findings
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(final_report, f, indent=2, ensure_ascii=False)

        logging.info(f"\n[✔] Scan finished. Output saved to '{output_file}'.")
        return final_report

if __name__ == "__main__":
    groq_api_key = os.getenv("GROQ_API_KEY", "").strip()
    if not groq_api_key:
        api_path = Path(__file__).resolve().parent / "api.txt"
        if api_path.exists():
            for line in api_path.read_text(encoding="utf-8").splitlines():
                if line.strip().lower().startswith("groq:"):
                    groq_api_key = line.split(":", 1)[1].strip()
                    break
    if not groq_api_key:
        raise ValueError("GROQ_API_KEY is required. Set env var, or add a 'Groq:' line in DEPI/api.txt.")

    input_dir = sys.argv[1] if len(sys.argv) > 1 else "input"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "secret_findings.json"
    pipeline = SecretHunterPipeline(groq_api_key=groq_api_key, input_dir=input_dir)
    asyncio.run(pipeline.run(output_file=output_file))