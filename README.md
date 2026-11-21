# ClientSec AI

## Requirements

Before installing or running the project, make sure you have:

- Python 3.10 or newer.
- `pip` for installing Python packages.
- Internet access for crawling websites and calling the Groq API.
- A valid Groq API key.
- Permission to test the target website.
- A modern web browser for Streamlit dashboard and PDF viewing.

## Groq API Key

1. Open the Groq Console: https://console.groq.com/keys
2. Sign in or create a Groq account.
3. Open **API Keys**.
4. Select **Create API Key**.
5. Copy the key and keep it private.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Saif-Aldeen04/ClientSec_AI.git
cd ClientSec_AI
```

### 2. Create a virtual environment

#### Windows (PowerShell or CMD)

```powershell
py -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install groq beautifulsoup4 esprima httpx streamlit pandas plotly jsbeautifier reportlab>=4.0
```

#### Linux or macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install groq beautifulsoup4 esprima httpx streamlit pandas plotly jsbeautifier reportlab>=4.0
```

### Installed Libraries

- `groq`: communicates with Groq models for the three AI auditors.
- `beautifulsoup4`: parses HTML and extracts JavaScript-related content.
- `esprima`: performs static JavaScript parsing and syntax analysis.
- `httpx`: performs asynchronous HTTP requests inside the crawler.
- `streamlit`: provides the interactive localhost dashboard.
- `pandas`: organizes and filters findings for dashboard display.
- `plotly`: creates severity and vulnerability charts.
- `jsbeautifier`: beautifies JavaScript before extraction and chunking.
- `reportlab`: generates the professional PDF assessment report.

The project also uses Python standard libraries such as `asyncio`, `argparse`, `json`, `socket`, `subprocess`, and `pathlib`.

## Configure the API Key

Create `api.txt` in the project root and place the key using this format:

```text
Groq: gsk_your_api_key_here
```

The auditors also accept an environment variable:

### Windows PowerShell

```powershell
$env:GROQ_API_KEY = "gsk_your_api_key_here"
```

### Linux or macOS

```bash
export GROQ_API_KEY="gsk_your_api_key_here"
```

Do not commit API keys or share them publicly.

## How to Run the Project

### Interactive mode

```bash
python3 Program.py
```

The program securely asks for the Groq key and target URL. Windows users can run:

```powershell
python Program.py
```

### Direct scan mode

```bash
python3 Program.py --url https://example.com
```

### Limited crawl

```bash
python3 Program.py --url https://example.com --confirm-authorized --depth 2 --max-pages 50
```

Options:

- `--url`: target website URL.
- `--depth`: maximum crawler depth.
- `--max-pages`: maximum number of pages to crawl.
- `--confirm-authorized`: explicitly confirms that you are authorized to test the target.
- `--dashboard-only`: opens or reuses the dashboard without running a scan.
- `--pdf-only`: creates a PDF from the latest `Output/Final_JSON.json` without running a scan.
- `--output`: optionally specifies a custom crawler JSON output path.

If no depth or page limit is supplied, `Program.py` currently requests unlimited crawler defaults.

### Dashboard-only mode

```bash
python3 Program.py --dashboard-only
```

Use this command when `Output/Final_JSON.json` already exists. The launcher reuses an existing dashboard server instead of starting duplicate copies and opens one browser tab.

### PDF-only mode

```bash
python3 Program.py --pdf-only
```

This command reads the latest merged JSON result and creates:

```text
Output/ClientSec_AI_Security_Report.pdf
```

Windows equivalent:

```powershell
python Program.py --pdf-only
```

## Project Overview

ClientSec AI is a Python-based security analysis tool for evaluating the client-side security of authorized websites. It combines web crawling, static JavaScript analysis, parallel AI auditing, result merging, interactive visualization, and PDF reporting in one pipeline.

The tool mainly analyzes downloaded JavaScript and HTML content. It does not replace dynamic penetration testing, browser-based exploitation testing, or manual security validation.

## How the Pipeline Works

1. **Crawling**

   `Program.py` starts `Crawler.py`, which uses the `clientsec-crawler` package under `clientsec-crawler/src`. The crawler follows pages inside the target scope and collects JavaScript and HTML assets. The crawler output is stored in `Output/crawler_result.json`.

2. **Asset downloading**

   `Program.py` downloads discovered JavaScript files into `Output/InputFiles`. Existing input files are cleared before the new scan so stale files are not accidentally reused.

3. **JavaScript extraction**

   `js_extractor.py` statically analyzes JavaScript using Esprima. It extracts nested functions, comments, variables, source structures, and security-relevant code patterns. It also splits large scripts into semantic chunks under `Output/Chunks` and identifies critical sections.

4. **Parallel AI auditing**

   The 38 or other number of generated chunks are processed through three specialized auditors:

   - `owasp_auditor.py`: looks for OWASP client-side vulnerabilities such as DOM XSS and unsafe sink usage.
   - `secret_auditor.py`: searches for API keys, passwords, tokens, secrets, and exposed administrative paths.
   - `logic_auditor.py`: identifies business-logic flaws and unsafe application behavior.

   The auditors use Groq asynchronously and save their results in `Output/AI_Results`.

5. **Findings normalization**

   Each finding should retain relevant fields such as severity, CWE, OWASP category, source file, line number, function name, proof of concept, vulnerable code, remediation, and impact. AI output is treated as a candidate finding and should be manually validated.

6. **Result merging**

   `merge_ai_results.py` combines the three auditor outputs into:

   ```text
   Output/Final_JSON.json
   ```

7. **PDF generation**

   `Generate_Report.py` converts `Final_JSON.json` into a complete professional PDF containing an executive summary, severity distribution, findings register, detailed findings, vulnerable code, remediation guidance, and validation notes.

8. **Interactive dashboard**

   `dashboard_single.py` runs through Streamlit and displays severity metrics, charts, finding tables, filters, source details, and remediation information. The dashboard runs locally at a URL printed by `Program.py`, normally beginning from `http://localhost:8501`.

## Output Structure

```text
Output/
├── crawler_result.json
├── crawler_result.html
├── Final_JSON.json
├── ClientSec_AI_Security_Report.pdf
├── dashboard.log
├── InputFiles/
├── Chunks/
└── AI_Results/
    ├── logic_findings.json
    ├── owasp_findings.json
    └── secret_findings.json
```

## Severity Levels

Findings can be classified as:

- `CRITICAL`
- `HIGH`
- `MEDIUM`
- `LOW`
- `INFO`
- `UNKNOWN`

Severity values represent the auditor or merged JSON classification. They should be reviewed and adjusted during manual validation when exploitability or business impact differs.

## Complete Run Example

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install groq beautifulsoup4 esprima httpx streamlit pandas plotly jsbeautifier reportlab>=4.0

python3 Program.py --url https://example.com --confirm-authorized --depth 2 --max-pages 50
```

After the pipeline completes, the dashboard opens once and the PDF report is written under `Output`.

## Security and Authorization Notice

- Only scan websites that you own or are explicitly authorized to test.
- Do not use this tool against third-party systems without written permission.
- AI findings can contain false positives or hallucinated details.
- Review source code and reproduce each finding safely before reporting or remediation.
- The dashboard and PDF are analysis aids, not proof that an exploit works.

## Limitations

- Static analysis cannot prove runtime exploitability.
- Dynamic JavaScript execution is not equivalent to browser automation or a full DAST scan.
- Crawling may miss authenticated pages or client-side routes.
- Groq model availability and API rate limits may affect analysis.
- Client-generated pages may require additional browser instrumentation for complete coverage.

## Future Roadmap

### Additional AI Providers

The next version is planned to support multiple AI providers instead of relying only on Groq. The planned providers are:

- **Ollama:** run open-source models locally, allowing fully local or partially offline analysis and avoiding cloud API limits.
- **OpenRouter:** route requests through one API to access and switch between multiple model providers.
- **AgentRouter:** provide another configurable routing gateway for model selection and automated provider switching.

Each provider will expose the same auditor interface so OWASP, secrets, and business-logic analysis can continue using the existing prompt and JSON-result structure.

### Continue Analysis When a Provider Limit Is Reached

A future resume workflow will allow the pipeline to continue safely when the active provider reaches a quota or rate limit.

Planned behavior:

1. Pause the affected analysis stage without losing completed chunk results.
2. Save progress and the index of the last processed chunk.
3. Detect provider errors such as quota exhaustion, insufficient balance, rate limits, or unavailable models.
4. Ask the user to select a new provider and API key or continue with a local Ollama model.
5. Resume only the unfinished chunks instead of repeating the entire scan.
6. Merge all completed and resumed findings into the same `Final_JSON.json` output.

Example planned usage:

```bash
python3 Program.py --continue
python3 Program.py --url https://example.com --provider openrouter
python3 Program.py --url https://example.com --provider ollama --model llama3
```

The provider fallback and resume feature will support automatic fallback or manual selection. Automatic fallback may change models and provider costs, so provider rules and spending limits should be configurable by the user.
