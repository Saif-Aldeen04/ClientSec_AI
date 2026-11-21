# ClientSec AI

## Requirements

- Python 3.10 or newer
- A Groq API key
- Internet access

## Get a Groq API Key

1. Open the Groq Console: https://console.groq.com/keys
2. Sign in or create a Groq account.
3. Open **API Keys**.
4. Select **Create API Key**.
5. Give the key a name and copy it.

Keep the key private. Do not commit it to GitHub or share it with anyone.

## Download and Install

```bash
git clone https://github.com/Saif-Aldeen04/ClientSec_AI.git
cd ClientSec_AI

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install groq beautifulsoup4 esprima httpx streamlit pandas plotly jsbeautifier
```

On Windows:

```powershell
git clone https://github.com/Saif-Aldeen04/ClientSec_AI.git
cd ClientSec_AI

py -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install groq beautifulsoup4 esprima httpx streamlit pandas plotly jsbeautifier
```

### Installed Libraries

- `groq`: connects the auditors to Groq AI APIs.
- `beautifulsoup4`: parses HTML and extracts JavaScript-related content.
- `esprima`: statically parses JavaScript and extracts code structures.
- `httpx`: performs the crawler's asynchronous HTTP requests.
- `streamlit`: runs the interactive security dashboard.
- `pandas`: processes and organizes dashboard data.
- `plotly`: creates dashboard charts and visualizations.
- `jsbeautifier`: formats JavaScript before analysis and chunking.

## Configure the Groq API Key

Create a file named `api.txt` in the project directory and add the key using this format:

```text
Groq: gsk_your_api_key_here
```


## Interactive Run

```bash
python3 Program.py
```

The program will hide the API key while you enter it, and then ask for the target website URL.

## Direct Run

```bash
python3 Program.py --url https://example.com
```

You can also specify limits and confirm authorization:

```bash
python3 Program.py --url https://example.com --confirm-authorized --depth 2 --max-pages 50
```

## Run Dashboard Only (No Re-Scan)

If `Output/Final_JSON.json` already exists, you can launch the dashboard directly without running the full pipeline again:

```bash
python3 Program.py --dashboard-only
```

## Notes

- Only scan websites that you are authorized to test.
- The `Output` directory is created automatically during a run.
- After the pipeline finishes and `Output/Final_JSON.json` is created, the local dashboard starts automatically.
- The terminal prints the localhost URL and opens it in your default browser.
