# LogAnalyser
Small local web app to analyze Linux **Logwatch** reports with an Ollama-hosted LLM.

![Log Analyser Main](/assets/loganalyser1.png "Log Analyser main")

## Purpose

This project helps you understand Logwatch output faster by turning long service sections into:

- prioritized findings (critical/high/medium/low when possible)
- likely root causes in plain language
- security-relevant signals (failed logins, suspicious patterns, privilege issues)
- practical next investigation/fix actions
- evidence-backed findings with chunk/source references

It is designed for local/private usage: logs stay on your machine.

## How It Works
![Log Analyser log file updated](/assets/loganalyser2.png "Log Analyser log file updated")

1. Upload a `.log` or `.txt` file in the web UI.

2. Choose a profile to analyse. 

![Log Analyser profiles](/assets/loganalyser3.png "Log Analyser profiles")

2. The backend detects Logwatch section boundaries (`--- ... Begin ---`) and builds event-aware chunks.

3. Each chunk is analyzed by an Ollama model through `langchain-ollama` and converted to structured JSON findings.

4. A second-pass reducer deduplicates and prioritizes findings across all chunks.
5. Results are shown as:
    - a structured sortable table (severity, service, confidence, evidence, actions, sources)
    - a narrative Markdown report
6. You can export results as:
    - `.md` (editable, versionable)
    - PDF (formatted print/export from browser)

![Log Analyser profiles](/assets/loganalyser4.png "Log Analyser profiles")

## Tech Stack

- FastAPI
- LangChain (`langchain-ollama`, `langchain-text-splitters`)
- Ollama (local model serving)
- Simple HTML/CSS/JS frontend (offline-safe built-in Markdown renderer)

## Project Structure

- `app.py`: FastAPI app and `/analyse` endpoint with profile support
- `operations.py`: Logwatch-aware chunking, first-pass chunk analysis, and second-pass reducer
- `models.py`: Ollama model configuration
- `prompt.py`: profile-specific prompts + reducer prompt
- `static/index.html`: frontend UI with structured table, sorting, dark mode, print styles, and export actions

## Requirements

- Python 3.11+ (project currently runs in a local venv)
- Ollama installed and running
- At least one local model pulled in Ollama

## Install

1. Create and activate a virtual environment (if needed).
2. Install Python dependencies:

```bash
pip install fastapi uvicorn python-multipart langchain-ollama langchain-text-splitters
```

3. Install Ollama (Linux):

We have several options to install Ollama:
- Using a script
- Using docker
    - docker with CUDA support (highly recommended)

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Official docs:
- Linux install: https://docs.ollama.com/linux
- Quickstart: https://docs.ollama.com/quickstart

## Ollama Setup

Start Ollama:

```bash
ollama serve
```

Or run [Ollama with Docker](https://hub.docker.com/r/ollama/ollama) (example with CUDA support):

**note**: You need to have *nvidia-container-toolkit* installed

```bash
docker run -d --gpus=all --name ollama -p 11434:11434 -v ollama:/root/.ollama ollama/ollama
```

In another terminal, pull a model:

```bash
ollama pull mistral
```

If using Docker, pull the model inside the container:

```bash
docker exec -it ollama ollama pull mistral
```

The code currently defaults to:

```python
model="mistral:7b-instruct-v0.3-q8_0"
```

If that exact tag is not available locally, update `models.py` to a tag you have (for example `mistral:latest`).

## Model Recommendations (Logwatch Analysis)

There is no single best model for every machine. Use this practical tiering:

1. **Balanced default (most users):** `mistral` (7B)
- Good instruction following for incident-style summaries
- Fast enough on CPU/GPU for iterative log review
- Small memory footprint compared to larger models

2. **Low-resource machines:** `gemma3:4b` (or smaller Gemma3 variants)
- Lower RAM/VRAM requirement
- Useful when you prioritize speed and local compatibility

3. **Higher reasoning depth (slower):** `deepseek-r1:8b` or `deepseek-r1:14b`
- Better multi-step reasoning in complex incident chains
- Usually slower, with higher memory requirements

4. **Higher quality with more hardware:** `llama3.1:8b` (and above)
- Strong general instruction and long-context performance
- Better output quality at increased compute cost

Notes:
- For this app, non-coding general instruction models are usually better than coder-focused models.
- Keep temperature low (current config uses `0.15`) for stable, repeatable findings.

## Run the App

```bash
uvicorn app:app --reload
```

Open:

`http://127.0.0.1:8000`

## Analysis Profiles

You can choose one of the built-in profiles from the UI before running analysis:

- `general`: balanced incident triage across service and security signals
- `security`: threat-focused analysis (auth abuse, suspicious behavior, escalation attempts)
- `service_health`: reliability/availability-focused analysis
- `compliance`: audit/evidence-oriented analysis

Profiles change prompt focus while keeping the same output schema.

## Export Formats: Markdown vs PDF

- **Markdown (`.md`)**: best for editing, Git history, and collaboration in tools like VS Code/GitHub.
- **PDF**: best for fixed formatting and sharing with non-technical stakeholders.

Recommended workflow:
1. Save `.md` as your source of truth.
2. Export PDF when you need a finalized report.

## Tuning Tips

- If analyses feel too brief, increase `num_predict` in `models.py`.
- If model output drifts or gets creative, keep temperature low (`0.1` to `0.2`).
- If logs are very large, keep chunking event-aware (already implemented in `operations.py`).
- If chunk-level findings are repetitive, keep the reducer pass enabled (default behavior).

## License

This project is free software released under the **GNU General Public License v3.0 or later (GPL-3.0-or-later)**.

See `LICENSE` for the full text.

## References

- Ollama docs: https://docs.ollama.com/
- Ollama Linux install: https://docs.ollama.com/linux
- Ollama model library: https://ollama.com/search
- Mistral model page: https://ollama.com/library/mistral
- Gemma 3 model page: https://ollama.com/library/gemma3
- DeepSeek-R1 model page: https://ollama.com/library/deepseek-r1
- Llama 3.1 model page: https://ollama.com/library/llama3.1
- LangChain `ChatOllama`: https://api.python.langchain.com/en/latest/ollama/chat_models/langchain_ollama.chat_models.ChatOllama.html
