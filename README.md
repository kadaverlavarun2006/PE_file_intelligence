# Sentinel PE

A local Flask application for static inspection of Windows PE executable (`.exe`) and dynamic-link library (`.dll`) files. Uploaded files are parsed with `pefile`; the application never executes them.

## Run locally

```powershell
<python> -m pip install -r requirements.txt
<python> app.py
```

Replace `<python>` with your Python interpreter. Open `http://127.0.0.1:5000/`. The upload limit is 100 MiB. Temporary upload files are created with unique names and removed after each request.

## Explainable threat heuristics

The static score is the sum of triggered rule weights, capped at 100. Severity bands are low (0–24), medium (25–49), high (50–74), and critical (75–100). Rules describe observed PE metadata, including selected imported API groups, packer-associated section names, section entropy of at least 7.2/8, writable/executable permissions, entry-point location, section count, large overlays, TLS callbacks, and machine/optional-header consistency. Every rule is returned with its trigger state, score impact, and explanation. These indicators can occur in legitimate software: heuristic findings do not prove malware, and a low score does not prove safety.

## Optional LLM explanation

The LLM integration is disabled unless `SENTINEL_LLM_API_KEY` is configured in the server environment before startup. It uses an OpenAI-compatible chat-completions endpoint by default; optionally set `SENTINEL_LLM_API_URL` and `SENTINEL_LLM_MODEL`. For example, in PowerShell:

```powershell
$env:SENTINEL_LLM_API_KEY = "<your API key>"
$env:SENTINEL_LLM_MODEL = "gpt-4o-mini"
<python> app.py
```

The API URL must use HTTPS; HTTP is permitted only for localhost services. When a user requests a summary, the server sends extracted metadata and triggered heuristic evidence to the configured provider. It does not send the binary, original filename, or file hash. The summary is advisory, may be inaccurate, and does not prove that a file is malicious or safe. No LLM provider is contacted when the feature is unconfigured or unused.

## API

`GET /api/status` reports upload limits and whether optional LLM summaries are configured.

`POST /api/analyze` accepts multipart form data with a `file` field. Successful responses include file size and SHA-256, architecture, entry-point RVA/VA, section metadata and entropy, imported DLLs and functions, an explainable weighted score, severity, and per-rule findings. Errors return a JSON `error` message with an appropriate HTTP status.

`POST /api/summarize` accepts JSON containing the prior analysis report and returns an advisory plain-text LLM summary. It returns `503` while LLM summaries are not configured.

This is static metadata inspection, not an antivirus engine or a sandbox. Uploaded files are never executed. Run the service only on a trusted machine and keep Flask and `pefile` dependencies updated; parsing untrusted files can still expose parser vulnerabilities.
"# PE_file_intelligence" 
