# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Defensive AI Audit Framework is a Python-based proof-of-concept that uses AI API calls to generate machine-specific defensive auditing scripts. Rather than running static checks on every machine, it collects a local system profile, sends it to an AI model, receives a tailored audit script, validates it for safety, and saves reports. This project is for authorized defensive security research and education only.

## Architecture

The framework runs entirely on a **controller machine** (non-vulnerable). Target machines (vulnerable machines) are only reached over SSH — no framework code runs on them directly.

Seven modules in `src/` with strict single-responsibility separation:

```
main.py
  ↓
target_connector.py  ← SSH → target: collect system info
  ↓
system_profile.py    ← parse remote data on controller
  ↓
prompt_builder.py
  ↓
ai_client.py         ← local LLM API on controller
  ↓
validator.py
  ↓
target_connector.py  ← SSH → target: execute validated script
  ↓
report_writer.py
```

- **`main.py`** — coordinator only; accepts target connection details, orchestrates all other modules, prints user summary
- **`target_connector.py`** — all SSH communication with remote targets; runs read-only enumeration commands to collect system info, transfers and executes validated scripts on the target, returns output to controller; must never execute a script that has not passed `validator.py`
- **`system_profile.py`** — parses raw remote command output from `target_connector.py` into a clean structured profile; must never request or parse credentials, tokens, keys, cookies, or browser history
- **`prompt_builder.py`** — builds system prompt (AI role + safety rules) and user prompt (structured profile + audit request); does not contact the API
- **`ai_client.py`** — sends prompts to local LLM API (on controller), parses response to structured JSON; API key loaded from environment variable only, never hardcoded
- **`validator.py`** — checks AI-generated code for blocked patterns before any execution; returns `{"approved": bool, "issues": [...], "warnings": [...]}`
- **`report_writer.py`** — produces the final **paginated PDF audit report** (cover page, system profile, findings, CVE section, appendices for prompts/AI response/validation/raw output) via `reportlab` or `fpdf2`; also exposes `extract_findings()` and `extract_cves()` helpers used by `main.py`. Supporting logs/JSON dumps may be saved to `reports/`, `logs/`, and `generated_scripts/` alongside the PDF

## Validator Blocked Patterns

`validator.py` must reject generated scripts containing: file deletion, credential/token/cookie collection, privilege escalation, persistence mechanisms, security tool disabling, suspicious shell commands, `eval()`/`exec()` misuse, unauthorized network connections, or destructive commands.

## Environment & API Keys

API keys must be loaded from environment variables or a local `.env` file. The `.gitignore` already excludes `.env` files. Never hardcode keys in source files.

## Scope Constraints

This project is defensive and read-only. Do not implement or suggest: exploitation, privilege escalation, credential theft, persistence, evasion, unauthorized scanning, or disabling security tools. All generated audit scripts must be read-only checks only.

## Development State

The project is in the planning phase — all `src/` files are currently empty placeholders. Feature branches exist for each original module (`feature/system-profiler`, `feature/ai-client`, `feature/validator`, `feature/prompt-builder`, `feature/report-writer`). A new branch should be created for `target_connector.py`. Implement each module on its corresponding feature branch.

## Output Directories

Generated scripts → `generated_scripts/`, reports → `reports/`, logs → `logs/`. These directories should be created if they don't exist; their contents are gitignored.
