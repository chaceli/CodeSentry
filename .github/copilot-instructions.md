# CodeSentry — Copilot / AI agent instructions

Purpose: Short, actionable guidance to help AI coding agents be productive in this repository.

## Quick commands ✅
- Install deps: `pip install -r requirements.txt`
- Run unit tests: `python -m unittest discover` (tests use `unittest`) or `pytest` if available
- Run CLI scan: `python -m cli.main scan <path>`
  - Exit codes: `0` ok, `2` found high/critical vulnerabilities
- Configure AI: `cp .env.example .env` and set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` (see `config/settings.py`)

## High-level architecture (big picture) 🔧
- `core/` — parsing and static analysis
  - `core/parser.py` — Tree-sitter based C/C++ parsing helpers (`parser.parse_content`, `get_calls`, `get_functions`, `get_code_snippet`)
  - `core/analyzer.py` — two-stage detection: regex `VULNERABILITY_PATTERNS` (fast) + AST checks (Tree-sitter)
  - `core/models.py` — dataclasses (`Vulnerability`, `Location`, `ScanResult`) and enums (`Severity`, `VulnerabilityType`)
- `ai/` — LLM integrations & validation
  - `ai/engine.py` — `AIEngine` wrapper, `OpenAIEngine` and `ClaudeEngine`; relies on env keys; prompts expect a strict `VERDICT/ANALYSIS/RISK_LEVEL/SUGGESTED_FIX` format
  - `ai/validator.py` — calls `ai_engine.verify_vulnerability` and updates `Vulnerability` fields (confidence, ai_verified, fix_suggestion)
- `output/` — reporting
  - `output/reporter.py` supports `text`, `json`, `sarif` output formats
- `cli/` — command entrypoint (`cli/main.py`)
- `config/` — runtime/config (see `config/settings.py`) for env-driven behavior
- `utils/` — logging (`utils/logger.py`) and other helpers

## Project-specific conventions & patterns 📐
- Singletons: `parser`, `analyzer`, `ai_engine`, `validator` are module-level singletons; use existing instance APIs instead of creating duplicates.
- Add rules in `core/analyzer.py` inside `VULNERABILITY_PATTERNS` with fields: `id`, `type` (use `VulnerabilityType`), `severity` (`Severity`), `title`, `pattern`, `message`.
  - Example: add a regex pattern and add a unit test in `tests/test_core.py` plus a sample in `tests/samples/`.
- AST checks rely on `parser.get_calls` and `parser.get_code_snippet` — when writing AST logic, use those helpers and return `Vulnerability` objects matching `core/models.py`.
- AI responses are parsed by exact prefixes (e.g., lines starting with `VERDICT:`). Keep prompts and parsing robust and tolerant of minor deviations.
- Configuration via env vars: `AI_ENABLED`, `DEFAULT_MODEL`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `RECURSIVE_SCAN`, etc. Check `config/settings.py` for exact names.

## Testing and CI guidance 🧪
- Update `tests/test_core.py` when changing detection behavior; tests use `unittest` assertions and sample files under `tests/samples/`.
- For new rules, include a concise sample C file demonstrating the issue in `tests/samples/` and an assertion that detection occurs.
- CLI behaviors worth asserting: `--no-ai` skips AI validation; `--format` supports `text|json|sarif`.

## Integration & dependency notes ⚠️
- Tree-sitter is required (`tree_sitter` and `tree_sitter_languages` packages). Use `get_language("c")` for parsing C.
- LLM usage: code will raise if API key expected by engine implementation is missing (OpenAIEngine/ClaudeEngine constructors). `AIEngine` will fallback to `None` gracefully — validator will skip AI if not available.
- Log usage: use the shared `log` from `utils/logger.py` (already configured with console + daily rotating file)

## Practical examples / do this when changing code 💡
- To add a new detection:
  1. Add pattern to `VULNERABILITY_PATTERNS` in `core/analyzer.py` (or implement AST check)
  2. Add sample to `tests/samples/` demonstrating the issue
  3. Add test in `tests/test_core.py` to assert detection
  4. Run `python -m unittest discover` and fix failures
- To add AI verification behavior:
  - Update `ai/engine.py` prompt and parsing; add unit tests that mock `ai_engine.verify_vulnerability` returning expected dicts and assert `validator.validate_result` updates vulnerabilities accordingly

## Important gotchas 🎯
- Regex rules can produce false positives; AI validator adjusts `confidence` and `severity` based on `verdict`.
- Code snippets are line-indexed; `parser.get_code_snippet` uses 0-based start/end tuple (start_point/end_point)
- AI parsing expects exact prefixes; prefer structured outputs (VERDICT/ANALYSIS/RISK_LEVEL/SUGGESTED_FIX)

---
If any part is unclear (missing files, behavior you expect covered), tell me which area to expand and I'll iterate. 🙋‍♂️
