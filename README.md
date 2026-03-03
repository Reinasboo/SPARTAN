# SPARTAN v2.0 — Autonomous Security Audit & Exploit Agent

```
   _______  ___  ____  ____  ___   _  _
  / __/ _ \/ _ |/ __ \/_  / / _ | / \/ |
  \__ \/ ___/ __ / /_/ //_ < / __ |/ , |
 /___/_/  /_/ |_\____/____//_/ |_/_/|_|
```

> **"Think like an attacker. Report like an auditor. Build like an engineer."**

SPARTAN is an autonomous AI security research agent for authorized penetration testing, bug bounty hunting, and smart-contract auditing. It orchestrates a structured 5-phase methodology, maintains persistent session memory, and produces submission-ready professional reports.

---

## What SPARTAN Does

| Capability | Details |
|---|---|
| **Attack Surface Mapping** | Enumerates all endpoints, entry points, roles, trust boundaries |
| **Threat Modeling** | Identifies threat actors, key assumptions, and high-risk components |
| **Vulnerability Analysis** | Full Web2 + Web3 taxonomy — 25+ vulnerability classes + OWASP Top 10 |
| **Recon Tool Generation** | Ready-to-run Nmap, Subfinder, WhatWeb, and Schemathesis commands |
| **Exploit Validation** | Safe, local PoC generation — Playwright browser scripts, curl templates, Python |
| **Dataflow Analysis** | Source-to-sink taint analysis for injection and XSS vulnerability detection |
| **Protocol Checklists** | DeFi-specific vulnerability checklists for 12+ protocol types |
| **Report Generation** | Submission-ready Markdown reports with CVSS v3.1 scoring |
| **Remediation Review** | Validates applied fixes, checks for regressions |
| **Session Persistence** | Full audit workspace saved to disk, resumable at any time |
| **Multi-Provider LLM** | Works with OpenAI, Anthropic, or OpenRouter |
| **YAML Audit Config** | Declarative `.yaml` config files for repeatable, scripted audits |

---

## Audit Domains

- Web Applications (REST, GraphQL, WebSockets, SPAs)
- APIs & Backends (auth flows, business logic, rate limiting)
- Smart Contracts (Solidity, Vyper, EVM bytecode reasoning)
- DeFi Protocols (AMMs, lending, vaults, bridges, staking)
- Account Abstraction (ERC-4337 bundler/paymaster/wallet)
- Governance & DAOs (voting, timelocks, proposal flows)
- L2 & Cross-Chain (sequencer risks, bridges, finality)
- Cryptographic Systems (signatures, ZK circuits, key management)
- Authentication Systems (OAuth2, JWT, SAML, MFA bypass, TOTP/2FA)

---

## 5-Phase Methodology

```
Phase 1 — Recon        → Attack Surface Map + Threat Model + Recon Tool Commands
Phase 2 — Analysis     → OWASP Top 10 + Protocol Checklists + Dataflow Analysis
Phase 3 — Validation   → Playwright/curl PoC generation + CVSS v3.1 scoring
Phase 4 — Report       → Submission-ready Markdown reports
Phase 5 — Remediation  → Fix verification + regression check
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Set your API key

```bash
# Copy the example config
copy .env.example .env

# Edit .env and set your API key:
# OPENAI_API_KEY=sk-...        (for OpenAI)
# ANTHROPIC_API_KEY=sk-ant-... (for Anthropic)
# OPENROUTER_API_KEY=sk-or-... (for OpenRouter)
```

Or set environment variables directly:

```powershell
# Windows PowerShell
$env:OPENAI_API_KEY = "sk-..."
$env:SPARTAN_LLM_PROVIDER = "openai"
$env:SPARTAN_LLM_MODEL = "gpt-4o"

# Or use Gemini
$env:GEMINI_API_KEY = "AIza..."
$env:SPARTAN_LLM_PROVIDER = "gemini"
$env:SPARTAN_GEMINI_MODEL = "gemini-2.0-flash"
```

### 3. Run SPARTAN

```bash
# Interactive mode (recommended)
python main.py

# Start with a target immediately
python main.py --target "UniswapV3 fork vault contract"

# Start with a source file
python main.py --target "MyVault" --file contracts/Vault.sol

# Load a YAML audit config (see example-audit-config.yaml)
python main.py --config audit.yaml

# Use Anthropic Claude
python main.py --provider anthropic

# Use Google Gemini
python main.py --provider gemini

# Resume last session
python main.py --resume
```

---

## Audit Config Files

For repeatable, scripted audits, define the full scope in a YAML file and pass it with `--config`:

```bash
python main.py --config example-audit-config.yaml
```

The config file controls:

| Section | Key Options |
|---|---|
| `scope` | `url`, `repo`, `openapi_path`, `protocol_type`, `contract_addresses`, `chain_id` |
| `authentication` | `login_type` (`none` \| `form` \| `api_key` \| `bearer_token` \| `basic` \| `oauth` \| `web3` \| `totp`), credentials via env vars, multi-step `login_flow` |
| `rules` | `include_owasp_top10`, `include_api_security_top10`, `include_web3_vulns`, `include_protocol_vulns`, `no_exploit_no_report`, `max_severity_to_report`, `focus`, `avoid`, `custom_checklist` |
| `pipeline` | `max_concurrent_agents`, `timeout_per_phase_seconds`, `retry_on_failure`, `auto_advance_phases`, `stream_output`, `save_intermediate`, `retry_preset` |
| `auditor_notes` | Free-text context injected into each phase prompt |
| `known_issues` | Pre-known areas of concern to prioritize |

See [example-audit-config.yaml](example-audit-config.yaml) for a fully-annotated template covering both web-app and DeFi targets.

---

## Interactive Commands

| Command | Action |
|---|---|
| `target <name>` | Set or change the audit target |
| `phase <name>` | Jump to Recon / Analysis / Validation / Report / Remediation |
| `continue` | Advance to the next phase |
| `status` | Show session summary (findings, phase, target) |
| `report` | Generate full Markdown audit report |
| `findings` | List all findings in this session |
| `finding <id>` | Show details of FINDING-001, FINDING-002, etc. |
| `sessions` | List all saved sessions |
| `load <id>` | Load a previous session by ID |
| `save` | Force-save current session |
| `clear` | Clear conversation history (keeps findings) |
| `model` | Show active LLM model |
| `help` | Show all commands |
| `exit` | Save and exit |

---

## Usage Examples

### Audit a Solidity smart contract

```
> python main.py --target "StakingVault" --file contracts/StakingVault.sol

[Recon]> continue
[Analysis]> continue
[Validation]> continue
[Report]> report
```

### Bug bounty web app audit

```
> python main.py

[SPARTAN]> target https://api.example.com
[Recon]>   The API uses JWT auth with RS256. Admin panel at /admin.
           REST endpoints: /api/v1/users, /api/v1/orders, /api/v1/upload
[Analysis]> continue
[Validation]> continue
[Report]> report
```

### Scripted audit with YAML config

```
> python main.py --config my-audit.yaml

[Recon]> continue
[Analysis]> continue
[Validation]> continue
[Report]> report
```

### Resume a previous session

```
> python main.py --sessions
ID         Target                          Phase           Findings   Last Active
──────────────────────────────────────────────────────────────────────────────────
a1b2c3d4   StakingVault                   Analysis        3          2026-03-03 09:15

> python main.py --load a1b2c3d4
```

---

## Shannon Integration — What's New

SPARTAN v2.0 incorporates Shannon's multi-agent analysis and live exploitation capabilities:

### Recon Tool Commands (`agent/tools/recon_tools.py`)

SPARTAN generates operator-ready shell commands during Phase 1:

| Tool | Purpose |
|---|---|
| **Nmap** | Port/service discovery — default, deep, UDP, vuln-script, and web modes |
| **Subfinder** | Passive subdomain enumeration with optional DNS resolution |
| **WhatWeb** | Technology fingerprinting (frameworks, CMS, server headers) |
| **Schemathesis** | OpenAPI schema-driven API fuzzing — auth-token-aware |

Commands are printed as annotated blocks (tool, flags, expected output) for the operator to copy-run. SPARTAN never executes them automatically.

### Web Exploit Templates (`agent/tools/web_exploits.py`)

Payload banks and PoC generators with enforced safety levels:

| PoC Type | Safety | Description |
|---|---|---|
| `build_playwright_script()` | LOCAL | Headless browser PoC for XSS, IDOR, CSRF, auth bypass |
| `build_curl_poc()` | LOCAL/SAFE | curl reproduction steps for SQLi, SSRF, file traversal, etc. |
| Payload banks | — | SQLi (error/blind/time), XSS, SSTI, SSRF, CMDi, path traversal |

Every `PoC` object carries a `PoCSafety` label (`SAFE` / `LOCAL` / `SIMULATED`) and a formatted `.format()` method for inclusion in reports.

### Dataflow Analysis (`agent/tools/dataflow.py`)

Static taint analysis over source code snippets:

- Detects **20+ source patterns** (request params, headers, cookies, DB reads, env vars, file reads)
- Detects **20+ sink patterns** (SQL queries, `eval`, `exec`, `render`, `mark_safe`, `innerHTML`, shell commands)
- Returns per-finding severity, source type, sink type, and matched code line
- `build_dataflow_prompt()` wraps analysis into a structured LLM prompt for Phase 2

### OWASP Knowledge Base (`agent/knowledge/owasp.py`)

- Full **OWASP Top 10 (2021)** — A01 through A10 with payload examples per category
- Full **OWASP API Security Top 10 (2023)** — API01 through API10
- `search_owasp(query)` — keyword search across IDs, names, and categories
- `build_owasp_prompt(include_api=True)` — injects OWASP context into Phase 2 analysis prompts

### Protocol Vulnerability Checklists (`agent/knowledge/protocol_vulns.py`)

DeFi-specific checklist library for 12 protocol types:

`lending` · `dexes` · `bridge` · `oracle` · `governance` · `algo-stables` · `liquid-staking` · `yield-aggregator` · `staking-pool` · `cdp` · `nft-marketplace` · `account-abstraction`

- `detect_protocol_type(description)` — auto-detects protocol type from free text
- `get_protocol_checklist(protocol_type)` — returns the full checklist for a given type
- `get_multi_protocol_checklist(types)` — combines checklists for multi-protocol targets

### "No Exploit, No Report" Policy

Controlled via `rules.no_exploit_no_report: true` in the audit config. When enabled, the final report only includes findings that have a confirmed `PoC` object attached. Unconfirmed findings are downgraded in severity and flagged as requiring further validation.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SPARTAN_LLM_PROVIDER` | `openai` | LLM provider: `openai` \| `anthropic` \| `openrouter` \| `gemini` |
| `SPARTAN_LLM_MODEL` | `gpt-4o` | Model name for OpenAI |
| `SPARTAN_ANTHROPIC_MODEL` | `claude-opus-4-5` | Model name for Anthropic |
| `SPARTAN_GEMINI_MODEL` | `gemini-2.0-flash` | Model name for Gemini (`gemini-2.0-flash` \| `gemini-2.5-pro-preview-03-25`) |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `OPENROUTER_API_KEY` | — | OpenRouter API key |
| `GEMINI_API_KEY` | — | Google Gemini API key (get one at [aistudio.google.com](https://aistudio.google.com)) |
| `SPARTAN_MAX_TOKENS` | `8192` | Max tokens per response |
| `SPARTAN_TEMPERATURE` | `0.2` | LLM temperature |
| `SPARTAN_STREAM` | `true` | Stream output in real-time |
| `SPARTAN_SAVE_SESSIONS` | `true` | Auto-save session state |

---

## Project Structure

```
Spartan/
├── main.py                        # CLI entry point (--config/-c flag)
├── requirements.txt
├── .env.example
├── example-audit-config.yaml      # Annotated YAML config template
├── sessions/                      # Auto-saved session files
├── reports/                       # Generated audit reports
├── tests/                         # Test suite — 244 tests, all passing
│   ├── test_session.py            # Session + Finding data models (26 tests)
│   ├── test_cvss.py               # CVSS v3.1 scoring engine (29 tests)
│   ├── test_knowledge.py          # protocol_vulns + OWASP knowledge bases (35 tests)
│   ├── test_tools.py              # Recon tools + web exploits + dataflow (58 tests)
│   ├── test_phases.py             # Phase prompt builders (33 tests)
│   └── test_spartan.py            # SpartanAgent orchestration (35 tests)
├── config/
│   ├── settings.py                # All configuration & constants
│   ├── prompts.py                 # System prompts for each phase
│   └── audit_config.py            # YAML audit config parser & dataclasses
└── agent/
    ├── spartan.py                 # Core SpartanAgent class
    ├── session.py                 # Session & finding data models
    ├── llm_client.py              # Multi-provider LLM abstraction
    ├── formatter.py               # Terminal output formatting
    ├── phases/
    │   ├── recon.py               # Phase 1 — Reconnaissance + recon tool injection
    │   ├── analysis.py            # Phase 2 — OWASP + protocol checklist + dataflow
    │   ├── validation.py          # Phase 3 — PoC generation + CVSS scoring
    │   ├── report.py              # Phase 4 — Report generation
    │   └── remediation.py         # Phase 5 — Remediation review
    ├── tools/
    │   ├── recon_tools.py         # Nmap / Subfinder / WhatWeb / Schemathesis builders
    │   ├── web_exploits.py        # Playwright PoCs, curl templates, payload banks
    │   └── dataflow.py            # Source-to-sink taint analysis engine
    └── knowledge/
        ├── web2_vulns.py          # Web2/API vulnerability taxonomy
        ├── web3_vulns.py          # Web3/DeFi vulnerability taxonomy
        ├── protocol_vulns.py      # DeFi protocol-specific checklists (12 types)
        ├── owasp.py               # OWASP Top 10 (2021) + API Security Top 10 (2023)
        └── cvss.py                # CVSS v3.1 scoring engine
```

---

## Running Tests

```bash
# Run the full test suite
python -m pytest tests/ -v

# Run a specific module
python -m pytest tests/test_tools.py -v

# Short summary only
python -m pytest tests/ --tb=short
```

Expected: **244 passed** in under 3 seconds (all tests are offline — no LLM calls).

---

## Ethical & Legal Notice

SPARTAN operates under strict ethical guardrails that **cannot be overridden**:

- **Authorization required** — Only test systems you are explicitly authorized to test
- **No live production exploits** — All PoCs are safe, local, forked, or simulated
- **No real data exfiltration** — PoCs prove access, they do not extract real user data
- **No malware generation** — PoCs demonstrate vulnerability class, not weaponized payloads
- **Authorized use only** — Bug bounty programs, CTFs, authorized red team engagements, security research

---

*SPARTAN v2.0 — Built for elite security research. Authorized contexts only.*
