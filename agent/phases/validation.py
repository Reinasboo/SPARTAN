"""
SPARTAN v2.0 — Phase 3: Exploit Validation (Safe PoC Mode)
Shannon integration: Playwright browser automation, cURL PoCs, "No Exploit No Report" enforcement.
"""

from __future__ import annotations

from agent.tools.web_exploits import (
    build_playwright_script,
    build_curl_poc,
    SQL_INJECTION_PAYLOADS,
    XSS_PAYLOADS,
    SSRF_PAYLOADS,
    COMMAND_INJECTION_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    enforce_no_exploit_no_report,
    PoCSafety,
)
from config.prompts import PHASE_PROMPTS


VALIDATION_CONTEXT_TEMPLATE = """
You are conducting Phase 3 Exploit Validation on:

TARGET: {target}
FINDINGS FROM PHASE 2:
{findings_summary}

ADDITIONAL CONTEXT:
{context}

## SHANNON "NO EXPLOIT, NO REPORT" ENFORCEMENT
Every finding included in the final report MUST have confirmed reproduction evidence.
Findings without PoC evidence are labeled [UNCONFIRMED] and EXCLUDED from the report.

## BROWSER AUTOMATION PAYLOADS (Shannon Integration)

### XSS Detection Payloads — Inject into all string parameters:
{xss_payloads}

### SQL Injection Payloads — Auth bypass and time-based blind:
{sqli_payloads}

### SSRF Payloads — Submit to all URL-accepting parameters:
{ssrf_payloads}

### Command Injection — Shell metacharacter injection:
{cmdi_payloads}

### Path Traversal — File system escape:
{path_payloads}

## PoC GENERATION REQUIREMENTS (Shannon-style)

For **web app vulnerabilities**, provide:
1. **Playwright Python script** (browser-automated PoC) — for XSS, IDOR, auth bypass, CSRF
2. **cURL command** (HTTP-level PoC) — for injection, SSRF, JWT attacks, header manipulation
3. Safety label: [PoC — SAFE] / [PoC — LOCAL] / [PoC — SIMULATED]

For **smart contract vulnerabilities**, provide:
1. **Foundry test** in Solidity — for reentrancy, flash loans, MEV
2. **cast command** — for access control checks
3. **Python web3.py script** — for oracle manipulation, governance attacks

## PoC Template:
```
[PoC — SAFE/LOCAL/SIMULATED]
// Target: <function/endpoint>
// Vulnerability: <type>  
// OWASP: <ID>
// Impact: <what an attacker achieves>
// Prerequisites: <what the attacker needs>
// CVSS v3.1: <score> (<vector>)

<Playwright script / cURL / Foundry test>

// Expected result: <output/state>
// Evidence: <what to look for>
// Attacker outcome: <impact>
```

Platform severity assignment per confirmed finding:
- Immunefi: Critical ($10k-$X00k) / High / Medium / Low
- HackerOne: P1 (Critical) / P2 (High) / P3 (Medium) / P4 (Low) / P5 (Informational)
- Code4rena/Sherlock: High / Medium / Low / Informational

Start with highest-severity findings first.
"""


def build_validation_prompt(
    target: str,
    findings_summary: str,
    context: str = "",
) -> str:
    """Build the Phase 3 validation prompt with Shannon exploitation templates."""

    xss_payloads = "\n".join(f"  {p}" for p in XSS_PAYLOADS["basic"][:5])
    sqli_payloads = "\n".join(f"  {p}" for p in SQL_INJECTION_PAYLOADS["auth_bypass"][:4])
    ssrf_payloads = "\n".join(f"  {p}" for p in SSRF_PAYLOADS[:5])
    cmdi_payloads = "\n".join(f"  {p}" for p in COMMAND_INJECTION_PAYLOADS[:5])
    path_payloads = "\n".join(f"  {p}" for p in PATH_TRAVERSAL_PAYLOADS[:4])

    return VALIDATION_CONTEXT_TEMPLATE.format(
        target=target,
        findings_summary=findings_summary or "(Summarize findings from Phase 2 analysis)",
        context=context or "(No additional context)",
        xss_payloads=xss_payloads,
        sqli_payloads=sqli_payloads,
        ssrf_payloads=ssrf_payloads,
        cmdi_payloads=cmdi_payloads,
        path_payloads=path_payloads,
    )


def build_web_validation_prompt(target: str, vuln_type: str, parameter: str = "") -> str:
    """Generate a specific browser-based PoC for a web vulnerability type (Shannon integration)."""
    poc = build_playwright_script(
        vuln_type=vuln_type,
        target_url=target,
        parameter=parameter,
        safety=PoCSafety.SIMULATED,
    )
    return poc.format()


def build_web3_validation_prompt(
    target: str,
    findings_summary: str,
    context: str = "",
) -> str:
    """Build Web3-specific validation prompt for smart contract findings."""
    return f"""You are conducting Phase 3 Smart Contract Exploit Validation on:

TARGET: {target}
FINDINGS: {findings_summary}

## SMART CONTRACT PoC REQUIREMENTS

For each finding, provide one of:
1. **Foundry Test** (preferred):
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract ExploitTest is Test {{
    // Setup + exploit code
    function testExploit() public {{
        // [PoC — SIMULATED / FORKED-MAINNET]
        // Impact: <X ETH / tokens drained>
    }}
}}
```

2. **cast command** (for quick state probes):
```bash
cast call <contract> "function(args)" --rpc-url $RPC_URL
```

3. **Python web3.py** (for complex multi-step attacks):
```python
from web3 import Web3
# [PoC — SAFE/SIMULATED]
```

Additional context: {context or "(None)"}
"""


def build_validation_system_prompt() -> str:
    return PHASE_PROMPTS["validation"]


POC_HEADER = "[PoC — SAFE/LOCAL/SIMULATED]"
UNCONFIRMED_LABEL = "[UNCONFIRMED — NEEDS VALIDATION]"
CONFIRMED_LABEL = "[CONFIRMED — INCLUDED IN REPORT]"
EXCLUDED_LABEL = "[UNCONFIRMED — EXCLUDED FROM REPORT per No-Exploit-No-Report policy]"
