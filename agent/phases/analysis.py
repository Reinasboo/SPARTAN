"""
SPARTAN v2.0 — Phase 2: Vulnerability Analysis
Systematic identification of all weaknesses.
Shannon integration: OWASP parallel analysis + Protocol Vulnerabilities Index for DeFi.
"""

from __future__ import annotations

import asyncio
import json as _json

from agent.knowledge.web2_vulns import WEB2_VULNERABILITIES
from agent.knowledge.web3_vulns import WEB3_VULNERABILITIES
from agent.knowledge.owasp import build_owasp_analysis_prompt
from agent.knowledge.protocol_vulns import detect_protocol_type, get_multi_protocol_checklist
from agent.tools.dataflow import build_dataflow_analysis_prompt
from config.prompts import PHASE_PROMPTS


# ── JSON output instruction appended to every analysis prompt ─────────────────

JSON_OUTPUT_INSTRUCTION = """
## ⚠️ CRITICAL OUTPUT FORMAT REQUIREMENT

You MUST output every finding as a JSON block inside triple backticks.
Plain-text finding descriptions are NOT accepted and will be ignored.

Each finding JSON block:
```json
{
  "title": "Short descriptive vulnerability title",
  "severity": "Critical|High|Medium|Low|Informational|Gas",
  "category": "Vulnerability class (e.g. Reentrancy, SQLi, IDOR)",
  "owasp_id": "e.g. A01:2021 or API1:2023 or SWC-107",
  "cwe": "CWE-XXX",
  "file_path": "path/to/file.sol",
  "line_number": 42,
  "vulnerable_snippet": "exact code line(s) containing the vulnerability",
  "attack_prerequisite": "What the attacker must have/control to exploit this",
  "impact_justification": "Concrete impact: what funds/data/access is at risk",
  "exploit_path": ["1. Attacker does X", "2. This causes Y", "3. Impact Z"],
  "cvss_score": 9.1,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "poc": "Foundry test / curl / Python script showing exploitation",
  "confidence": 85,
  "status": "CONFIRMED|DRAFT|UNCONFIRMED"
}
```

Rules:
- `file_path` + `line_number` + `vulnerable_snippet` are REQUIRED. Omit if you do not have them — do NOT guess.
- `status: "CONFIRMED"` only if you have traced the full exploit path end-to-end.
- `confidence` is your 0-100 self-assessment of certainty.
- If you cannot provide evidence, set `status: "DRAFT"` and `confidence: < 60`.
- Findings without `file_path`, `line_number`, AND `vulnerable_snippet` will be automatically discarded.
"""

ANALYSIS_CONTEXT_TEMPLATE = """
You are conducting Phase 2 Vulnerability Analysis on:

TARGET: {target}
ATTACK SURFACE (from Phase 1): {attack_surface_summary}

ADDITIONAL SCOPE / SOURCE CODE:
{context}

{dataflow_analysis}

{owasp_prompt}

## Web2 / API Vulnerability Checklist:
{web2_checks}

## Web3 / Smart Contract Checklist:
{web3_checks}

{protocol_checklist}

## Analysis Requirements:
For each potential vulnerability found:
1. State the vulnerability class, OWASP ID, and CWE/SWC ID
2. Identify the exact root cause (specific function, line, or logic)
3. Trace the full exploit path (attacker input → state change → impact)
4. Assess prerequisites (what does the attacker need?)
5. Assign preliminary severity (Critical/High/Medium/Low/Informational)
6. Self-assess confidence (0-100) — be honest, not optimistic

{json_output_instruction}

Be exhaustive. Check every trust boundary identified in Phase 1.
Think like an elite red team engineer running four parallel analysis agents simultaneously.
"""


# ── Parallel async OWASP agent runners ───────────────────────────────────────

OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable Components",
    "A07": "Authentication Failures",
    "A08": "Software Integrity Failures",
    "A09": "Logging Failures",
    "A10": "SSRF",
}

_OWASP_AGENT_TEMPLATE = """You are a specialized security agent focused ONLY on {category_id}: {category_name}.

Target: {target}
Source context:
{context}

Scan exclusively for {category_name} vulnerabilities in this code/system.
Output findings as JSON blocks per the format below.

{json_output_instruction}

If no findings for this category, output: []
"""


async def _run_single_owasp_agent(
    category_id: str,
    category_name: str,
    target: str,
    context: str,
) -> str:
    """Run one OWASP category agent asynchronously."""
    from agent.llm_client import chat
    prompt = _OWASP_AGENT_TEMPLATE.format(
        category_id=category_id,
        category_name=category_name,
        target=target,
        context=context[:3000],
        json_output_instruction=JSON_OUTPUT_INSTRUCTION,
    )
    messages = [
        {"role": "system", "content": PHASE_PROMPTS["analysis"]},
        {"role": "user", "content": prompt},
    ]
    loop = asyncio.get_event_loop()
    # run the synchronous chat() in a thread pool to avoid blocking
    return await loop.run_in_executor(None, chat, messages)


async def run_parallel_owasp_agents(
    target: str,
    context: str,
    categories: dict[str, str] | None = None,
) -> str:
    """
    Run all OWASP category agents concurrently using asyncio.gather().
    Returns combined JSON-block output from all agents.
    """
    cats = categories or OWASP_CATEGORIES
    tasks = [
        _run_single_owasp_agent(cid, cname, target, context)
        for cid, cname in cats.items()
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    parts = []
    for cid, result in zip(cats.keys(), results):
        if isinstance(result, Exception):
            continue
        if result and result.strip():
            parts.append(f"<!-- OWASP {cid} Agent Output -->\n{result}")
    return "\n\n".join(parts)


def run_parallel_owasp_agents_sync(
    target: str,
    context: str,
    categories: dict[str, str] | None = None,
) -> str:
    """Synchronous wrapper for run_parallel_owasp_agents."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Can't run nested event loops — fall back to sequential
            return ""
        return loop.run_until_complete(
            run_parallel_owasp_agents(target, context, categories)
        )
    except RuntimeError:
        return ""


# ── Builder functions ─────────────────────────────────────────────────────────

def build_analysis_prompt(
    target: str,
    attack_surface_summary: str,
    context: str = "",
    include_web2: bool = True,
    include_web3: bool = True,
    source_code: str | None = None,
) -> str:
    """Build the Phase 2 analysis prompt with OWASP and Protocol Vulnerabilities Index."""

    web2_checks = ""
    if include_web2:
        checks = [f"- [ ] {v.name} ({', '.join(v.cwe)})" for v in WEB2_VULNERABILITIES]
        web2_checks = "\n".join(checks)

    web3_checks = ""
    if include_web3:
        checks = [f"- [ ] {v.name} ({v.swc})" for v in WEB3_VULNERABILITIES]
        web3_checks = "\n".join(checks)

    # OWASP parallel analysis block
    owasp_prompt = build_owasp_analysis_prompt(include_api=include_web2)

    # DeFi Protocol Vulnerabilities Index
    protocol_checklist = ""
    if include_web3:
        combined_text = (target + " " + attack_surface_summary + " " + context).lower()
        detected_protocols = detect_protocol_type(combined_text)
        if detected_protocols:
            protocol_checklist = get_multi_protocol_checklist(detected_protocols)

    # Data flow analysis if source code provided
    dataflow_analysis = ""
    if source_code:
        dataflow_analysis = build_dataflow_analysis_prompt(source_code)

    return ANALYSIS_CONTEXT_TEMPLATE.format(
        target=target,
        attack_surface_summary=attack_surface_summary or "(Use Phase 1 context from conversation)",
        context=context or "(No source code provided — reason from target description and architecture)",
        dataflow_analysis=dataflow_analysis,
        owasp_prompt=owasp_prompt,
        web2_checks=web2_checks or "(Not applicable for this target)",
        web3_checks=web3_checks or "(Not applicable for this target)",
        protocol_checklist=protocol_checklist,
        json_output_instruction=JSON_OUTPUT_INSTRUCTION,
    )


def build_analysis_system_prompt() -> str:
    return PHASE_PROMPTS["analysis"]

