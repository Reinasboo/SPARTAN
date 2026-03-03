"""
SPARTAN v2.0 — Phase 2: Vulnerability Analysis
Systematic identification of all weaknesses.
Shannon integration: OWASP parallel analysis + Protocol Vulnerabilities Index for DeFi.
"""

from __future__ import annotations

from agent.knowledge.web2_vulns import WEB2_VULNERABILITIES
from agent.knowledge.web3_vulns import WEB3_VULNERABILITIES
from agent.knowledge.owasp import build_owasp_analysis_prompt
from agent.knowledge.protocol_vulns import detect_protocol_type, get_multi_protocol_checklist
from agent.tools.dataflow import build_dataflow_analysis_prompt
from config.prompts import PHASE_PROMPTS


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
6. Mark certainty: CONFIRMED | [UNCONFIRMED — NEEDS VALIDATION]
7. Per Shannon policy: UNCONFIRMED findings will be excluded from final report unless PoC provided

## Format each finding as:
### Potential Finding: <Title>
**Class:** <vulnerability type>
**OWASP ID:** <e.g., A01:2021 or API1:2023>
**CWE/SWC:** <ID>
**Location:** <specific function/endpoint/line>
**Root Cause:** <technical explanation>
**Exploit Path:** <step by step>
**Prerequisites:** <what attacker needs>
**Preliminary Severity:** <severity>
**Status:** CONFIRMED | [UNCONFIRMED — NEEDS VALIDATION]
**Notes:** <anything else relevant>

Be exhaustive. Check every trust boundary identified in Phase 1.
Think like an elite red team engineer running four parallel analysis agents simultaneously.
"""


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
    )


def build_analysis_system_prompt() -> str:
    return PHASE_PROMPTS["analysis"]
