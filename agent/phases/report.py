"""
SPARTAN v2.0 — Phase 4: Report Generation
Produces submission-ready, professional audit reports.
Platform-aware: immunefi | hackerone | code4rena | internal (default)
"""

from __future__ import annotations
from datetime import datetime, timezone

from config.prompts import PHASE_PROMPTS
from config.settings import REPORTS_DIR


# ── Platform-specific report templates ───────────────────────────────────────

_IMMUNEFI_HEADER = """
## Immunefi Submission Format

**Vulnerability Report — {target}**

| Field | Value |
|-------|-------|
| Project | {target} |
| Severity | {severity} |
| Vulnerability Type | {category} |
| Impact | {impact} |
| Affected Contract | {file_path} |
| Line Number | {line_number} |
| CVSS Score | {cvss_score} |

### Description
{summary}

### Proof of Concept
{poc}

### Recommended Fix
{remediation}
"""

_HACKERONE_HEADER = """
## HackerOne Report Format

**Title:** {title}
**Severity:** {severity}
**Weakness:** {category}
**CVSS:** {cvss_score} ({cvss_vector})

### Summary
{summary}

### Steps to Reproduce
{exploit_path}

### Supporting Material / References
- File: `{file_path}` line {line_number}
- Snippet: `{vulnerable_snippet}`

### Impact
{impact}
"""

_CODE4RENA_HEADER = """
## Code4rena Submission

### [{severity}] {title}

**Submitted by:** SPARTAN v2.0
**Labels:** {category}

#### Summary
{summary}

#### Vulnerability Details
**File:** `{file_path}` line {line_number}

```solidity
{vulnerable_snippet}
```

#### Impact
{impact}

#### Proof of Concept
{poc}

#### Recommended Mitigation Steps
{remediation}
"""

_PLATFORM_TEMPLATES = {
    "immunefi": _IMMUNEFI_HEADER,
    "hackerone": _HACKERONE_HEADER,
    "code4rena": _CODE4RENA_HEADER,
}

# ── Confidence tier labels ────────────────────────────────────────────────────

def _confidence_tier(confidence: int) -> str:
    if confidence >= 85:
        return "CONFIRMED"
    if confidence >= 60:
        return "NEEDS_VERIFICATION"
    return "LOW_CONFIDENCE"


# ── Main report prompt templates ──────────────────────────────────────────────

REPORT_CONTEXT_TEMPLATE = """
You are generating Phase 4 Audit Reports for:

TARGET: {target}
SESSION ID: {session_id}
AUDIT DATE: {audit_date}
PLATFORM: {platform}

CONFIDENCE TIERS:
- CONFIRMED (confidence >= 85%): Include in main report with full details
- NEEDS_VERIFICATION (60-84%): Include with "Needs Verification" badge
- LOW_CONFIDENCE (< 60%): Exclude from main report — summarised in appendix only

ALL REPORTABLE FINDINGS FROM THIS SESSION:
{all_findings}

{platform_instructions}

Your task — generate complete, submission-ready reports for ALL findings above.
Exclude REJECTED findings. Include NEEDS_VERIFICATION findings with a clear notice.

Use the EXACT following format for each finding:

---

## [FINDING-###] — <Vulnerability Title>

**Severity:** Critical / High / Medium / Low / Informational
**Confidence:** <confidence>% (<tier>)
**CVSS Score:** X.X (Vector: CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...)
**Target:** <contract / endpoint / component>
**Category:** <vulnerability class>
**CWE/SWC:** <ID>
**File:** `<file_path>` line <line_number>

---

### Summary
One-paragraph plain-English summary of the vulnerability and its impact.

---

### Vulnerability Details

**Root Cause:**
<Precise technical explanation. Reference specific functions, lines, or logic flows.>

**Vulnerable Snippet:**
```
<vulnerable_snippet>
```

**Attack Path:**
1. Attacker does X
2. This causes Y
3. Result: Z (funds drained / access gained / data exposed)

**Prerequisites:** <attack_prerequisite>

---

### Proof of Concept

```[language]
// [PoC — SAFE/LOCAL/SIMULATED]
<code or curl command>
```

---

### Impact Analysis
- **Confidentiality:** High / Medium / Low / None
- **Integrity:** High / Medium / Low / None
- **Availability:** High / Medium / Low / None
- **Financial Impact:** <estimated loss potential if applicable>

---

### Recommended Fix

<Specific, actionable remediation. Include code snippets where applicable.>

---

### References
- <CWE link, EIP link, CVE, or research paper>

---

Generate one complete report entry per finding.
End with an executive summary table.
"""

_PLATFORM_INSTRUCTIONS = {
    "immunefi": """
IMMUNEFI PLATFORM REQUIREMENTS:
- Severity tiers: Critical (>$100k impact), High ($10k-$100k), Medium ($1k-$10k), Low (<$1k)
- Required: smart contract address, function name, PoC transaction/test
- Format: Use Immunefi's vulnerability category taxonomy
- Critical findings must include estimated TVL at risk
""",
    "hackerone": """
HACKERONE PLATFORM REQUIREMENTS:
- Use HackerOne weakness types (CWE references)
- Severity: Critical/High/Medium/Low/Informational
- Required: Steps to reproduce (numbered), supporting material
- CVSS score required for severity > Low
- Avoid jargon — report must be readable by triage team
""",
    "code4rena": """
CODE4RENA PLATFORM REQUIREMENTS:
- Severity: High (funds at direct risk), Medium (limited risk), Low/QA, Gas
- Required: Solidity code snippet of vulnerability, mitigation steps
- Gas findings: include gas cost savings estimate
- Use `<details>` tags for longer PoC sections if applicable
- Each issue = one GitHub issue submission
""",
    "general": "",
    "internal": "",
}


EXEC_SUMMARY_PROMPT = """
After all finding reports, add an executive summary:

## Executive Summary

| Finding ID | Title | Severity | CVSS | Confidence | Category | Status |
|---|---|---|---|---|---|---|
{finding_rows}

**Total Findings:** {total}
**Critical:** {critical} | **High:** {high} | **Medium:** {medium} | **Low:** {low} | **Info/Gas:** {info}
**Confirmed:** {confirmed} | **Needs Verification:** {needs_verification} | **Rejected:** {rejected}

**Auditor:** SPARTAN v2.0
**Date:** {date}
**Session:** {session_id}
**Platform:** {platform}
"""


def build_report_prompt(
    target: str,
    session_id: str,
    all_findings_text: str,
    platform: str = "general",
) -> str:
    """Build the Phase 4 report generation prompt."""
    platform = platform.lower().strip()
    platform_instructions = _PLATFORM_INSTRUCTIONS.get(platform, "")
    return REPORT_CONTEXT_TEMPLATE.format(
        target=target,
        session_id=session_id,
        audit_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        all_findings=all_findings_text or "(No findings recorded — generate based on conversation context)",
        platform=platform.upper(),
        platform_instructions=platform_instructions,
    )


def build_report_system_prompt(platform: str = "general") -> str:
    base = PHASE_PROMPTS["report"]
    platform = platform.lower().strip()
    if platform in _PLATFORM_INSTRUCTIONS and _PLATFORM_INSTRUCTIONS[platform]:
        return base + "\n\n" + _PLATFORM_INSTRUCTIONS[platform]
    return base


def save_report(content: str, target: str, session_id: str, platform: str = "general") -> str:
    """Save report to disk. Returns the file path."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe_target = "".join(c if c.isalnum() or c in "-_" else "_" for c in target)[:40]
    date_str    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    plat_tag    = f"_{platform}" if platform not in ("general", "internal", "") else ""
    filename    = f"SPARTAN_Report_{safe_target}_{session_id}{plat_tag}_{date_str}.md"
    path        = REPORTS_DIR / filename
    with open(path, "w", encoding="utf-8") as fh:
        report_header = f"""# SPARTAN Security Audit Report
**Target:** {target}
**Session:** {session_id}
**Date:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
**Agent:** SPARTAN v2.0
**Platform:** {platform.upper()}
**Classification:** CONFIDENTIAL — AUTHORIZED SECURITY RESEARCH ONLY

---

"""
        fh.write(report_header + content)
    return str(path)

