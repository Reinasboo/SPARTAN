"""
SPARTAN v2.0 — Phase 4: Report Generation
Produces submission-ready, professional audit reports.
"""

from __future__ import annotations
from datetime import datetime, timezone

from config.prompts import PHASE_PROMPTS
from config.settings import REPORTS_DIR


REPORT_CONTEXT_TEMPLATE = """
You are generating Phase 4 Audit Reports for:

TARGET: {target}
SESSION ID: {session_id}
AUDIT DATE: {audit_date}

ALL FINDINGS FROM THIS SESSION:
{all_findings}

PLATFORM: {platform}

Your task — generate complete, submission-ready reports for ALL confirmed findings.

Use the EXACT following format for each finding:

---

## [FINDING-###] — <Vulnerability Title>

**Severity:** Critical / High / Medium / Low / Informational
**CVSS Score:** X.X (Vector: CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...)
**Target:** <contract / endpoint / component>
**Category:** <vulnerability class>
**CWE/SWC:** <ID>

---

### Summary
One-paragraph plain-English summary of the vulnerability and its impact.

---

### Vulnerability Details

**Root Cause:**
<Precise technical explanation. Reference specific functions, lines, or logic flows.>

**Attack Path:**
1. Attacker does X
2. This causes Y
3. Result: Z (funds drained / access gained / data exposed)

---

### Proof of Concept

```[language]
// [PoC — SAFE/LOCAL/SIMULATED]
// Target: <function/endpoint>
// Vulnerability: <type>
// Impact: <what an attacker achieves>
// Prerequisites: <what attacker needs>

<code or curl command>

// Expected result: <what happens>
// Attacker outcome: <impact>
```

**Reproduction Steps:**
1. ...
2. ...
3. ...

**Expected vs. Actual Behavior:**
- Expected: ...
- Actual: ...

---

### Impact Analysis
- **Confidentiality:** High / Medium / Low / None
- **Integrity:** High / Medium / Low / None
- **Availability:** High / Medium / Low / None
- **Financial Impact:** <estimated loss potential if applicable>
- **Affected Users / Contracts / Funds:** <scope>

---

### Recommended Fix

<Specific, actionable remediation. Include code snippets where applicable.>

**Fix Verification:** Describe exactly how to confirm the fix is correct.

---

### References
- <CWE link, EIP link, CVE, or research paper>

---

Generate one complete report entry per confirmed finding.
End with an executive summary table.
"""

EXEC_SUMMARY_PROMPT = """
After all finding reports, add an executive summary:

## Executive Summary

| Finding ID | Title | Severity | CVSS | Category | Status |
|---|---|---|---|---|---|
{finding_rows}

**Total Findings:** {total}
**Critical:** {critical} | **High:** {high} | **Medium:** {medium} | **Low:** {low} | **Info/Gas:** {info}

**Auditor:** SPARTAN v2.0
**Date:** {date}
**Session:** {session_id}
"""


def build_report_prompt(
    target: str,
    session_id: str,
    all_findings_text: str,
    platform: str = "general",
) -> str:
    """Build the Phase 4 report generation prompt."""
    return REPORT_CONTEXT_TEMPLATE.format(
        target=target,
        session_id=session_id,
        audit_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        all_findings=all_findings_text or "(No findings recorded — generate based on conversation context)",
        platform=platform,
    )


def build_report_system_prompt() -> str:
    return PHASE_PROMPTS["report"]


def save_report(content: str, target: str, session_id: str) -> str:
    """Save report to disk. Returns the file path."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe_target = "".join(c if c.isalnum() or c in "-_" else "_" for c in target)[:40]
    date_str    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename    = f"SPARTAN_Report_{safe_target}_{session_id}_{date_str}.md"
    path        = REPORTS_DIR / filename
    with open(path, "w", encoding="utf-8") as fh:
        report_header = f"""# SPARTAN Security Audit Report
**Target:** {target}
**Session:** {session_id}
**Date:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
**Agent:** SPARTAN v2.0
**Classification:** CONFIDENTIAL — AUTHORIZED SECURITY RESEARCH ONLY

---

"""
        fh.write(report_header + content)
    return str(path)
