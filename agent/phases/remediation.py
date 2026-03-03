"""
SPARTAN v2.0 — Phase 5: Remediation Review
Validate applied fixes are correct and complete.
"""

from __future__ import annotations

from config.prompts import PHASE_PROMPTS


REMEDIATION_CONTEXT_TEMPLATE = """
You are conducting Phase 5 Remediation Review on:

TARGET: {target}
ORIGINAL FINDINGS: {original_findings}

APPLIED FIX / UPDATED CODE:
{fix_content}

SPECIFIC FINDING(S) BEING REVIEWED: {finding_ids}

Your task — for each fix reviewed:

## Fix Review Checklist:
1. **Root Cause Addressed?** — Is the fundamental vulnerability fixed, not just the symptom?
2. **PoC Blocked?** — Does the fix prevent the original PoC from succeeding?
3. **Edge Cases Covered?** — Does the fix handle all the edge cases from the original analysis?
4. **Regression Check** — Does the fix introduce new vulnerabilities or break existing functionality?
5. **New Attack Surface** — Does the fix create new attack paths?
6. **Completeness** — Are there any related functions/paths with the same root cause that were missed?

## Output Format:
For each finding reviewed:

### Fix Review: [FINDING-###]
**Fix Status:** ✅ CONFIRMED FIXED | ⚠️ RESIDUAL RISK | ❌ FIX INCOMPLETE

**Analysis:**
<Technical analysis of the fix quality>

**Root Cause Treatment:**
- [ ] Root cause fully addressed
- [ ] Only symptom treated (explain why)

**PoC Status:** Blocked | Still exploitable | Partially mitigated

**Regression Risk:**
<Any new issues introduced by the fix>

**Residual Risk (if any):**
<What attack surface remains>

**Fix Confirmation / Residual Risk Notice:**
<Clear statement for the developer>

---

Be rigorous. Many incomplete fixes introduce new vulnerabilities.
"""


def build_remediation_prompt(
    target: str,
    original_findings: str,
    fix_content: str,
    finding_ids: str = "all findings",
) -> str:
    """Build the Phase 5 remediation review prompt."""
    return REMEDIATION_CONTEXT_TEMPLATE.format(
        target=target,
        original_findings=original_findings or "(Refer to findings from earlier in conversation)",
        fix_content=fix_content or "(No fix provided — analyze proposed remediation from context)",
        finding_ids=finding_ids,
    )


def build_remediation_system_prompt() -> str:
    return PHASE_PROMPTS["remediation"]


# Status markers
FIX_CONFIRMED  = "✅ CONFIRMED FIXED"
RESIDUAL_RISK  = "⚠️ RESIDUAL RISK"
FIX_INCOMPLETE = "❌ FIX INCOMPLETE"
