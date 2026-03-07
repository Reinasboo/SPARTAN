"""
SPARTAN v2.0 — Devil's Advocate Verification Pass
Secondary lightweight LLM call that challenges each finding before registration.
Returns CONFIRMED / REJECTED / NEEDS_MORE_EVIDENCE without bias toward reporting bugs.
"""

from __future__ import annotations

import json as _json
import re

from agent.llm_client import chat


# ── Prompts ───────────────────────────────────────────────────────────────────

DEVIL_ADVOCATE_SYSTEM = """You are a skeptical peer-reviewer challenging a security finding.
Your mission is to PREVENT FALSE POSITIVES — rigorously look for reasons this is NOT a real bug.

Ask yourself:
1. Is the vulnerable code path actually reachable by an untrusted caller?
2. Is there a modifier, require(), access check, or mitigating logic that prevents exploitation?
3. Are the stated prerequisites realistically achievable by an external attacker?
4. Does the described impact actually follow from the code?

Be concrete and reference the code. Do NOT confirm findings speculatively.

Respond with valid JSON only — no markdown, no commentary outside the JSON object:
{
  "verdict": "CONFIRMED" | "REJECTED" | "NEEDS_MORE_EVIDENCE",
  "reason": "<one concise sentence>",
  "confidence": <integer 0-100>
}"""

_TEMPLATE = """\
Review this security finding:

TITLE: {title}
SEVERITY: {severity}
CATEGORY: {category}
FILE: {file_path}
LINE: {line_number}
VULNERABLE SNIPPET:
```
{vulnerable_snippet}
```
ATTACK PREREQUISITE: {attack_prerequisite}
IMPACT JUSTIFICATION: {impact_justification}

SOURCE CONTEXT:
```
{source_context}
```

Is this a real, exploitable vulnerability? Reply in JSON only.
"""


# ── Result type ───────────────────────────────────────────────────────────────

class DevilVerdict:
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"

    def __init__(self, verdict: str, reason: str, confidence: int):
        self.verdict = verdict
        self.reason = reason
        self.confidence = confidence

    def __repr__(self) -> str:
        return f"DevilVerdict({self.verdict}, {self.confidence}%, {self.reason!r})"


# ── Core function ─────────────────────────────────────────────────────────────

def devil_advocate_check(
    title: str,
    severity: str,
    category: str,
    file_path: str,
    line_number: int,
    vulnerable_snippet: str,
    attack_prerequisite: str,
    impact_justification: str,
    source_context: str = "",
) -> DevilVerdict:
    """
    Run a devil's advocate LLM verification pass for a single finding.
    Uses a cheap/fast model preference; falls back to current configured model.
    Returns a DevilVerdict with CONFIRMED / REJECTED / NEEDS_MORE_EVIDENCE.
    """
    user_msg = _TEMPLATE.format(
        title=title,
        severity=severity,
        category=category,
        file_path=file_path or "(unknown)",
        line_number=line_number or "(unknown)",
        vulnerable_snippet=vulnerable_snippet[:800] if vulnerable_snippet else "(none provided)",
        attack_prerequisite=attack_prerequisite or "(not specified)",
        impact_justification=impact_justification or "(not specified)",
        source_context=source_context[:1500] if source_context else "(not provided)",
    )

    messages = [
        {"role": "system", "content": DEVIL_ADVOCATE_SYSTEM},
        {"role": "user", "content": user_msg},
    ]

    try:
        raw = chat(messages)
    except Exception:
        # On LLM failure, err on the side of caution — keep as DRAFT
        return DevilVerdict(DevilVerdict.NEEDS_MORE_EVIDENCE, "Devil's advocate LLM call failed", 0)

    return _parse_verdict(raw)


def _parse_verdict(raw: str) -> DevilVerdict:
    """Extract JSON verdict from LLM response, with robust fallback."""
    # Try to find a JSON object in the response
    json_match = re.search(r'\{[^{}]*"verdict"[^{}]*\}', raw, re.DOTALL)
    if json_match:
        try:
            data = _json.loads(json_match.group(0))
            verdict = data.get("verdict", "NEEDS_MORE_EVIDENCE").strip().upper()
            if verdict not in (
                DevilVerdict.CONFIRMED, DevilVerdict.REJECTED, DevilVerdict.NEEDS_MORE_EVIDENCE
            ):
                verdict = DevilVerdict.NEEDS_MORE_EVIDENCE
            reason = str(data.get("reason", "")).strip()[:200]
            confidence = max(0, min(100, int(data.get("confidence", 50) or 50)))
            return DevilVerdict(verdict, reason, confidence)
        except (ValueError, KeyError, TypeError):
            pass

    # Fallback: text-scan for verdict keywords
    upper = raw.upper()
    if "CONFIRMED" in upper:
        return DevilVerdict(DevilVerdict.CONFIRMED, "Parsed from text (no JSON)", 60)
    if "REJECTED" in upper:
        return DevilVerdict(DevilVerdict.REJECTED, "Parsed from text (no JSON)", 60)
    return DevilVerdict(DevilVerdict.NEEDS_MORE_EVIDENCE, "Could not parse LLM verdict", 0)
