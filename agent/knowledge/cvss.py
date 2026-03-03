"""
SPARTAN v2.0 — CVSS v3.1 Scoring Engine
Compute base scores from metric vectors and map to platform severities.
"""

from __future__ import annotations
import re
from dataclasses import dataclass


# ── CVSS v3.1 metric value tables ────────────────────────────────────────────

AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}  # Attack Vector
AC  = {"L": 0.77, "H": 0.44}                           # Attack Complexity
PR  = {                                                  # Privileges Required
    "N": {"U": 0.85, "C": 0.85},
    "L": {"U": 0.62, "C": 0.68},
    "H": {"U": 0.27, "C": 0.50},
}
UI  = {"N": 0.85, "R": 0.62}                            # User Interaction
SC  = {"U": 0.0,  "C": 0.0}                             # Scope (affects PR)

# Impact sub-score metrics
CIA = {"N": 0.00, "L": 0.22, "H": 0.56}


@dataclass
class CVSSVector:
    """Parsed CVSS v3.1 base vector."""
    AV: str = "N"
    AC: str = "L"
    PR: str = "N"
    UI: str = "N"
    S:  str = "U"
    C:  str = "H"
    I:  str = "H"
    A:  str = "H"

    def to_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}"
            f"/UI:{self.UI}/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}"
        )

    @classmethod
    def from_string(cls, vector: str) -> "CVSSVector":
        """Parse a CVSS v3.1 vector string."""
        mapping: dict[str, str] = {}
        for part in vector.split("/"):
            if ":" in part:
                k, v = part.split(":", 1)
                mapping[k] = v
        return cls(
            AV=mapping.get("AV", "N"),
            AC=mapping.get("AC", "L"),
            PR=mapping.get("PR", "N"),
            UI=mapping.get("UI", "N"),
            S=mapping.get("S", "U"),
            C=mapping.get("C", "H"),
            I=mapping.get("I", "H"),
            A=mapping.get("A", "H"),
        )


def calculate_cvss(vector: CVSSVector) -> float:
    """
    Calculate CVSS v3.1 Base Score.
    Returns float rounded to 1 decimal place.
    """
    scope_changed = vector.S == "C"

    av_val = AV.get(vector.AV, 0.85)
    ac_val = AC.get(vector.AC, 0.77)
    pr_val = PR.get(vector.PR, {}).get(vector.S, 0.85)
    ui_val = UI.get(vector.UI, 0.85)

    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    isc_base = 1 - (
        (1 - CIA.get(vector.C, 0.56)) *
        (1 - CIA.get(vector.I, 0.56)) *
        (1 - CIA.get(vector.A, 0.56))
    )

    if scope_changed:
        iss = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
    else:
        iss = 6.42 * isc_base

    if iss <= 0:
        return 0.0

    if scope_changed:
        base_score = min(1.08 * (iss + exploitability), 10.0)
    else:
        base_score = min(iss + exploitability, 10.0)

    # Round up to 1 decimal
    import math
    rounded = math.ceil(base_score * 10) / 10
    return round(min(rounded, 10.0), 1)


def score_to_severity(score: float) -> str:
    """Map CVSS score to qualitative severity rating."""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    return "Informational"


def score_to_immunefi(score: float) -> str:
    if score >= 9.0:  return "Critical"
    elif score >= 7.0: return "High"
    elif score >= 4.0: return "Medium"
    return "Low"


def score_to_hackerone(score: float) -> str:
    if score >= 9.0:  return "P1 (Critical)"
    elif score >= 7.0: return "P2 (High)"
    elif score >= 4.0: return "P3 (Medium)"
    elif score > 0.0:  return "P4 (Low)"
    return "P5 (Informational)"


def score_to_code4rena(score: float) -> str:
    if score >= 7.0:  return "High"
    elif score >= 4.0: return "Medium"
    elif score > 0.0:  return "Low / Informational"
    return "Gas"


def full_severity_row(score: float) -> str:
    """Return a formatted severity summary for all platforms."""
    return (
        f"**CVSS:** {score} ({score_to_severity(score)})  \n"
        f"**Immunefi:** {score_to_immunefi(score)}  \n"
        f"**HackerOne:** {score_to_hackerone(score)}  \n"
        f"**Code4rena/Sherlock:** {score_to_code4rena(score)}"
    )


# ── Pre-built common vectors ──────────────────────────────────────────────────

COMMON_VECTORS = {
    "unauthenticated_rce": CVSSVector("N", "L", "N", "N", "C", "H", "H", "H"),
    "auth_rce":            CVSSVector("N", "L", "L", "N", "U", "H", "H", "H"),
    "reentrancy_drain":    CVSSVector("N", "L", "N", "N", "U", "H", "H", "N"),
    "ssrf_cloud_creds":    CVSSVector("N", "L", "N", "N", "C", "H", "H", "N"),
    "idor_read":           CVSSVector("N", "L", "L", "N", "U", "H", "N", "N"),
    "logic_bypass":        CVSSVector("N", "L", "L", "N", "U", "N", "H", "N"),
    "dos_loop":            CVSSVector("N", "L", "N", "N", "U", "N", "N", "H"),
}


def score_common(vector_name: str) -> tuple[float, str]:
    """Return (score, severity) for a named common vector."""
    vec = COMMON_VECTORS.get(vector_name)
    if not vec:
        raise KeyError(f"Unknown common vector: {vector_name}")
    score = calculate_cvss(vec)
    return score, score_to_severity(score)
