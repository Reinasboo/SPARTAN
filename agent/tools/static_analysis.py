"""
SPARTAN v2.0 — Static Analysis Integration

Wrappers for Semgrep (Web2) and Slither/Mythril (Solidity).
Results are fed to the LLM for validation — the LLM confirms true/false positives
and supplies evidence. Tools discover, LLM decides.

All tools are optional; missing tools are silently skipped.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class StaticFinding:
    """A raw finding emitted by a static analysis tool."""

    tool: str           # "semgrep" | "slither" | "mythril"
    rule_id: str
    title: str
    severity: str       # INFO | WARNING | ERROR (tool-normalised)
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    cwe: str = ""
    swc: str = ""

    def to_prompt_block(self) -> str:
        loc = f"{self.file_path}:{self.line_number}" if self.file_path else "unknown"
        parts = [
            f"[{self.tool.upper()} — {self.rule_id}]",
            f"Title: {self.title}",
            f"Severity: {self.severity}",
            f"Location: {loc}",
        ]
        if self.code_snippet:
            parts.append(f"Code: {self.code_snippet[:300]}")
        if self.description:
            parts.append(f"Description: {self.description[:400]}")
        if self.cwe:
            parts.append(f"CWE: {self.cwe}")
        if self.swc:
            parts.append(f"SWC: {self.swc}")
        return "\n".join(parts)


@dataclass
class StaticAnalysisResult:
    """Aggregated output from one static analysis tool run."""

    tool: str
    findings: list[StaticFinding] = field(default_factory=list)
    error: str = ""
    skipped: bool = False

    def is_empty(self) -> bool:
        return not self.findings and not self.error


# ── Tool runners ──────────────────────────────────────────────────────────────

def run_semgrep(target_path: str, config: str = "auto") -> StaticAnalysisResult:
    """Run semgrep on a file or directory. Returns parsed findings."""
    if not shutil.which("semgrep"):
        return StaticAnalysisResult(tool="semgrep", skipped=True)

    try:
        proc = subprocess.run(
            ["semgrep", "--config", config, "--json", "--quiet", target_path],
            capture_output=True,
            text=True,
            timeout=120,
        )
        data = json.loads(proc.stdout or "{}")
        findings: list[StaticFinding] = []
        for r in data.get("results", []):
            extra = r.get("extra", {})
            findings.append(StaticFinding(
                tool="semgrep",
                rule_id=r.get("check_id", ""),
                title=r.get("check_id", "").split(".")[-1].replace("-", " ").title(),
                severity=extra.get("severity", "WARNING"),
                file_path=r.get("path", ""),
                line_number=r.get("start", {}).get("line", 0),
                code_snippet=extra.get("lines", ""),
                description=extra.get("message", ""),
                cwe=str(extra.get("metadata", {}).get("cwe", "")),
            ))
        return StaticAnalysisResult(tool="semgrep", findings=findings)
    except subprocess.TimeoutExpired:
        return StaticAnalysisResult(tool="semgrep", error="timeout after 120s")
    except Exception as exc:
        return StaticAnalysisResult(tool="semgrep", error=str(exc))


def run_slither(target_path: str) -> StaticAnalysisResult:
    """Run Slither on a Solidity file or directory."""
    if not shutil.which("slither"):
        return StaticAnalysisResult(tool="slither", skipped=True)

    try:
        proc = subprocess.run(
            ["slither", target_path, "--json", "-"],
            capture_output=True,
            text=True,
            timeout=180,
        )
        raw = proc.stdout or "{}"
        # Slither sometimes emits non-JSON preamble; find the first `{`
        start = raw.find("{")
        data = json.loads(raw[start:]) if start >= 0 else {}

        findings: list[StaticFinding] = []
        for detector in data.get("results", {}).get("detectors", []):
            elements = detector.get("elements", [])
            file_path = ""
            line_number = 0
            snippet = ""
            if elements:
                src = elements[0].get("source_mapping", {})
                file_path = src.get("filename_relative", "")
                lines = src.get("lines", [])
                line_number = lines[0] if lines else 0
                snippet = elements[0].get("name", "")

            findings.append(StaticFinding(
                tool="slither",
                rule_id=detector.get("check", ""),
                title=detector.get("check", "").replace("-", " ").title(),
                severity=detector.get("impact", "Medium"),
                file_path=file_path,
                line_number=line_number,
                code_snippet=snippet,
                description=detector.get("description", ""),
                swc=detector.get("swc-id", ""),
            ))
        return StaticAnalysisResult(tool="slither", findings=findings)
    except subprocess.TimeoutExpired:
        return StaticAnalysisResult(tool="slither", error="timeout after 180s")
    except Exception as exc:
        return StaticAnalysisResult(tool="slither", error=str(exc))


def run_mythril(contract_path: str) -> StaticAnalysisResult:
    """Run Mythril on a Solidity file."""
    if not shutil.which("myth"):
        return StaticAnalysisResult(tool="mythril", skipped=True)

    try:
        proc = subprocess.run(
            ["myth", "analyze", contract_path, "-o", "json", "--execution-timeout", "60"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        raw = proc.stdout or "[]"
        data = json.loads(raw)
        issues = data if isinstance(data, list) else data.get("issues", [])

        findings: list[StaticFinding] = []
        for issue in issues:
            findings.append(StaticFinding(
                tool="mythril",
                rule_id=issue.get("swc-id", ""),
                title=issue.get("title", ""),
                severity=issue.get("severity", "Medium"),
                file_path=issue.get("filename", ""),
                line_number=issue.get("lineno", 0),
                code_snippet=issue.get("code", ""),
                description=issue.get("description", ""),
                swc=issue.get("swc-id", ""),
            ))
        return StaticAnalysisResult(tool="mythril", findings=findings)
    except subprocess.TimeoutExpired:
        return StaticAnalysisResult(tool="mythril", error="timeout after 120s")
    except Exception as exc:
        return StaticAnalysisResult(tool="mythril", error=str(exc))


# ── Prompt builder ────────────────────────────────────────────────────────────

def build_static_analysis_prompt(results: list[StaticAnalysisResult]) -> str:
    """
    Convert static analysis results into a structured prompt block for SPARTAN.

    The LLM's job is to validate these findings — true / false positive triage —
    and supply file_path + line_number + vulnerable_snippet evidence for each
    confirmed finding so they can be emitted as json-finding blocks.
    """
    if not results:
        return ""

    tool_summary: list[str] = []
    all_findings: list[StaticFinding] = []

    for r in results:
        if r.skipped:
            tool_summary.append(f"- {r.tool}: not installed (skipped)")
        elif r.error:
            tool_summary.append(f"- {r.tool}: error — {r.error[:120]}")
        else:
            tool_summary.append(f"- {r.tool}: {len(r.findings)} finding(s)")
            all_findings.extend(r.findings)

    if not all_findings:
        summary_str = "\n".join(tool_summary)
        return f"## STATIC ANALYSIS PRE-SCAN\n{summary_str}\n(No findings from tooling.)\n"

    blocks = [f.to_prompt_block() for f in all_findings[:50]]  # cap at 50
    summary_str = "\n".join(tool_summary)

    return (
        f"## STATIC ANALYSIS PRE-SCAN RESULTS\n"
        f"Tools: {summary_str}\n"
        f"Total: {len(all_findings)} finding(s)\n\n"
        f"For EACH finding below:\n"
        f"1. Confirm true positive or false positive (with reasoning)\n"
        f"2. If true positive: emit a `json-finding` block with full evidence\n"
        f"3. If false positive: state why and skip\n\n"
        + "\n\n---\n\n".join(blocks)
    )


def run_all_tools(target_path: str) -> list[StaticAnalysisResult]:
    """
    Detect appropriate tools for the target and run them all.
    Returns a list of results (skipped tools are included with skipped=True).
    """
    path = Path(target_path)
    results: list[StaticAnalysisResult] = []

    # Solidity / Vyper targets get Slither + Mythril
    is_solidity = (
        (path.is_file() and path.suffix in (".sol", ".vy"))
        or (path.is_dir() and any(path.rglob("*.sol")))
    )

    if is_solidity:
        results.append(run_slither(target_path))
        if path.is_file() and path.suffix == ".sol":
            results.append(run_mythril(target_path))

    # All targets get semgrep
    results.append(run_semgrep(target_path))

    return results
