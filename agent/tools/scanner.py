"""
SPARTAN v2.0 — Static Analysis Scanner Integration
Semgrep / Slither pre-scan: if tool is in PATH, run it on provided source files and
return structured findings that the LLM can interpret rather than discover blindly.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class ScannerFinding:
    """A single raw finding from semgrep or slither."""
    tool: str                  # "semgrep" | "slither"
    rule_id: str
    message: str
    severity: str              # "ERROR" | "WARNING" | "INFO"
    file_path: str
    line_number: int
    snippet: str = ""
    category: str = ""


@dataclass
class ScannerResult:
    """Aggregate result from running all available scanners."""
    findings: list[ScannerFinding] = field(default_factory=list)
    tools_run: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)   # tools not in PATH

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    def to_context_string(self) -> str:
        """Format for LLM consumption — structured list of tool-confirmed issues."""
        if not self.has_findings:
            if self.tools_run:
                return (
                    f"## Static Analysis Pre-Scan Results\n"
                    f"Tools run: {', '.join(self.tools_run)}\n"
                    f"Result: **No findings detected by automated tools.**\n"
                    f"Proceed with manual LLM-based analysis.\n"
                )
            return ""

        lines = [
            "## Static Analysis Pre-Scan Results",
            f"Tools run: {', '.join(self.tools_run)}",
            f"**{len(self.findings)} automated findings** — verify each below:\n",
        ]
        for i, f in enumerate(self.findings, 1):
            lines.append(f"### Tool Finding #{i} [{f.tool.upper()}] — {f.rule_id}")
            lines.append(f"- **Severity:** {f.severity}")
            lines.append(f"- **Category:** {f.category or 'N/A'}")
            lines.append(f"- **File:** `{f.file_path}` line {f.line_number}")
            lines.append(f"- **Message:** {f.message}")
            if f.snippet:
                lines.append(f"- **Snippet:**\n```\n{f.snippet}\n```")
            lines.append("")
        return "\n".join(lines)


# ── Semgrep runner ────────────────────────────────────────────────────────────

def _semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def run_semgrep(source_path: str | Path, timeout: int = 60) -> list[ScannerFinding]:
    """
    Run semgrep with auto-config on the given path.
    Returns parsed findings. Raises nothing — errors are caught and returned empty.
    """
    if not _semgrep_available():
        return []

    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config", "auto",
                "--json",
                "--timeout", str(timeout),
                "--metrics=off",
                str(source_path),
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
        raw = json.loads(result.stdout)
        findings = []
        for r in raw.get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {})
            sev_raw = extra.get("severity", "WARNING").upper()
            findings.append(ScannerFinding(
                tool="semgrep",
                rule_id=r.get("check_id", "unknown"),
                message=extra.get("message", "").strip(),
                severity=sev_raw,
                file_path=r.get("path", ""),
                line_number=r.get("start", {}).get("line", 0),
                snippet=extra.get("lines", "").strip(),
                category=meta.get("category", meta.get("cwe", [""])[0] if meta.get("cwe") else ""),
            ))
        return findings
    except (subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, OSError):
        return []


# ── Slither runner ────────────────────────────────────────────────────────────

def _slither_available() -> bool:
    return shutil.which("slither") is not None


def _severity_from_impact(slither_impact: str) -> str:
    mapping = {"High": "ERROR", "Medium": "WARNING", "Low": "INFO", "Informational": "INFO"}
    return mapping.get(slither_impact, "WARNING")


def run_slither(source_path: str | Path, timeout: int = 120) -> list[ScannerFinding]:
    """
    Run Slither on a .sol file or directory.
    Returns parsed findings. Raises nothing.
    """
    if not _slither_available():
        return []

    try:
        result = subprocess.run(
            ["slither", str(source_path), "--json", "-"],
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
        raw = json.loads(result.stdout)
        if not isinstance(raw, dict):
            return []
        findings = []
        for det in raw.get("results", {}).get("detectors", []):
            elements = det.get("elements", [])
            file_path = ""
            line_number = 0
            snippet = ""
            if elements:
                src_map = elements[0].get("source_mapping", {})
                file_path = src_map.get("filename_relative", "")
                lines = src_map.get("lines", [])
                line_number = lines[0] if lines else 0
                snippet = elements[0].get("name", "")

            findings.append(ScannerFinding(
                tool="slither",
                rule_id=det.get("check", "unknown"),
                message=det.get("description", "").strip(),
                severity=_severity_from_impact(det.get("impact", "Medium")),
                file_path=file_path,
                line_number=line_number,
                snippet=snippet,
                category=det.get("check", ""),
            ))
        return findings
    except (subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, OSError):
        return []


# ── Public API ────────────────────────────────────────────────────────────────

def scan_source(
    source_path: str | Path,
    run_semgrep_flag: bool = True,
    run_slither_flag: bool = True,
) -> ScannerResult:
    """
    Run all available static analysis tools on the given source path.
    Returns a ScannerResult with all findings aggregated.
    """
    result = ScannerResult()
    path = Path(source_path)

    if not path.exists():
        result.errors.append(f"Path does not exist: {source_path}")
        return result

    # Semgrep — works on Python, JS, and Solidity
    if run_semgrep_flag:
        if _semgrep_available():
            findings = run_semgrep(path)
            result.findings.extend(findings)
            result.tools_run.append("semgrep")
        else:
            result.skipped.append("semgrep")

    # Slither — Solidity only
    if run_slither_flag:
        is_sol = (
            path.suffix == ".sol"
            or (path.is_dir() and any(path.rglob("*.sol")))
        )
        if is_sol:
            if _slither_available():
                findings = run_slither(path)
                result.findings.extend(findings)
                result.tools_run.append("slither")
            else:
                result.skipped.append("slither")

    return result


def scan_code_string(
    code: str,
    lang_hint: str = "auto",
    run_semgrep_flag: bool = True,
    run_slither_flag: bool = True,
) -> ScannerResult:
    """
    Scan a code string by writing it to a temp file first.
    lang_hint: "python" | "solidity" | "javascript" | "auto"
    """
    ext_map = {"python": ".py", "solidity": ".sol", "javascript": ".js", "auto": ".py"}
    # Auto-detect from content
    if lang_hint == "auto":
        if "pragma solidity" in code or "contract " in code:
            ext = ".sol"
        elif "def " in code or "import " in code:
            ext = ".py"
        elif "function " in code or "const " in code or "require(" in code:
            ext = ".js"
        else:
            ext = ".py"
    else:
        ext = ext_map.get(lang_hint, ".py")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=ext, delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        return scan_source(tmp_path, run_semgrep_flag, run_slither_flag)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
