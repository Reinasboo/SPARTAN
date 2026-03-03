"""
SPARTAN v2.0 — Output Formatter
Produces clean, structured terminal and Markdown output.
"""

from __future__ import annotations

from config.settings import SEVERITY_COLORS, RESET_COLOR, BOLD, DIM


DIVIDER = "─" * 44
THIN_DIVIDER = "─" * 44


def spartan_header(target: str, phase: str) -> str:
    """Produce the SPARTAN response header."""
    return (
        f"\n{BOLD}[SPARTAN ACTIVE — Target: {target}]{RESET_COLOR}\n"
        f"{BOLD}Phase:{RESET_COLOR} {phase}\n"
        f"{DIVIDER}\n"
    )


def spartan_footer(next_action: str) -> str:
    """Produce the SPARTAN response footer."""
    return (
        f"\n{DIVIDER}\n"
        f"{BOLD}NEXT ACTION:{RESET_COLOR} {next_action}\n"
    )


def format_finding_badge(finding_id: str, severity: str, title: str, confirmed: bool = True) -> str:
    color = SEVERITY_COLORS.get(severity, "")
    conf_label = "" if confirmed else f" {DIM}[UNCONFIRMED — NEEDS VALIDATION]{RESET_COLOR}"
    return (
        f"\n{color}{BOLD}[{finding_id}] — {severity.upper()}{RESET_COLOR}\n"
        f"{BOLD}{title}{RESET_COLOR}{conf_label}"
    )


def format_poc_block(code: str, label: str = "SAFE/LOCAL/SIMULATED") -> str:
    return (
        f"\n{DIM}[PoC — {label}]{RESET_COLOR}\n"
        f"```\n{code}\n```"
    )


def format_severity_row(severity: str, count: int) -> str:
    color = SEVERITY_COLORS.get(severity, "")
    return f"  {color}{BOLD}{count} {severity}{RESET_COLOR}"


def format_session_banner(session_id: str, target: str, model: str) -> str:
    return (
        f"\n{'═' * 50}\n"
        f"{BOLD}  SPARTAN v2.0 — Autonomous Security Audit Agent{RESET_COLOR}\n"
        f"{'═' * 50}\n"
        f"  Session:  {session_id}\n"
        f"  Target:   {target}\n"
        f"  Model:    {model}\n"
        f"{'═' * 50}\n"
        f"  Type {BOLD}help{RESET_COLOR} for commands | {BOLD}status{RESET_COLOR} for session overview\n"
        f"{'═' * 50}\n"
    )


def format_help() -> str:
    commands = [
        ("target <name>",         "Set or change the audit target"),
        ("phase <name>",          "Jump to a specific phase (Recon/Analysis/Validation/Report/Remediation)"),
        ("status",                "Show current session summary"),
        ("sessions",              "List all saved sessions"),
        ("load <id>",             "Load a previous session"),
        ("report",                "Generate full markdown report for all findings"),
        ("save",                  "Save current session to disk"),
        ("findings",              "List all findings in this session"),
        ("finding <id>",          "Show details of a specific finding"),
        ("clear",                 "Clear conversation history (keep findings)"),
        ("model",                 "Show active LLM model"),
        ("continue",              "Resume from last recorded phase"),
        ("exit / quit",           "Exit SPARTAN"),
        ("<anything else>",       "Send message to SPARTAN agent"),
    ]
    lines = [f"\n{BOLD}SPARTAN Commands:{RESET_COLOR}\n"]
    for cmd, desc in commands:
        lines.append(f"  {BOLD}{cmd:<25}{RESET_COLOR} {desc}")
    return "\n".join(lines) + "\n"


def format_authorization_check(target: str) -> str:
    return (
        f"\n{BOLD}⚠  AUTHORIZATION CHECK{RESET_COLOR}\n"
        f"{DIVIDER}\n"
        f"Before proceeding with security analysis of:\n"
        f"  {BOLD}{target}{RESET_COLOR}\n\n"
        f"Can you confirm:\n"
        f"  1. This target is in scope for your authorized engagement?\n"
        f"  2. You have explicit written permission to test this target?\n\n"
        f"Type {BOLD}confirmed{RESET_COLOR} to proceed, or provide authorization context.\n"
    )


def truncate_for_context(text: str, max_chars: int = 4000) -> str:
    """Trim long texts to prevent context overflow."""
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    return (
        text[:half]
        + f"\n\n[... {len(text) - max_chars} characters truncated ...]\n\n"
        + text[-half:]
    )
