"""
SPARTAN v2.0 — Recon Tools
Shannon-style reconnaissance tool command generator.

Tools:
  - Nmap       : Port/service/script scanning
  - Subfinder  : Subdomain enumeration (passive)
  - WhatWeb    : Technology fingerprinting
  - Schemathesis: OpenAPI schema-driven API fuzzing
  
Returns shell commands as strings for SPARTAN to include in recon output.
The agent does NOT automatically execute these; they are presented to the
operator as ready-to-run commands with full flag explanations.
"""

from __future__ import annotations
import re
import urllib.parse
from dataclasses import dataclass, field


RECON_TOOLS_AVAILABLE = ["nmap", "subfinder", "whatweb", "schemathesis"]


@dataclass
class ReconCommand:
    tool: str
    command: str
    description: str
    expected_output: str
    flags_explained: dict[str, str] = field(default_factory=dict)

    def __str__(self) -> str:
        lines = [
            f"# {self.tool.upper()} — {self.description}",
            f"$ {self.command}",
            "",
            f"# Expected: {self.expected_output}",
        ]
        if self.flags_explained:
            lines.append("# Flags:")
            for flag, explanation in self.flags_explained.items():
                lines.append(f"#   {flag:<20} {explanation}")
        return "\n".join(lines)


def _extract_host(target: str) -> str:
    """Extract hostname/IP from a URL or bare host string."""
    if "://" not in target:
        target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or target
    # Strip port
    host = re.sub(r':\d+$', '', host)
    return host


def _extract_base_url(target: str) -> str:
    """Return https://hostname base URL."""
    if "://" not in target:
        target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    if parsed.port:
        return f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
    return f"{parsed.scheme}://{parsed.hostname}"


# ── Nmap ──────────────────────────────────────────────────────────────────────

def build_nmap_command(target: str, mode: str = "default") -> ReconCommand:
    """
    Build an Nmap command for the target.

    Modes:
      default   — SYN scan + version detection + default scripts
      deep      — Full port scan with aggressive scripts
      udp       — Top UDP ports
      vuln      — Vuln NSE script category
      web       — Web-focused NSE scripts (http-*)
    """
    host = _extract_host(target)

    mode_configs = {
        "default": (
            f"nmap -sV -sC -T4 -oN nmap_default_{host}.txt {host}",
            "Open ports, service versions, default NSE scripts",
            {"-sV": "Version detection", "-sC": "Default scripts", "-T4": "Aggressive timing"},
        ),
        "deep": (
            f"nmap -sV -sC -p- -T4 -A -oN nmap_deep_{host}.txt {host}",
            "All 65535 ports, OS detection, traceroute, scripts",
            {"-p-": "All ports", "-A": "OS + traceroute + scripts", "-T4": "Aggressive timing"},
        ),
        "udp": (
            f"nmap -sU --top-ports 200 -T4 -oN nmap_udp_{host}.txt {host}",
            "Top 200 UDP ports",
            {"-sU": "UDP scan", "--top-ports 200": "Top 200 most common UDP ports"},
        ),
        "vuln": (
            f"nmap --script vuln -T4 -p80,443,8080,8443 -oN nmap_vuln_{host}.txt {host}",
            "Common web vulnerability NSE scripts",
            {"--script vuln": "Run all vuln-category NSE scripts"},
        ),
        "web": (
            f"nmap -p 80,443,8080,8443,3000,5000,8000,9000 --script 'http-*' "
            f"-T4 -oN nmap_web_{host}.txt {host}",
            "Web service enumeration and fingerprinting on all common web ports",
            {"--script 'http-*'": "All HTTP-related NSE scripts", "-p ...": "Common web ports"},
        ),
    }

    cmd, expected, flags = mode_configs.get(mode, mode_configs["default"])
    return ReconCommand(
        tool="nmap",
        command=cmd,
        description=f"Network/service scan ({mode} mode)",
        expected_output=expected,
        flags_explained=flags,
    )


# ── Subfinder ─────────────────────────────────────────────────────────────────

def build_subfinder_command(
    target: str,
    resolve: bool = True,
    output_file: bool = True,
) -> ReconCommand:
    """Build a Subfinder passive subdomain enumeration command."""
    host = _extract_host(target)
    # Strip www. prefix for subdomain enumeration
    domain = re.sub(r'^www\.', '', host)

    flags: dict[str, str] = {
        "-d": "Target domain",
        "-silent": "Output subdomains only (no banners)",
    }
    cmd_parts = [f"subfinder -d {domain} -silent"]

    if resolve:
        cmd_parts.append("-resolve")
        flags["-resolve"] = "Resolve subdomains to IPs"

    if output_file:
        out = f"subfinder_{domain}.txt"
        cmd_parts.append(f"-o {out}")
        flags[f"-o {out}"] = "Save results to file"

    return ReconCommand(
        tool="subfinder",
        command=" ".join(cmd_parts),
        description="Passive subdomain enumeration",
        expected_output=f"List of subdomains for {domain} with resolved IPs",
        flags_explained=flags,
    )


# ── WhatWeb ───────────────────────────────────────────────────────────────────

def build_whatweb_command(
    target: str,
    aggression: int = 3,
) -> ReconCommand:
    """
    Build a WhatWeb technology fingerprinting command.
    Aggression: 1 (passive) to 4 (aggressive, sends many requests).
    """
    base_url = _extract_base_url(target)

    aggression = max(1, min(4, aggression))
    cmd = f"whatweb -a{aggression} --log-json=whatweb_results.json {base_url}"

    descriptions = {
        1: "Passive (single request per URL)",
        2: "Polite (few requests, no brute force)",
        3: "Aggressive (many requests, guesses common paths)",
        4: "Heavy (many requests, thorough brute force)",
    }

    return ReconCommand(
        tool="whatweb",
        command=cmd,
        description=f"Technology fingerprinting (aggression {aggression}: {descriptions[aggression]})",
        expected_output=(
            "Web server type, CMS, framework, JavaScript libraries, WAF detection, "
            "IP address, HTTP headers, cookies"
        ),
        flags_explained={
            f"-a{aggression}": f"Aggression level {aggression}: {descriptions[aggression]}",
            "--log-json": "Save output as JSON for structured analysis",
        },
    )


# ── Schemathesis ──────────────────────────────────────────────────────────────

def build_schemathesis_command(
    target: str,
    schema_path: str = "/openapi.json",
    checks: str = "all",
    auth_token: str | None = None,
    max_examples: int = 100,
) -> ReconCommand:
    """
    Build a Schemathesis OpenAPI schema-driven API fuzzing command.

    Runs property-based testing against the OpenAPI spec to find:
      - 5xx errors (server errors from unexpected inputs)
      - Schema validation failures
      - Authentication bypass
      - Response conformance violations
    """
    base_url = _extract_base_url(target)
    schema_url = f"{base_url}{schema_path}"

    flags: dict[str, str] = {
        "--checks all": f"Run all checks: not_{','.join(['5xx','response_conformance','content_type_conformance'])}",
        f"--max-examples={max_examples}": f"Generate {max_examples} test cases per endpoint",
        "--show-errors-tracebacks": "Show full Python tracebacks on errors",
    }

    cmd_parts = [
        f"schemathesis run",
        f"--checks {checks}",
        f"--max-examples={max_examples}",
        "--show-errors-tracebacks",
    ]

    if auth_token:
        cmd_parts.append(f"-H 'Authorization: Bearer {auth_token}'")
        flags["-H 'Authorization: Bearer ...'"] = "Auth header for authenticated testing"

    # Try common schema locations
    alt_paths = ["/swagger.json", "/v1/openapi.json", "/api/openapi.json", "/docs/openapi.json"]
    schema_note = f"# If schema not at {schema_path}, try: {', '.join(alt_paths)}"

    cmd_parts.append(schema_url)
    cmd = " ".join(cmd_parts)

    return ReconCommand(
        tool="schemathesis",
        command=cmd,
        description="OpenAPI schema-driven API fuzzing (property-based testing)",
        expected_output=(
            "Test results per endpoint: passed/failed/errored counts, "
            "5xx responses logged as security findings, schema violations flagged"
        ),
        flags_explained=flags,
    )


# ── Combined recon block generator ────────────────────────────────────────────

def build_full_recon_block(
    target: str,
    is_url: bool = True,
    has_openapi: bool = False,
    auth_token: str | None = None,
    deep_scan: bool = False,
) -> str:
    """
    Generate a full recon commands block for inclusion in SPARTAN recon phase output.

    Returns formatted string with all relevant tool commands.
    """
    commands: list[ReconCommand] = []

    if is_url:
        commands.append(build_whatweb_command(target, aggression=3))
        commands.append(build_subfinder_command(target))
        commands.append(build_nmap_command(target, mode="web"))
        if deep_scan:
            commands.append(build_nmap_command(target, mode="deep"))
            commands.append(build_nmap_command(target, mode="vuln"))
        if has_openapi:
            commands.append(build_schemathesis_command(target, auth_token=auth_token))
    else:
        # Generic target (IP or host)
        commands.append(build_nmap_command(target, mode="default"))
        if deep_scan:
            commands.append(build_nmap_command(target, mode="deep"))
            commands.append(build_nmap_command(target, mode="udp"))
            commands.append(build_nmap_command(target, mode="vuln"))

    sep = "\n" + "─" * 60 + "\n"
    lines = [
        "=" * 60,
        "SPARTAN RECON TOOL COMMANDS",
        "Run these against the target to gather intelligence.",
        "=" * 60,
        "",
    ]
    for cmd in commands:
        lines.append(str(cmd))
        lines.append(sep)

    lines += [
        "NOTE: Review output before proceeding to Analysis phase.",
        "Paste tool output into SPARTAN conversation for integration.",
    ]
    return "\n".join(lines)
