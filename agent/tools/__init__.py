"""
SPARTAN v2.0 — Tools Package
Shannon-integrated reconnaissance and exploitation tooling.
"""
from agent.tools.recon_tools import (
    build_nmap_command,
    build_subfinder_command,
    build_whatweb_command,
    build_schemathesis_command,
    build_full_recon_block,
    RECON_TOOLS_AVAILABLE,
)
from agent.tools.web_exploits import (
    get_injection_payloads,
    get_auth_bypass_templates,
    get_ssrf_payloads,
    build_playwright_script,
    PoC,
)
from agent.tools.dataflow import (
    DataFlowAnalyzer,
    analyze_sources_and_sinks,
    SOURCE_PATTERNS,
    SINK_PATTERNS,
)

__all__ = [
    "build_nmap_command",
    "build_subfinder_command",
    "build_whatweb_command",
    "build_schemathesis_command",
    "build_full_recon_block",
    "RECON_TOOLS_AVAILABLE",
    "get_injection_payloads",
    "get_auth_bypass_templates",
    "get_ssrf_payloads",
    "build_playwright_script",
    "PoC",
    "DataFlowAnalyzer",
    "analyze_sources_and_sinks",
    "SOURCE_PATTERNS",
    "SINK_PATTERNS",
]
