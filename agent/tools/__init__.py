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
from agent.tools.scanner import (
    scan_source,
    scan_code_string,
    ScannerResult,
    ScannerFinding,
)
from agent.tools.code_chunker import (
    chunk_source_file,
    chunk_source_dict,
    chunks_to_prompt,
    CodeChunk,
)
from agent.tools.github_fetcher import (
    fetch_github_repo,
    is_github_url,
    FetchedRepo,
)
from agent.tools.devil_advocate import (
    devil_advocate_check,
    DevilVerdict,
)

__all__ = [
    # Recon tools
    "build_nmap_command",
    "build_subfinder_command",
    "build_whatweb_command",
    "build_schemathesis_command",
    "build_full_recon_block",
    "RECON_TOOLS_AVAILABLE",
    # Web exploits
    "get_injection_payloads",
    "get_auth_bypass_templates",
    "get_ssrf_payloads",
    "build_playwright_script",
    "PoC",
    # Dataflow
    "DataFlowAnalyzer",
    "analyze_sources_and_sinks",
    "SOURCE_PATTERNS",
    "SINK_PATTERNS",
    # Scanner
    "scan_source",
    "scan_code_string",
    "ScannerResult",
    "ScannerFinding",
    # Code chunker
    "chunk_source_file",
    "chunk_source_dict",
    "chunks_to_prompt",
    "CodeChunk",
    # GitHub fetcher
    "fetch_github_repo",
    "is_github_url",
    "FetchedRepo",
    # Devil's advocate
    "devil_advocate_check",
    "DevilVerdict",
]
