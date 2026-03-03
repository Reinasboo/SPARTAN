"""
SPARTAN v2.0 — Audit Configuration System (Shannon Integration)
YAML-based audit configuration for structured security assessments.

Supports:
  - Authentication configuration (form, API key, OAuth, Web3 wallet)
  - TOTP/2FA integration
  - Scope definition (URL, repo, contract addresses)
  - Focus and avoid path rules
  - Pipeline controls (parallel analysis, retry settings)
  - Protocol type hint for DeFi audits

Usage:
    from config.audit_config import AuditConfig, load_config
    config = load_config("audit.yaml")
    config = AuditConfig.from_dict({...})          # from dict
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class TOTPConfig:
    secret: str = ""
    issuer: str = ""
    digits: int = 6
    interval: int = 30


@dataclass
class LoginStep:
    """A single step in a multi-step login flow."""
    action: str               # 'fill', 'click', 'wait', 'wait_for_url', 'select', 'check'
    selector: str = ""        # CSS or XPath selector
    value: str = ""           # Value to fill / option to select
    wait_ms: int = 0          # For 'wait' action


@dataclass
class AuthConfig:
    login_type: str = "none"
    # Types: none, form, api_key, bearer_token, basic, oauth, web3, totp

    # Form-based auth
    login_url: str = ""
    username_selector: str = ""
    password_selector: str = ""
    submit_selector: str = "button[type=submit]"
    success_condition: str = "url_change"   # url_change, text_present, status_200

    # Credentials (prefer env var references like $ENV_VAR)
    username: str = ""
    password: str = ""

    # API token / bearer
    api_key: str = ""
    api_key_header: str = "Authorization"
    api_key_prefix: str = "Bearer"

    # Basic auth
    basic_user: str = ""
    basic_pass: str = ""

    # TOTP / 2FA
    totp: Optional[TOTPConfig] = None
    totp_selector: str = ""              # CSS selector for OTP input field

    # Complex multi-step login flow
    login_flow: list[LoginStep] = field(default_factory=list)

    # Web3
    wallet_private_key: str = ""         # Use env var: $SPARTAN_WALLET_KEY
    rpc_url: str = ""

    # OAuth
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    oauth_token_url: str = ""

    def is_authenticated(self) -> bool:
        return self.login_type != "none"

    def get_headers(self) -> dict[str, str]:
        """Return HTTP headers for this auth configuration."""
        if self.login_type in ("api_key", "bearer_token"):
            key = self._resolve_env(self.api_key)
            if key:
                return {self.api_key_header: f"{self.api_key_prefix} {key}".strip()}
        if self.login_type == "basic":
            import base64
            creds = base64.b64encode(
                f"{self._resolve_env(self.basic_user)}:{self._resolve_env(self.basic_pass)}".encode()
            ).decode()
            return {"Authorization": f"Basic {creds}"}
        return {}

    @staticmethod
    def _resolve_env(value: str) -> str:
        """Resolve $ENV_VAR references to actual values."""
        if value.startswith("$"):
            return os.environ.get(value[1:], "")
        return value


@dataclass
class ScopeConfig:
    url: str = ""                            # Primary target URL
    repo: str = ""                           # Local path or GitHub URL of source code
    contract_addresses: list[str] = field(default_factory=list)
    chain_id: int = 1                        # Ethereum mainnet
    rpc_url: str = ""
    openapi_path: str = ""                   # Path/URL to OpenAPI schema
    protocol_type: str = ""                  # DeFi protocol type hint (see protocol_vulns.py)
    # If protocol_type is "auto", SPARTAN auto-detects from target description


@dataclass
class RulesConfig:
    focus: list[str] = field(default_factory=list)   # paths/endpoints to focus on
    avoid: list[str] = field(default_factory=list)   # paths/endpoints to skip
    include_owasp_top10: bool = True
    include_api_security_top10: bool = True
    include_web3_vulns: bool = False          # Auto-set to True if protocol_type specified
    include_protocol_vulns: bool = False      # Auto-set to True if protocol_type specified
    custom_checklist: list[str] = field(default_factory=list)
    no_exploit_no_report: bool = True         # Shannon's "No Exploit, No Report" policy
    max_severity_to_report: str = "INFO"      # CRITICAL, HIGH, MEDIUM, LOW, INFO


@dataclass
class PipelineConfig:
    max_concurrent_agents: int = 3        # Parallel analysis agents (Shannon-style)
    retry_on_failure: int = 2
    timeout_per_phase_seconds: int = 300
    stream_output: bool = True
    auto_advance_phases: bool = False     # If True, auto-advances phases without user confirmation
    save_intermediate: bool = True
    retry_preset: str = "balanced"        # conservative, balanced, aggressive


@dataclass
class AuditConfig:
    """
    Complete SPARTAN audit configuration.
    Loaded from YAML file or constructed programmatically.
    """
    # Meta
    name: str = "SPARTAN Audit"
    version: str = "2.0"
    description: str = ""

    # Sub-configs
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    authentication: AuthConfig = field(default_factory=AuthConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)

    # Extra notes for LLM context
    auditor_notes: str = ""
    known_issues: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "AuditConfig":
        """Construct AuditConfig from a parsed YAML/dict."""
        config = cls()

        config.name = data.get("name", config.name)
        config.version = data.get("version", config.version)
        config.description = data.get("description", config.description)
        config.auditor_notes = data.get("auditor_notes", "")
        config.known_issues = data.get("known_issues", [])

        # Scope
        s = data.get("scope", {})
        config.scope = ScopeConfig(
            url=s.get("url", ""),
            repo=s.get("repo", ""),
            contract_addresses=s.get("contract_addresses", []),
            chain_id=s.get("chain_id", 1),
            rpc_url=s.get("rpc_url", ""),
            openapi_path=s.get("openapi_path", ""),
            protocol_type=s.get("protocol_type", ""),
        )

        # Authentication
        a = data.get("authentication", {})
        totp_data = a.get("totp")
        totp = TOTPConfig(
            secret=totp_data.get("secret", ""),
            issuer=totp_data.get("issuer", ""),
            digits=totp_data.get("digits", 6),
            interval=totp_data.get("interval", 30),
        ) if totp_data else None

        raw_flow = a.get("login_flow", [])
        login_flow = [
            LoginStep(
                action=step.get("action", ""),
                selector=step.get("selector", ""),
                value=step.get("value", ""),
                wait_ms=step.get("wait_ms", 0),
            )
            for step in raw_flow
        ] if isinstance(raw_flow, list) else []

        config.authentication = AuthConfig(
            login_type=a.get("login_type", "none"),
            login_url=a.get("login_url", ""),
            username_selector=a.get("username_selector", ""),
            password_selector=a.get("password_selector", ""),
            submit_selector=a.get("submit_selector", "button[type=submit]"),
            success_condition=a.get("success_condition", "url_change"),
            username=a.get("username", ""),
            password=a.get("password", ""),
            api_key=a.get("api_key", ""),
            api_key_header=a.get("api_key_header", "Authorization"),
            api_key_prefix=a.get("api_key_prefix", "Bearer"),
            basic_user=a.get("basic_user", ""),
            basic_pass=a.get("basic_pass", ""),
            totp=totp,
            totp_selector=a.get("totp_selector", ""),
            login_flow=login_flow,
            wallet_private_key=a.get("wallet_private_key", ""),
            rpc_url=a.get("rpc_url", ""),
            oauth_client_id=a.get("oauth_client_id", ""),
            oauth_client_secret=a.get("oauth_client_secret", ""),
            oauth_token_url=a.get("oauth_token_url", ""),
        )

        # Rules
        r = data.get("rules", {})
        config.rules = RulesConfig(
            focus=r.get("focus", []),
            avoid=r.get("avoid", []),
            include_owasp_top10=r.get("include_owasp_top10", True),
            include_api_security_top10=r.get("include_api_security_top10", True),
            include_web3_vulns=r.get("include_web3_vulns", bool(config.scope.protocol_type)),
            include_protocol_vulns=r.get("include_protocol_vulns", bool(config.scope.protocol_type)),
            custom_checklist=r.get("custom_checklist", []),
            no_exploit_no_report=r.get("no_exploit_no_report", True),
            max_severity_to_report=r.get("max_severity_to_report", "INFO"),
        )

        # Pipeline
        p = data.get("pipeline", {})
        config.pipeline = PipelineConfig(
            max_concurrent_agents=p.get("max_concurrent_agents", 3),
            retry_on_failure=p.get("retry_on_failure", 2),
            timeout_per_phase_seconds=p.get("timeout_per_phase_seconds", 300),
            stream_output=p.get("stream_output", True),
            auto_advance_phases=p.get("auto_advance_phases", False),
            save_intermediate=p.get("save_intermediate", True),
            retry_preset=p.get("retry_preset", "balanced"),
        )

        return config

    def to_context_string(self) -> str:
        """Format config as context string for the LLM system prompt."""
        lines = [
            "## Audit Configuration",
            f"Name: {self.name}",
        ]
        if self.description:
            lines.append(f"Description: {self.description}")
        if self.scope.url:
            lines.append(f"Target URL: {self.scope.url}")
        if self.scope.repo:
            lines.append(f"Source Repo: {self.scope.repo}")
        if self.scope.protocol_type:
            lines.append(f"Protocol Type: {self.scope.protocol_type}")
        if self.scope.contract_addresses:
            lines.append(f"Contracts: {', '.join(self.scope.contract_addresses)}")

        if self.authentication.is_authenticated():
            lines.append(f"Authentication: {self.authentication.login_type}")
            if self.authentication.totp:
                lines.append("MFA/TOTP: enabled")

        if self.rules.focus:
            lines.append(f"Focus paths: {', '.join(self.rules.focus)}")
        if self.rules.avoid:
            lines.append(f"Avoid paths: {', '.join(self.rules.avoid)}")
        if self.rules.custom_checklist:
            lines.append(f"Custom checklist items: {len(self.rules.custom_checklist)}")

        lines.append(f"No-Exploit-No-Report policy: {'ACTIVE' if self.rules.no_exploit_no_report else 'DISABLED'}")
        lines.append(f"Parallel agents: {self.pipeline.max_concurrent_agents}")

        if self.auditor_notes:
            lines.append(f"\nAuditor notes: {self.auditor_notes}")
        if self.known_issues:
            lines.append(f"Known issues to investigate: {'; '.join(self.known_issues)}")

        return "\n".join(lines)

    def validate(self) -> list[str]:
        """Validate config and return list of warnings."""
        warnings = []

        if not self.scope.url and not self.scope.repo:
            warnings.append("No target URL or repo specified in scope.")

        if self.authentication.login_type == "form":
            if not self.authentication.login_url:
                warnings.append("login_type=form but no login_url specified.")
            if not self.authentication.username:
                warnings.append("login_type=form but no username specified.")

        if self.authentication.login_type in ("api_key", "bearer_token"):
            if not self.authentication.api_key:
                warnings.append("login_type=api_key but no api_key specified.")

        if self.authentication.totp and not self.authentication.totp.secret:
            warnings.append("TOTP configured but no secret provided.")

        return warnings


# ── YAML loading ──────────────────────────────────────────────────────────────

def load_config(config_path: str) -> AuditConfig:
    """
    Load AuditConfig from a YAML file.
    Falls back gracefully if PyYAML is not installed.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    try:
        import yaml  # type: ignore
    except ImportError:
        raise ImportError(
            "PyYAML is required for config file support. "
            "Install with: pip install pyyaml"
        )

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid config file format: {config_path}")

    config = AuditConfig.from_dict(data)

    warnings = config.validate()
    for w in warnings:
        print(f"[CONFIG WARNING] {w}")

    return config


def default_config(target: str = "") -> AuditConfig:
    """Return a default empty AuditConfig with optional target URL."""
    config = AuditConfig()
    if target:
        config.scope.url = target
        config.name = f"SPARTAN Audit — {target}"
    return config
