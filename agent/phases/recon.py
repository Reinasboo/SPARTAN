"""
SPARTAN v2.0 — Phase 1: Reconnaissance & Threat Modeling
Produces Attack Surface Map + Threat Model for the target.
Shannon integration: Nmap / Subfinder / WhatWeb / Schemathesis tool commands.
"""

from __future__ import annotations
import urllib.parse

from agent.knowledge.web2_vulns import get_web2_checklist
from agent.knowledge.web3_vulns import get_web3_checklist
from agent.tools.recon_tools import build_full_recon_block
from config.prompts import PHASE_PROMPTS


RECON_CONTEXT_TEMPLATE = """
You are conducting Phase 1 Reconnaissance on the following target:

TARGET: {target}

ADDITIONAL CONTEXT PROVIDED:
{context}

{tool_commands}

{web2_checklist}

{web3_checklist}

Your task:
1. Produce a complete **Attack Surface Map** — enumerate all:
   - Entry points (functions, endpoints, public/external surfaces)
   - Roles and permission levels
   - Trust boundaries (where does the system trust external data?)
   - Third-party integrations and dependencies
   - Upgrade/admin mechanisms

2. Produce a **Threat Model** covering:
   - Threat actors and their capabilities
   - High-value targets within the system
   - Key assumptions the system makes that an attacker could violate
   - Ordered list of highest-risk components to investigate

3. List specific questions and areas to probe deeply in Phase 2.

Format your output clearly with headers. Be thorough and adversarial in thinking.
"""


def build_recon_prompt(
    target: str,
    context: str = "",
    has_openapi: bool = False,
    auth_token: str | None = None,
    deep_scan: bool = False,
) -> str:
    """Build the Phase 1 reconnaissance prompt with tool commands."""
    is_web3 = _detect_web3(target + " " + context)
    is_url = _is_url(target)

    web2_check = get_web2_checklist() if not is_web3 else ""
    web3_check = get_web3_checklist() if is_web3 else ""

    # Generate tool commands block for URL targets
    tool_commands = ""
    if is_url and not is_web3:
        tool_commands = build_full_recon_block(
            target=target,
            is_url=True,
            has_openapi=has_openapi,
            auth_token=auth_token,
            deep_scan=deep_scan,
        )
        tool_commands = "## DISCOVERY COMMANDS (Run before proceeding)\n\n```\n" + tool_commands + "\n```\n"
    elif not is_web3:
        # Generic host-based target
        tool_commands = build_full_recon_block(
            target=target,
            is_url=False,
            deep_scan=deep_scan,
        )
        tool_commands = "## DISCOVERY COMMANDS (Run before proceeding)\n\n```\n" + tool_commands + "\n```\n"

    return RECON_CONTEXT_TEMPLATE.format(
        target=target,
        context=context or "(No additional context provided — infer from target description)",
        tool_commands=tool_commands,
        web2_checklist=web2_check,
        web3_checklist=web3_check,
    )


def build_recon_system_prompt() -> str:
    return PHASE_PROMPTS["recon"]


def _is_url(text: str) -> bool:
    """Detect if target looks like a URL."""
    return text.startswith(("http://", "https://")) or "://" in text


def _detect_web3(text: str) -> bool:
    """Heuristic: does this look like a Web3 / smart contract target?"""
    web3_keywords = [
        "solidity", "contract", "evm", "defi", "token", "vault", "dao",
        "erc20", "erc721", "erc4626", "proxy", "upgradeable", "chainlink",
        "uniswap", "aave", "compound", "0x", "abi", "vyper", "hardhat",
        "foundry", "blockchain", "ethereum", "polygon", "arbitrum", "optimism",
        "dex", "amm", "lending", "bridge", "cdp", "stablecoin", "oracle",
        "liquid staking", "yield aggregator", "staking pool", "governance",
    ]
    text_lower = text.lower()
    return any(kw in text_lower for kw in web3_keywords)


def parse_attack_surface(recon_output: str) -> dict:
    """
    Parse recon output into structured attack surface data.
    Returns dict with entry_points, roles, trust_boundaries, high_risk_areas.
    """
    data = {
        "entry_points": [],
        "roles": [],
        "trust_boundaries": [],
        "integrations": [],
        "high_risk_areas": [],
        "raw": recon_output,
    }
    return data
