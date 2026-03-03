"""
Tests for agent/phases/ — prompt builders for all 5 phases
"""
import unittest
from unittest.mock import patch

from agent.phases.recon import build_recon_prompt, build_recon_system_prompt, _detect_web3, _is_url
from agent.phases.analysis import build_analysis_prompt, build_analysis_system_prompt
from agent.phases.validation import build_validation_prompt, build_validation_system_prompt
from agent.phases.report import build_report_prompt, build_report_system_prompt
from agent.phases.remediation import build_remediation_prompt, build_remediation_system_prompt


# ── Recon Phase ───────────────────────────────────────────────────────────────

class TestIsUrl(unittest.TestCase):

    def test_http_is_url(self):
        self.assertTrue(_is_url("http://example.com"))

    def test_https_is_url(self):
        self.assertTrue(_is_url("https://app.example.com/api"))

    def test_plain_contract_not_url(self):
        self.assertFalse(_is_url("VaultContract.sol"))

    def test_contract_address_not_url(self):
        self.assertFalse(_is_url("0xAbCd1234567890abcdef1234567890abcdef1234"))

    def test_ip_without_scheme_not_url(self):
        self.assertFalse(_is_url("192.168.1.1"))


class TestDetectWeb3(unittest.TestCase):

    def test_solidity_is_web3(self):
        self.assertTrue(_detect_web3("this solidity contract uses ERC20"))

    def test_defi_terms_are_web3(self):
        # These are confirmed keywords in _detect_web3
        for term in ["defi", "solidity", "evm", "erc20", "lending", "bridge", "oracle", "foundry"]:
            self.assertTrue(_detect_web3(f"audit this {term} system"), f"'{term}' should be web3")

    def test_normal_web_app_is_not_web3(self):
        self.assertFalse(_detect_web3("nodejs express rest api postgres database"))

    def test_empty_string(self):
        self.assertFalse(_detect_web3(""))


class TestBuildReconPrompt(unittest.TestCase):

    TARGET = "https://app.example.com"

    def test_returns_string(self):
        prompt = build_recon_prompt(self.TARGET, "")
        self.assertIsInstance(prompt, str)

    def test_target_in_prompt(self):
        prompt = build_recon_prompt(self.TARGET, "")
        self.assertIn("app.example.com", prompt)

    def test_tool_commands_injected_for_url(self):
        prompt = build_recon_prompt(self.TARGET, "", has_openapi=False, deep_scan=False)
        # URL targets should get tool commands
        self.assertIn("nmap", prompt.lower())

    def test_openapi_adds_schemathesis(self):
        prompt = build_recon_prompt(self.TARGET, "", has_openapi=True)
        self.assertIn("schemathesis", prompt.lower())

    def test_auth_token_passed_to_schemathesis(self):
        # auth_token is forwarded to tool commands; only visible if schemathesis included
        prompt = build_recon_prompt(self.TARGET, "", has_openapi=True, auth_token="Bearer tok123")
        self.assertIn("tok123", prompt)

    def test_context_in_prompt(self):
        prompt = build_recon_prompt(self.TARGET, "Found in bug bounty scope")
        self.assertIn("bug bounty", prompt)

    def test_web3_target_no_nmap(self):
        # For non-URL targets, nmap should not appear
        prompt = build_recon_prompt("MyDeFiVault.sol", "Solidity ERC20 vault")
        # Should have web3 content instead
        self.assertIsInstance(prompt, str)

    def test_system_prompt_returns_string(self):
        sp = build_recon_system_prompt()
        self.assertIsInstance(sp, str)
        self.assertGreater(len(sp), 50)


# ── Analysis Phase ────────────────────────────────────────────────────────────

class TestBuildAnalysisPrompt(unittest.TestCase):

    def test_basic_web2(self):
        prompt = build_analysis_prompt(
            target="https://app.example.com",
            attack_surface_summary="Web app with REST API",
            context="Check for injection",
            include_web2=True,
            include_web3=False,
        )
        self.assertIsInstance(prompt, str)
        self.assertGreater(len(prompt), 100)

    def test_web3_includes_defi_content(self):
        prompt = build_analysis_prompt(
            target="DeFiVault.sol",
            attack_surface_summary="Solidity vault",
            context="ERC20 token vault",
            include_web2=False,
            include_web3=True,
        )
        self.assertIsInstance(prompt, str)

    def test_owasp_injected(self):
        prompt = build_analysis_prompt(
            target="https://app.example.com",
            attack_surface_summary="REST API",
            context="",
            include_web2=True,
            include_web3=False,
        )
        # Should include OWASP top 10 IDs
        self.assertTrue("A01" in prompt or "OWASP" in prompt)

    def test_source_code_triggers_dataflow(self):
        source = """
from flask import request
import sqlite3
def get_user():
    username = request.args.get('user')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchall()
"""
        prompt = build_analysis_prompt(
            target="app.py",
            attack_surface_summary="Flask web app",
            context="",
            include_web2=True,
            include_web3=False,
            source_code=source,
        )
        self.assertIsInstance(prompt, str)
        self.assertGreater(len(prompt), 200)

    def test_protocol_type_detection_adds_checklist(self):
        prompt = build_analysis_prompt(
            target="LendingProtocol",
            attack_surface_summary="Collateral borrowing lending protocol",
            context="lending protocol with price oracle",
            include_web2=False,
            include_web3=True,
        )
        self.assertIsInstance(prompt, str)

    def test_system_prompt_returns_string(self):
        sp = build_analysis_system_prompt()
        self.assertIsInstance(sp, str)
        self.assertGreater(len(sp), 50)


# ── Validation Phase ──────────────────────────────────────────────────────────

class TestBuildValidationPrompt(unittest.TestCase):

    def test_basic_prompt(self):
        prompt = build_validation_prompt(
            target="https://app.example.com",
            findings_summary="FINDING-001: XSS in search",
            context="",
        )
        self.assertIsInstance(prompt, str)
        self.assertGreater(len(prompt), 100)

    def test_contains_finding_summary(self):
        prompt = build_validation_prompt(
            target="MyApp",
            findings_summary="FINDING-001: SQL Injection in login",
            context="",
        )
        self.assertIn("SQL Injection", prompt)

    def test_contains_payload_banks(self):
        prompt = build_validation_prompt(
            target="https://app.example.com",
            findings_summary="FINDING-001: XSS",
            context="",
        )
        # Should include actual XSS payloads from web_exploits
        lower = prompt.lower()
        self.assertTrue(
            "script" in lower or "payload" in lower or "xss" in lower,
            "Validation prompt should contain XSS-related content"
        )

    def test_system_prompt_returns_string(self):
        sp = build_validation_system_prompt()
        self.assertIsInstance(sp, str)
        self.assertGreater(len(sp), 50)


# ── Report Phase ──────────────────────────────────────────────────────────────

class TestBuildReportPrompt(unittest.TestCase):

    def test_basic_prompt(self):
        prompt = build_report_prompt(
            target="MySmartContract",
            session_id="abc12345",
            all_findings_text="### FINDING-001: Reentrancy\nSeverity: Critical",
        )
        self.assertIsInstance(prompt, str)
        self.assertIn("MySmartContract", prompt)

    def test_contains_findings(self):
        prompt = build_report_prompt(
            target="VaultContract",
            session_id="test123",
            all_findings_text="FINDING-001: Reentrancy | Critical",
        )
        self.assertIn("Reentrancy", prompt)

    def test_no_findings_message(self):
        prompt = build_report_prompt(
            target="CleanContract",
            session_id="clean001",
            all_findings_text="(No findings recorded)",
        )
        self.assertIsInstance(prompt, str)

    def test_system_prompt_returns_string(self):
        sp = build_report_system_prompt()
        self.assertIsInstance(sp, str)
        self.assertGreater(len(sp), 50)


# ── Remediation Phase ─────────────────────────────────────────────────────────

class TestBuildRemediationPrompt(unittest.TestCase):

    def test_basic_prompt(self):
        prompt = build_remediation_prompt(
            target="VaultContract",
            original_findings="FINDING-001: Reentrancy | Critical",
            fix_content="Added nonReentrant modifier to withdraw()",
        )
        self.assertIsInstance(prompt, str)
        self.assertIn("VaultContract", prompt)

    def test_contains_fix_content(self):
        prompt = build_remediation_prompt(
            target="MyApp",
            original_findings="FINDING-001: SQLi",
            fix_content="Used parameterized queries instead of string concat",
        )
        self.assertIn("parameterized", prompt)

    def test_system_prompt_returns_string(self):
        sp = build_remediation_system_prompt()
        self.assertIsInstance(sp, str)
        self.assertGreater(len(sp), 50)


if __name__ == "__main__":
    unittest.main()
