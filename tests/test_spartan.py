"""
Tests for agent/spartan.py — SpartanAgent orchestration (no LLM calls)
"""
import unittest
from unittest.mock import patch, MagicMock

from agent.session import Finding, Session
from agent.spartan import SpartanAgent


def _make_agent(target: str = "TestContract") -> SpartanAgent:
    session = Session(target=target)
    return SpartanAgent(session)


class TestSpartanAgentInit(unittest.TestCase):

    def test_init_with_session(self):
        session = Session(target="MyApp")
        agent = SpartanAgent(session)
        self.assertEqual(agent.session.target, "MyApp")
        self.assertIsNone(agent.audit_config)
        self.assertFalse(agent._pending_auth_check)

    def test_init_without_session_creates_default(self):
        agent = SpartanAgent()
        self.assertIsNotNone(agent.session)

    def test_new_session_classmethod(self):
        agent = SpartanAgent.new_session(target="Vault")
        self.assertEqual(agent.session.target, "Vault")
        self.assertEqual(agent.session.phase, "Recon")


class TestSetTarget(unittest.TestCase):

    def test_set_target_updates_target(self):
        agent = _make_agent("old-target")
        msg = agent.set_target("new-target")
        self.assertEqual(agent.session.target, "new-target")
        self.assertIn("new-target", msg)

    def test_set_target_resets_phase_to_recon(self):
        agent = _make_agent()
        agent.session.set_phase("Analysis")
        agent.set_target("AnotherTarget")
        self.assertEqual(agent.session.phase, "Recon")

    def test_set_same_target_no_close_message(self):
        agent = _make_agent("SameTarget")
        msg = agent.set_target("SameTarget")
        self.assertNotIn("closed", msg.lower())


class TestProcessInputRouting(unittest.TestCase):

    def setUp(self):
        self.agent = _make_agent("TestTarget")

    def test_status_command(self):
        result = self.agent.process_input("status")
        self.assertIn("TestTarget", result)

    def test_findings_empty(self):
        result = self.agent.process_input("findings")
        self.assertIn("No findings", result)

    def test_findings_with_data(self):
        fid = self.agent.session.next_finding_id()
        f = Finding(fid, "XSS Bug", "High", "XSS", "TestTarget")
        self.agent.session.add_finding(f)
        result = self.agent.process_input("findings")
        self.assertIn("XSS Bug", result)

    def test_show_finding(self):
        fid = self.agent.session.next_finding_id()
        f = Finding(fid, "SSRF in proxy", "Critical", "SSRF", "TestTarget")
        self.agent.session.add_finding(f)
        result = self.agent.process_input(f"finding {fid}")
        self.assertIn("SSRF in proxy", result)

    def test_show_nonexistent_finding(self):
        result = self.agent.process_input("finding FINDING-999")
        self.assertIn("not found", result.lower())

    def test_model_command(self):
        result = self.agent.process_input("model")
        self.assertIn("model", result.lower())

    def test_empty_input_no_target(self):
        agent = SpartanAgent()
        agent.session.target = "unset"
        result = agent.process_input("")
        self.assertIn("target", result.lower())

    def test_save_command(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("agent.session.SESSIONS_DIR", Path(tmpdir)):
                result = self.agent.process_input("save")
                self.assertIn("saved", result.lower())

    def test_authorization_not_confirmed(self):
        agent = _make_agent()
        agent._pending_auth_check = True
        result = agent.process_input("no")
        self.assertIn("authorized", result.lower())

    def test_authorization_confirmed_clears_pending(self):
        agent = _make_agent()
        agent._pending_auth_check = True
        with patch.object(agent, "_begin_recon", return_value="recon started"):
            result = agent.process_input("confirmed")
        self.assertFalse(agent._pending_auth_check)


class TestAdvancePhase(unittest.TestCase):

    def test_advance_from_recon(self):
        agent = _make_agent()
        agent.session.set_phase("Recon")
        with patch.object(agent, "_run_current_phase", return_value=""):
            result = agent._advance_and_continue()
        self.assertEqual(agent.session.phase, "Analysis")

    def test_advance_from_last_phase(self):
        agent = _make_agent()
        agent.session.set_phase("Remediation")
        result = agent._advance_and_continue()
        self.assertIn("final phase", result.lower())


class TestRegisterFindingManually(unittest.TestCase):

    def test_register_returns_finding(self):
        agent = _make_agent()
        f = agent.register_finding_manually(
            title="Integer Overflow",
            severity="High",
            category="Arithmetic",
            summary="Balance can overflow",
            cvss_score=8.1,
            poc="overflow(2**256 - 1)",
        )
        self.assertIsInstance(f, Finding)
        self.assertEqual(f.severity, "High")
        self.assertTrue(f.confirmed)
        self.assertIn(f, agent.session.findings)

    def test_register_increments_id(self):
        agent = _make_agent()
        f1 = agent.register_finding_manually("Bug 1", "Low", "test")
        f2 = agent.register_finding_manually("Bug 2", "Medium", "test")
        self.assertNotEqual(f1.finding_id, f2.finding_id)


class TestExtractAndRegisterFindings(unittest.TestCase):

    def _make_json_block(self, **kwargs) -> str:
        import json
        defaults = {
            "title": "Reentrancy in withdraw()",
            "severity": "Critical",
            "category": "Reentrancy",
            "file_path": "contracts/Vault.sol",
            "line_number": 42,
            "vulnerable_snippet": "token.transfer(msg.sender, amount);\nbalances[msg.sender] -= amount;",
            "attack_prerequisite": "Attacker must have a balance",
            "impact_justification": "All funds can be drained",
            "confidence": 90,
            "status": "DRAFT",
        }
        defaults.update(kwargs)
        return f"```json\n{json.dumps(defaults)}\n```"

    def test_extracts_json_finding(self):
        agent = _make_agent()
        response = self._make_json_block()
        agent._extract_and_register_findings(response, "Analysis")
        self.assertEqual(len(agent.session.findings), 1)
        self.assertEqual(agent.session.findings[0].title, "Reentrancy in withdraw()")

    def test_rejects_finding_without_evidence(self):
        agent = _make_agent()
        import json
        data = {
            "title": "Hallucinated Bug",
            "severity": "Critical",
            "category": "Reentrancy",
            # No file_path, line_number, or vulnerable_snippet
            "confidence": 90,
            "status": "CONFIRMED",
        }
        response = f"```json\n{json.dumps(data)}\n```"
        agent._extract_and_register_findings(response, "Analysis")
        self.assertEqual(len(agent.session.findings), 0)  # rejected — no evidence

    def test_no_duplicate_findings_same_file_line(self):
        agent = _make_agent()
        response = self._make_json_block(
            file_path="Vault.sol", line_number=42
        )
        agent._extract_and_register_findings(response, "Analysis")
        agent._extract_and_register_findings(response, "Analysis")
        # Same file+line → dedup
        matching = [f for f in agent.session.findings if f.title == "Reentrancy in withdraw()"]
        self.assertEqual(len(matching), 1)

    def test_no_duplicate_findings_jaccard(self):
        agent = _make_agent()
        r1 = self._make_json_block(
            title="Reentrancy in withdraw()", file_path="Vault.sol", line_number=10
        )
        r2 = self._make_json_block(
            title="Reentrancy in withdraw()", file_path="Vault.sol", line_number=99
        )
        agent._extract_and_register_findings(r1, "Analysis")
        agent._extract_and_register_findings(r2, "Analysis")
        # Same title → Jaccard dedup kicks in
        matching = [f for f in agent.session.findings if "Reentrancy" in f.title]
        self.assertEqual(len(matching), 1)

    def test_draft_status_remains_draft_without_devil_advocate(self):
        agent = _make_agent()
        response = self._make_json_block(status="DRAFT", confidence=70)
        agent._extract_and_register_findings(response, "Analysis")
        self.assertEqual(len(agent.session.findings), 1)
        self.assertEqual(agent.session.findings[0].status, "DRAFT")

    def test_confirmed_status_triggers_devil_advocate(self):
        agent = _make_agent()
        response = self._make_json_block(status="CONFIRMED", confidence=90)
        # Mock devil's advocate to return CONFIRMED so finding registers
        with patch("agent.tools.devil_advocate.devil_advocate_check") as mock_da:
            from agent.tools.devil_advocate import DevilVerdict
            mock_da.return_value = DevilVerdict("CONFIRMED", "Looks real", 90)
            agent._extract_and_register_findings(response, "Analysis")
        self.assertEqual(len(agent.session.findings), 1)
        self.assertEqual(agent.session.findings[0].status, "CONFIRMED")

    def test_devil_advocate_rejects_finding(self):
        agent = _make_agent()
        response = self._make_json_block(status="CONFIRMED", confidence=90)
        with patch("agent.tools.devil_advocate.devil_advocate_check") as mock_da:
            from agent.tools.devil_advocate import DevilVerdict
            mock_da.return_value = DevilVerdict("REJECTED", "Protected by modifier", 85)
            agent._extract_and_register_findings(response, "Analysis")
        # Still registered but as REJECTED
        self.assertEqual(len(agent.session.findings), 1)
        self.assertEqual(agent.session.findings[0].status, "REJECTED")

    def test_no_findings_from_clean_response(self):
        agent = _make_agent()
        response = "No vulnerabilities found. The code looks clean."
        agent._extract_and_register_findings(response, "Analysis")
        self.assertEqual(len(agent.session.findings), 0)

    def test_multiple_findings_in_list(self):
        import json
        agent = _make_agent()
        findings = [
            {
                "title": "Bug A", "severity": "High", "category": "SQLi",
                "file_path": "app.py", "line_number": 10,
                "vulnerable_snippet": "cursor.execute(user_input)",
                "confidence": 80, "status": "DRAFT",
            },
            {
                "title": "Bug B", "severity": "Medium", "category": "XSS",
                "file_path": "app.py", "line_number": 25,
                "vulnerable_snippet": "document.write(data)",
                "confidence": 75, "status": "DRAFT",
            },
        ]
        response = f"```json\n{json.dumps(findings)}\n```"
        agent._extract_and_register_findings(response, "Analysis")
        self.assertEqual(len(agent.session.findings), 2)


class TestHelperMethods(unittest.TestCase):

    def test_extract_target_name_url(self):
        agent = _make_agent()
        name = agent._extract_target_name("please audit https://app.example.com/api")
        self.assertIn("example.com", name)

    def test_extract_target_name_address(self):
        agent = _make_agent()
        name = agent._extract_target_name("check 0xAbCd1234567890abcdef1234567890abcdef1234")
        self.assertIn("0x", name)

    def test_extract_target_name_generic(self):
        agent = _make_agent()
        name = agent._extract_target_name("audit the vault contract")
        self.assertIsInstance(name, str)
        self.assertGreater(len(name), 0)

    def test_is_suspicious_target(self):
        agent = _make_agent()
        self.assertTrue(agent._is_suspicious_target("hack live production system"))

    def test_is_not_suspicious(self):
        agent = _make_agent()
        self.assertFalse(agent._is_suspicious_target("audit my local test contract"))

    def test_get_last_recon_summary_empty(self):
        agent = _make_agent()
        result = agent._get_last_recon_summary()
        self.assertIsInstance(result, str)

    def test_get_findings_summary_empty(self):
        agent = _make_agent()
        result = agent._get_findings_summary_text()
        self.assertIn("No findings", result)

    def test_get_all_findings_detailed_empty(self):
        agent = _make_agent()
        result = agent._get_all_findings_detailed()
        self.assertIn("No reportable findings", result)

    def test_determine_next_action_recon(self):
        agent = _make_agent()
        action = agent._determine_next_action("Recon", "")
        self.assertIsInstance(action, str)
        self.assertIn("Phase 2", action)

    def test_determine_next_action_unknown(self):
        agent = _make_agent()
        action = agent._determine_next_action("UnknownPhase", "")
        self.assertIsInstance(action, str)


class TestLoadConfigFile(unittest.TestCase):

    def test_load_valid_config(self):
        import tempfile, os, textwrap
        yaml_content = textwrap.dedent("""\
            name: "My Audit"
            scope:
              url: "https://app.example.com"
        """)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(yaml_content)
            tmp = f.name
        try:
            agent = _make_agent()
            result = agent.load_config_file(tmp)
            self.assertIsInstance(result, str)
            self.assertIn("loaded", result.lower())
            self.assertIsNotNone(agent.audit_config)
        finally:
            os.unlink(tmp)

    def test_load_nonexistent_config(self):
        agent = _make_agent()
        result = agent.load_config_file("/nonexistent/path/config.yaml")
        self.assertIn("error", result.lower())
        self.assertIsNone(agent.audit_config)

    def test_load_config_sets_target_from_scope(self):
        import tempfile, os, textwrap
        yaml_content = textwrap.dedent("""\
            scope:
              url: "https://vault.defi.com"
        """)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(yaml_content)
            tmp = f.name
        try:
            agent = SpartanAgent()  # target = "unset"
            agent.load_config_file(tmp)
            self.assertEqual(agent.session.target, "https://vault.defi.com")
        finally:
            os.unlink(tmp)


if __name__ == "__main__":
    unittest.main()
