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

    def test_extracts_potential_finding(self):
        agent = _make_agent()
        response = (
            "Potential Finding: Reentrancy in withdraw()\n"
            "Severity: Critical\n"
            "Class: Reentrancy\n"
            "Description: Funds can be drained via reentrancy."
        )
        agent._extract_and_register_findings(response, "Analysis")
        self.assertGreater(len(agent.session.findings), 0)
        titles = [f.title for f in agent.session.findings]
        self.assertIn("Reentrancy in withdraw()", titles)

    def test_extracts_finding_bracket_format(self):
        agent = _make_agent()
        response = (
            "[FINDING-001] — Price Oracle Manipulation\n"
            "Severity: High\n"
            "Category: Oracle\n"
        )
        agent._extract_and_register_findings(response, "Analysis")
        self.assertGreater(len(agent.session.findings), 0)

    def test_no_duplicate_findings(self):
        agent = _make_agent()
        response = (
            "Potential Finding: Reentrancy in withdraw()\n"
            "Severity: Critical\n"
        )
        agent._extract_and_register_findings(response, "Analysis")
        agent._extract_and_register_findings(response, "Analysis")
        titles = [f.title for f in agent.session.findings if f.title == "Reentrancy in withdraw()"]
        self.assertEqual(len(titles), 1)

    def test_no_false_finding_from_clean_response(self):
        agent = _make_agent()
        response = "No vulnerabilities found. The code looks clean."
        agent._extract_and_register_findings(response, "Analysis")
        self.assertEqual(len(agent.session.findings), 0)


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
        self.assertIn("No findings", result)

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
