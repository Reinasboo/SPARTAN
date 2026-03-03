"""
Tests for agent/session.py — Finding, Session, SessionRegistry
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent.session import Finding, Session, SessionRegistry


class TestFinding(unittest.TestCase):

    def _make_finding(self, **kwargs) -> Finding:
        defaults = dict(
            finding_id="FINDING-001",
            title="Test Reentrancy",
            severity="High",
            category="Reentrancy",
            target="VaultContract",
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_finding_creation_defaults(self):
        f = self._make_finding()
        self.assertEqual(f.finding_id, "FINDING-001")
        self.assertEqual(f.severity, "High")
        self.assertEqual(f.remediation_status, "open")
        self.assertFalse(f.confirmed)
        self.assertEqual(f.cvss_score, 0.0)

    def test_finding_to_dict_roundtrip(self):
        f = self._make_finding(summary="Funds can be drained", cvss_score=9.1)
        d = f.to_dict()
        self.assertEqual(d["severity"], "High")
        self.assertEqual(d["cvss_score"], 9.1)
        # Reconstruct
        f2 = Finding.from_dict(d)
        self.assertEqual(f2.title, f.title)
        self.assertEqual(f2.cvss_score, 9.1)

    def test_finding_one_liner_contains_id(self):
        f = self._make_finding()
        line = f.one_liner()
        self.assertIn("FINDING-001", line)
        self.assertIn("High", line)

    def test_finding_one_liner_unconfirmed_label(self):
        f = self._make_finding(confirmed=False)
        line = f.one_liner()
        self.assertIn("[UNCONFIRMED]", line)

    def test_finding_confirmed_no_unconfirmed_label(self):
        f = self._make_finding(confirmed=True)
        line = f.one_liner()
        self.assertNotIn("[UNCONFIRMED]", line)


class TestSession(unittest.TestCase):

    def setUp(self):
        self.session = Session(target="TestContract")

    def test_initial_state(self):
        self.assertEqual(self.session.phase, "Recon")
        self.assertEqual(self.session.target, "TestContract")
        self.assertEqual(self.session.findings, [])
        self.assertEqual(self.session.messages, [])

    def test_session_id_is_8_chars(self):
        self.assertEqual(len(self.session.session_id), 8)

    def test_next_finding_id_increments(self):
        id1 = self.session.next_finding_id()
        id2 = self.session.next_finding_id()
        id3 = self.session.next_finding_id()
        self.assertEqual(id1, "FINDING-001")
        self.assertEqual(id2, "FINDING-002")
        self.assertEqual(id3, "FINDING-003")

    def test_add_and_get_finding(self):
        fid = self.session.next_finding_id()
        f = Finding(fid, "XSS Bug", "Medium", "XSS", "TestContract")
        self.session.add_finding(f)
        retrieved = self.session.get_finding(fid)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.title, "XSS Bug")

    def test_get_finding_nonexistent_returns_none(self):
        result = self.session.get_finding("FINDING-999")
        self.assertIsNone(result)

    def test_set_phase_valid(self):
        for phase in ["Recon", "Analysis", "Validation", "Report", "Remediation"]:
            self.session.set_phase(phase)
            self.assertEqual(self.session.phase, phase)

    def test_set_phase_invalid_raises(self):
        with self.assertRaises(ValueError):
            self.session.set_phase("InvalidPhase")

    def test_advance_phase_sequence(self):
        self.session.set_phase("Recon")
        self.assertEqual(self.session.advance_phase(), "Analysis")
        self.assertEqual(self.session.advance_phase(), "Validation")
        self.assertEqual(self.session.advance_phase(), "Report")
        self.assertEqual(self.session.advance_phase(), "Remediation")
        # At last phase, returns None
        self.assertIsNone(self.session.advance_phase())
        self.assertEqual(self.session.phase, "Remediation")

    def test_add_message(self):
        self.session.add_message("user", "hello")
        self.session.add_message("assistant", "world")
        self.assertEqual(len(self.session.messages), 2)
        self.assertEqual(self.session.messages[0]["role"], "user")
        self.assertEqual(self.session.messages[1]["content"], "world")

    def test_severity_counts(self):
        for sev in ["Critical", "High", "High", "Medium"]:
            fid = self.session.next_finding_id()
            self.session.add_finding(Finding(fid, f"{sev} bug", sev, "test", "target"))
        counts = self.session.severity_counts()
        self.assertEqual(counts["Critical"], 1)
        self.assertEqual(counts["High"], 2)
        self.assertEqual(counts["Medium"], 1)

    def test_severity_summary_empty(self):
        self.assertEqual(self.session.severity_summary(), "No findings yet.")

    def test_severity_summary_nonempty(self):
        fid = self.session.next_finding_id()
        self.session.add_finding(Finding(fid, "Critical bug", "Critical", "RCE", "target"))
        summary = self.session.severity_summary()
        self.assertIn("Critical", summary)

    def test_serialization_roundtrip(self):
        fid = self.session.next_finding_id()
        self.session.add_finding(Finding(fid, "SSRF", "High", "SSRF", "target", summary="test"))
        self.session.add_message("user", "audit this")
        d = self.session.to_dict()
        s2 = Session.from_dict(d)
        self.assertEqual(s2.target, self.session.target)
        self.assertEqual(len(s2.findings), 1)
        self.assertEqual(s2.findings[0].title, "SSRF")
        self.assertEqual(len(s2.messages), 1)

    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("agent.session.SESSIONS_DIR", Path(tmpdir)):
                fid = self.session.next_finding_id()
                self.session.add_finding(Finding(fid, "Bug", "Low", "misc", "target"))
                path = self.session.save()
                self.assertTrue(path.exists())

                loaded = Session.load(self.session.session_id)
                self.assertEqual(loaded.target, "TestContract")
                self.assertEqual(len(loaded.findings), 1)

    def test_load_nonexistent_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("agent.session.SESSIONS_DIR", Path(tmpdir)):
                with self.assertRaises(FileNotFoundError):
                    Session.load("nonexistent")

    def test_status_block_contains_key_info(self):
        block = self.session.status_block()
        self.assertIn("TestContract", block)
        self.assertIn("Recon", block)


if __name__ == "__main__":
    unittest.main()
