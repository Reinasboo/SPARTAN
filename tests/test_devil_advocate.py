"""
Tests for agent/tools/devil_advocate.py — verification pass
"""
import unittest
from unittest.mock import patch

from agent.tools.devil_advocate import (
    devil_advocate_check,
    _parse_verdict,
    DevilVerdict,
)


class TestDevilVerdict(unittest.TestCase):

    def test_verdict_confirmed(self):
        v = DevilVerdict("CONFIRMED", "Real vulnerability", 90)
        self.assertEqual(v.verdict, "CONFIRMED")
        self.assertEqual(v.confidence, 90)

    def test_verdict_rejected(self):
        v = DevilVerdict("REJECTED", "Protected by modifier", 85)
        self.assertEqual(v.verdict, "REJECTED")

    def test_repr(self):
        v = DevilVerdict("CONFIRMED", "reason", 80)
        r = repr(v)
        self.assertIn("CONFIRMED", r)
        self.assertIn("80%", r)


class TestParseVerdict(unittest.TestCase):

    def test_parse_confirmed_json(self):
        raw = '{"verdict": "CONFIRMED", "reason": "Funds drained", "confidence": 88}'
        v = _parse_verdict(raw)
        self.assertEqual(v.verdict, "CONFIRMED")
        self.assertEqual(v.confidence, 88)
        self.assertEqual(v.reason, "Funds drained")

    def test_parse_rejected_json(self):
        raw = '{"verdict": "REJECTED", "reason": "Guarded by onlyOwner", "confidence": 92}'
        v = _parse_verdict(raw)
        self.assertEqual(v.verdict, "REJECTED")
        self.assertEqual(v.confidence, 92)

    def test_parse_needs_more_evidence_json(self):
        raw = '{"verdict": "NEEDS_MORE_EVIDENCE", "reason": "Cannot confirm", "confidence": 40}'
        v = _parse_verdict(raw)
        self.assertEqual(v.verdict, "NEEDS_MORE_EVIDENCE")

    def test_parse_json_with_surrounding_text(self):
        raw = 'After analysis:\n{"verdict": "CONFIRMED", "reason": "Real", "confidence": 75}\nEnd.'
        v = _parse_verdict(raw)
        self.assertEqual(v.verdict, "CONFIRMED")

    def test_parse_invalid_verdict_defaults_to_needs_more(self):
        raw = '{"verdict": "MAYBE", "reason": "unclear", "confidence": 50}'
        v = _parse_verdict(raw)
        self.assertEqual(v.verdict, "NEEDS_MORE_EVIDENCE")

    def test_fallback_text_confirmed(self):
        v = _parse_verdict("After review, CONFIRMED — this is exploitable.")
        self.assertEqual(v.verdict, "CONFIRMED")

    def test_fallback_text_rejected(self):
        v = _parse_verdict("This is REJECTED — guarded by require(msg.sender == owner).")
        self.assertEqual(v.verdict, "REJECTED")

    def test_fallback_no_keyword_defaults_needs_more(self):
        v = _parse_verdict("The code is interesting and could potentially...")
        self.assertEqual(v.verdict, "NEEDS_MORE_EVIDENCE")

    def test_confidence_clamped_0_to_100(self):
        raw = '{"verdict": "CONFIRMED", "reason": "test", "confidence": 150}'
        v = _parse_verdict(raw)
        self.assertLessEqual(v.confidence, 100)

        raw2 = '{"verdict": "CONFIRMED", "reason": "test", "confidence": -10}'
        v2 = _parse_verdict(raw2)
        self.assertGreaterEqual(v2.confidence, 0)


class TestDevilAdvocateCheck(unittest.TestCase):

    @patch("agent.tools.devil_advocate.chat")
    def test_returns_verdict(self, mock_chat):
        mock_chat.return_value = '{"verdict": "CONFIRMED", "reason": "Real", "confidence": 85}'
        v = devil_advocate_check(
            title="Reentrancy in withdraw()",
            severity="Critical",
            category="Reentrancy",
            file_path="Vault.sol",
            line_number=42,
            vulnerable_snippet="token.transfer(msg.sender, amount);\nbalances[msg.sender] -= amount;",
            attack_prerequisite="Attacker must have a balance",
            impact_justification="All funds can be drained",
            source_context="function withdraw() external { ... }",
        )
        self.assertEqual(v.verdict, "CONFIRMED")
        self.assertEqual(v.confidence, 85)

    @patch("agent.tools.devil_advocate.chat")
    def test_handles_llm_exception(self, mock_chat):
        mock_chat.side_effect = Exception("API error")
        v = devil_advocate_check(
            title="Some Bug",
            severity="High",
            category="Test",
            file_path="app.py",
            line_number=1,
            vulnerable_snippet="code",
            attack_prerequisite="None",
            impact_justification="Impact",
        )
        self.assertEqual(v.verdict, "NEEDS_MORE_EVIDENCE")
        self.assertEqual(v.confidence, 0)

    @patch("agent.tools.devil_advocate.chat")
    def test_calls_chat_with_messages(self, mock_chat):
        mock_chat.return_value = '{"verdict": "REJECTED", "reason": "Guarded", "confidence": 90}'
        devil_advocate_check(
            title="SSRF via URL param",
            severity="High",
            category="SSRF",
            file_path="server.py",
            line_number=20,
            vulnerable_snippet="requests.get(url)",
            attack_prerequisite="Control url param",
            impact_justification="SSRF to internal services",
        )
        self.assertTrue(mock_chat.called)
        call_args = mock_chat.call_args[0][0]  # first positional arg is messages
        self.assertIsInstance(call_args, list)
        self.assertEqual(call_args[0]["role"], "system")
        self.assertEqual(call_args[1]["role"], "user")


if __name__ == "__main__":
    unittest.main()
