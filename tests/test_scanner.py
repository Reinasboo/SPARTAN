"""
Tests for agent/tools/scanner.py — Semgrep/Slither integration
"""
import unittest
from unittest.mock import patch, MagicMock
import json
from pathlib import Path

from agent.tools.scanner import (
    ScannerFinding,
    ScannerResult,
    scan_source,
    scan_code_string,
    _semgrep_available,
    _slither_available,
    run_semgrep,
    run_slither,
)


class TestScannerFinding(unittest.TestCase):

    def test_scanner_finding_creation(self):
        f = ScannerFinding(
            tool="semgrep",
            rule_id="python.lang.security.audit.sql-injection",
            message="SQL injection via string concatenation",
            severity="ERROR",
            file_path="app.py",
            line_number=42,
            snippet="cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
            category="CWE-89",
        )
        self.assertEqual(f.tool, "semgrep")
        self.assertEqual(f.line_number, 42)
        self.assertEqual(f.severity, "ERROR")


class TestScannerResult(unittest.TestCase):

    def test_empty_result(self):
        r = ScannerResult()
        self.assertFalse(r.has_findings)
        self.assertEqual(r.tools_run, [])
        self.assertEqual(r.findings, [])

    def test_has_findings_true(self):
        r = ScannerResult()
        r.findings.append(ScannerFinding(
            tool="semgrep", rule_id="test", message="Test",
            severity="ERROR", file_path="f.py", line_number=1,
        ))
        self.assertTrue(r.has_findings)

    def test_to_context_string_empty_no_tools(self):
        r = ScannerResult()
        self.assertEqual(r.to_context_string(), "")

    def test_to_context_string_no_findings_with_tools(self):
        r = ScannerResult(tools_run=["semgrep"])
        ctx = r.to_context_string()
        self.assertIn("semgrep", ctx)
        self.assertIn("No findings", ctx)

    def test_to_context_string_with_finding(self):
        r = ScannerResult(tools_run=["semgrep"])
        r.findings.append(ScannerFinding(
            tool="semgrep",
            rule_id="test.rule",
            message="SQL injection found",
            severity="ERROR",
            file_path="app.py",
            line_number=10,
            snippet="cursor.execute(user_input)",
        ))
        ctx = r.to_context_string()
        self.assertIn("semgrep", ctx.lower())
        self.assertIn("SQL injection", ctx)
        self.assertIn("app.py", ctx)
        self.assertIn("10", ctx)

    def test_skipped_tools_tracked(self):
        r = ScannerResult(skipped=["semgrep", "slither"])
        self.assertEqual(len(r.skipped), 2)


class TestSemgrepUnavailable(unittest.TestCase):

    @patch("agent.tools.scanner.shutil.which", return_value=None)
    def test_semgrep_unavailable_returns_false(self, mock_which):
        self.assertFalse(_semgrep_available())

    @patch("agent.tools.scanner.shutil.which", return_value=None)
    def test_run_semgrep_returns_empty_when_unavailable(self, mock_which):
        findings = run_semgrep("/some/path")
        self.assertEqual(findings, [])


class TestSlitherUnavailable(unittest.TestCase):

    @patch("agent.tools.scanner.shutil.which", return_value=None)
    def test_slither_unavailable_returns_false(self, mock_which):
        self.assertFalse(_slither_available())

    @patch("agent.tools.scanner.shutil.which", return_value=None)
    def test_run_slither_returns_empty_when_unavailable(self, mock_which):
        findings = run_slither("/some/path")
        self.assertEqual(findings, [])


class TestScanSource(unittest.TestCase):

    def test_nonexistent_path_returns_error(self):
        result = scan_source("/definitely/does/not/exist/code.py")
        self.assertFalse(result.has_findings)
        self.assertTrue(len(result.errors) > 0)

    @patch("agent.tools.scanner._semgrep_available", return_value=False)
    @patch("agent.tools.scanner._slither_available", return_value=False)
    def test_no_tools_available_returns_result_with_skipped(self, mock_sl, mock_sg):
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            f.write(b"print('hello')")
            tmp = f.name
        try:
            result = scan_source(tmp)
            self.assertFalse(result.has_findings)
            self.assertIn("semgrep", result.skipped)
        finally:
            os.unlink(tmp)


class TestScanCodeString(unittest.TestCase):

    @patch("agent.tools.scanner._semgrep_available", return_value=False)
    @patch("agent.tools.scanner._slither_available", return_value=False)
    def test_python_code_string_no_crash(self, mock_sl, mock_sg):
        code = "def f(x):\n    return x"
        result = scan_code_string(code, lang_hint="python")
        self.assertIsInstance(result, ScannerResult)

    @patch("agent.tools.scanner._semgrep_available", return_value=False)
    @patch("agent.tools.scanner._slither_available", return_value=False)
    def test_solidity_code_string_detected(self, mock_sl, mock_sg):
        code = "pragma solidity ^0.8.0;\ncontract Vault {}"
        result = scan_code_string(code, lang_hint="auto")
        # Solidity → slither checked, semgrep checked, both skipped (unavailable)
        self.assertIsInstance(result, ScannerResult)


class TestSemgrepParsing(unittest.TestCase):

    @patch("agent.tools.scanner._semgrep_available", return_value=True)
    @patch("agent.tools.scanner.subprocess.run")
    def test_semgrep_parses_output(self, mock_run, mock_avail):
        mock_output = json.dumps({
            "results": [{
                "check_id": "python.lang.security.audit.avoid-pickle",
                "path": "app.py",
                "start": {"line": 5},
                "extra": {
                    "message": "Avoid pickle — leads to RCE",
                    "severity": "ERROR",
                    "lines": "import pickle",
                    "metadata": {"category": "security", "cwe": ["CWE-502"]},
                },
            }]
        })
        mock_run.return_value = MagicMock(
            stdout=mock_output, returncode=0
        )
        findings = run_semgrep("/fake/path")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "python.lang.security.audit.avoid-pickle")
        self.assertEqual(findings[0].line_number, 5)
        self.assertEqual(findings[0].severity, "ERROR")

    @patch("agent.tools.scanner._semgrep_available", return_value=True)
    @patch("agent.tools.scanner.subprocess.run")
    def test_semgrep_handles_empty_results(self, mock_run, mock_avail):
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"results": []}), returncode=0
        )
        findings = run_semgrep("/fake/path")
        self.assertEqual(findings, [])

    @patch("agent.tools.scanner._semgrep_available", return_value=True)
    @patch("agent.tools.scanner.subprocess.run")
    def test_semgrep_handles_invalid_json(self, mock_run, mock_avail):
        mock_run.return_value = MagicMock(stdout="not json", returncode=1)
        findings = run_semgrep("/fake/path")
        self.assertEqual(findings, [])


class TestSlitherParsing(unittest.TestCase):

    @patch("agent.tools.scanner._slither_available", return_value=True)
    @patch("agent.tools.scanner.subprocess.run")
    def test_slither_parses_output(self, mock_run, mock_avail):
        mock_output = json.dumps({
            "results": {"detectors": [{
                "check": "reentrancy-eth",
                "impact": "High",
                "description": "Reentrancy in withdraw()",
                "elements": [{
                    "name": "withdraw",
                    "source_mapping": {
                        "filename_relative": "Vault.sol",
                        "lines": [42],
                    },
                }],
            }]}
        })
        mock_run.return_value = MagicMock(stdout=mock_output, returncode=0)
        findings = run_slither("/fake/Vault.sol")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "reentrancy-eth")
        self.assertEqual(findings[0].severity, "ERROR")  # High → ERROR
        self.assertEqual(findings[0].line_number, 42)

    @patch("agent.tools.scanner._slither_available", return_value=True)
    @patch("agent.tools.scanner.subprocess.run")
    def test_slither_handles_empty(self, mock_run, mock_avail):
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"results": {"detectors": []}}), returncode=0
        )
        findings = run_slither("/fake/Vault.sol")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
