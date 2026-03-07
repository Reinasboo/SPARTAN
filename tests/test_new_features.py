"""
Tests for the new spartan.py module-level helpers:
- _estimate_cvss_from_vector (CVSS recomputation)
- SpartanAgent._jaccard (semantic deduplication)
- SpartanAgent.inject_github_source (GitHub fetcher wiring)
- SpartanAgent.run_scanner_on_source (scanner wiring)
- confidence gating in _get_all_findings_detailed
"""
import unittest
from unittest.mock import patch, MagicMock

from agent.session import Finding, Session
from agent.spartan import SpartanAgent, _estimate_cvss_from_vector


def _make_agent(target: str = "TestContract") -> SpartanAgent:
    session = Session(target=target)
    return SpartanAgent(session)


class TestEstimateCvssFromVector(unittest.TestCase):

    def test_critical_network_vector(self):
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8
        score = _estimate_cvss_from_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        self.assertIsNotNone(score)
        self.assertGreater(score, 9.0)
        self.assertLessEqual(score, 10.0)

    def test_low_vector(self):
        # AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N → very low
        score = _estimate_cvss_from_vector(
            "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
        )
        self.assertIsNotNone(score)
        self.assertLess(score, 3.0)

    def test_invalid_vector_returns_none(self):
        score = _estimate_cvss_from_vector("not-a-vector")
        self.assertIsNone(score)

    def test_partial_vector_returns_none(self):
        score = _estimate_cvss_from_vector("AV:N/AC:L")
        self.assertIsNone(score)

    def test_zero_impact_returns_zero(self):
        # All CIA:N → impact 0 → score 0
        score = _estimate_cvss_from_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        )
        self.assertIsNotNone(score)
        self.assertEqual(score, 0.0)

    def test_medium_vector(self):
        score = _estimate_cvss_from_vector(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
        )
        self.assertIsNotNone(score)
        self.assertGreater(score, 3.0)
        self.assertLess(score, 8.0)


class TestJaccardSimilarity(unittest.TestCase):

    def test_identical_strings(self):
        agent = _make_agent()
        self.assertAlmostEqual(agent._jaccard("hello world", "hello world"), 1.0)

    def test_completely_different(self):
        agent = _make_agent()
        self.assertAlmostEqual(agent._jaccard("cat dog bird", "xyz abc def"), 0.0)

    def test_partial_overlap(self):
        agent = _make_agent()
        score = agent._jaccard("reentrancy in withdraw function", "reentrancy vulnerability withdraw")
        # Two shared tokens out of five unique tokens = 0.4 — confirm it's above zero
        # and below 1.0 (i.e., real partial overlap is detected).
        self.assertGreater(score, 0.0)
        self.assertLess(score, 1.0)

    def test_empty_strings(self):
        agent = _make_agent()
        self.assertEqual(agent._jaccard("", ""), 0.0)

    def test_reentrancy_titles_dedup(self):
        agent = _make_agent()
        score = agent._jaccard(
            "Reentrancy in withdraw()",
            "Reentrancy vulnerability in withdraw() function"
        )
        self.assertGreaterEqual(score, 0.6)


class TestIsDuplicate(unittest.TestCase):

    def test_same_file_and_line_is_dup(self):
        agent = _make_agent()
        fid = agent.session.next_finding_id()
        f = Finding(fid, "Bug A", "High", "Test", "target",
                    file_path="Vault.sol", line_number=42)
        agent.session.add_finding(f)
        self.assertTrue(agent._is_duplicate("Different Title", "Vault.sol", 42))

    def test_same_file_different_line_not_dup(self):
        agent = _make_agent()
        fid = agent.session.next_finding_id()
        f = Finding(fid, "Bug A", "High", "Test", "target",
                    file_path="Vault.sol", line_number=42)
        agent.session.add_finding(f)
        self.assertFalse(agent._is_duplicate("Totally Different Bug Title", "Vault.sol", 99))

    def test_jaccard_dedup_threshold(self):
        agent = _make_agent()
        fid = agent.session.next_finding_id()
        f = Finding(fid, "Reentrancy in withdraw()", "Critical", "Reentrancy", "target",
                    file_path="Vault.sol", line_number=10)
        agent.session.add_finding(f)
        # Same title → should be dup
        self.assertTrue(agent._is_duplicate("Reentrancy in withdraw()", "Vault.sol", 99))

    def test_empty_findings_never_dup(self):
        agent = _make_agent()
        self.assertFalse(agent._is_duplicate("Any Bug", "any.sol", 1))


class TestGetAllFindingsDetailedConfidenceGate(unittest.TestCase):

    def _add_finding(self, agent, title, confidence, status="DRAFT"):
        fid = agent.session.next_finding_id()
        f = Finding(
            fid, title, "High", "Test", agent.session.target,
            confidence=confidence, status=status,
        )
        agent.session.add_finding(f)

    def test_includes_high_confidence_findings(self):
        agent = _make_agent()
        self._add_finding(agent, "High Confidence Bug", 90)
        text = agent._get_all_findings_detailed(min_confidence=60)
        self.assertIn("High Confidence Bug", text)

    def test_excludes_low_confidence_findings(self):
        agent = _make_agent()
        self._add_finding(agent, "Low Confidence Bug", 30)
        text = agent._get_all_findings_detailed(min_confidence=60)
        self.assertNotIn("Low Confidence Bug", text)

    def test_excludes_rejected_findings(self):
        agent = _make_agent()
        self._add_finding(agent, "Rejected Bug", 90, status="REJECTED")
        text = agent._get_all_findings_detailed(min_confidence=60)
        self.assertNotIn("Rejected Bug", text)

    def test_confirmed_tier_label(self):
        agent = _make_agent()
        self._add_finding(agent, "Confirmed Bug", 90, status="CONFIRMED")
        text = agent._get_all_findings_detailed(min_confidence=0)
        self.assertIn("CONFIRMED", text)

    def test_no_findings_returns_no_reportable_message(self):
        agent = _make_agent()
        text = agent._get_all_findings_detailed()
        self.assertIn("No reportable findings", text)


class TestInjectGithubSource(unittest.TestCase):

    def test_invalid_url_returns_message(self):
        agent = _make_agent()
        result = agent.inject_github_source("not-a-github-url")
        self.assertIn("Not a recognisable", result)

    @patch("agent.tools.github_fetcher.fetch_github_repo")
    def test_fetch_error_returns_message(self, mock_fetch):
        from agent.tools.github_fetcher import FetchedRepo
        mock_fetch.return_value = FetchedRepo(
            owner="org", repo="repo", ref="main", error="Rate limited"
        )
        agent = _make_agent()
        result = agent.inject_github_source("https://github.com/org/repo")
        self.assertIn("failed", result.lower())

    @patch("agent.tools.github_fetcher.fetch_github_repo")
    def test_successful_fetch_stores_cache(self, mock_fetch):
        from agent.tools.github_fetcher import FetchedRepo
        mock_fetch.return_value = FetchedRepo(
            owner="org", repo="repo", ref="main",
            files={"contracts/Vault.sol": "pragma solidity ^0.8.0;\ncontract Vault {}"},
        )
        agent = _make_agent()
        result = agent.inject_github_source("https://github.com/org/repo")
        # Should return a summary
        self.assertIsInstance(result, str)
        # Cache should be populated
        self.assertTrue(len(agent._github_source_cache) > 0)


class TestRunScannerOnSource(unittest.TestCase):

    @patch("agent.tools.scanner.scan_source")
    def test_scanner_result_stored_in_cache(self, mock_scan):
        from agent.tools.scanner import ScannerResult, ScannerFinding
        r = ScannerResult(tools_run=["semgrep"])
        r.findings.append(ScannerFinding(
            tool="semgrep", rule_id="test",
            message="SQL injection found", severity="ERROR",
            file_path="app.py", line_number=5,
        ))
        mock_scan.return_value = r
        agent = _make_agent()
        result = agent.run_scanner_on_source("/fake/path")
        self.assertIn("semgrep", result)
        self.assertTrue(len(agent._scanner_cache) > 0)

    @patch("agent.tools.scanner.scan_source")
    def test_no_findings_empty_cache(self, mock_scan):
        from agent.tools.scanner import ScannerResult
        mock_scan.return_value = ScannerResult(tools_run=["semgrep"])
        agent = _make_agent()
        agent.run_scanner_on_source("/fake/path")
        self.assertEqual(agent._scanner_cache, "")


class TestPlatformAndConfidenceDefaults(unittest.TestCase):

    def test_default_platform_is_general(self):
        agent = _make_agent()
        self.assertEqual(agent._platform, "general")

    def test_default_confidence_threshold(self):
        agent = _make_agent()
        self.assertEqual(agent._confidence_threshold, 60)

    def test_can_set_platform(self):
        agent = _make_agent()
        agent._platform = "immunefi"
        self.assertEqual(agent._platform, "immunefi")

    def test_can_set_confidence(self):
        agent = _make_agent()
        agent._confidence_threshold = 80
        self.assertEqual(agent._confidence_threshold, 80)


if __name__ == "__main__":
    unittest.main()
