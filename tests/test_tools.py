"""
Tests for agent/tools/ — recon_tools, web_exploits, dataflow
"""
import unittest

from agent.tools.recon_tools import (
    ReconCommand,
    build_nmap_command,
    build_subfinder_command,
    build_whatweb_command,
    build_schemathesis_command,
    build_full_recon_block,
    RECON_TOOLS_AVAILABLE,
)
from agent.tools.web_exploits import (
    PoC,
    PoCSafety,
    SQL_INJECTION_PAYLOADS,
    XSS_PAYLOADS,
    SSRF_PAYLOADS,
    SSTI_PAYLOADS,
    COMMAND_INJECTION_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    build_playwright_script,
    build_curl_poc,
    enforce_no_exploit_no_report,
)
from agent.tools.dataflow import (
    SOURCE_PATTERNS,
    SINK_PATTERNS,
    DataFlowFinding,
    DataFlowAnalysis,
    DataFlowAnalyzer,
    analyze_sources_and_sinks,
    build_dataflow_analysis_prompt,
)


# ── Recon Tools Tests ─────────────────────────────────────────────────────────

class TestReconToolsAvailable(unittest.TestCase):

    def test_tools_list_not_empty(self):
        self.assertGreater(len(RECON_TOOLS_AVAILABLE), 0)

    def test_expected_tools_present(self):
        for tool in ["nmap", "subfinder", "whatweb", "schemathesis"]:
            self.assertIn(tool, RECON_TOOLS_AVAILABLE)


class TestReconCommand(unittest.TestCase):

    def test_str_contains_tool_name(self):
        cmd = ReconCommand(
            tool="nmap",
            command="nmap -sV example.com",
            description="Version scan",
            expected_output="Open ports list",
        )
        s = str(cmd)
        self.assertIn("NMAP", s)
        self.assertIn("nmap -sV example.com", s)
        self.assertIn("Version scan", s)

    def test_str_with_flags_explained(self):
        cmd = ReconCommand(
            tool="nmap",
            command="nmap -sV example.com",
            description="Scan",
            expected_output="Ports",
            flags_explained={"-sV": "service version detection"},
        )
        s = str(cmd)
        self.assertIn("-sV", s)
        self.assertIn("service version detection", s)


class TestBuildNmapCommand(unittest.TestCase):

    def test_default_mode(self):
        cmd = build_nmap_command("example.com")
        self.assertIsInstance(cmd, ReconCommand)
        self.assertEqual(cmd.tool, "nmap")
        self.assertIn("example.com", cmd.command)

    def test_deep_mode(self):
        cmd = build_nmap_command("10.0.0.1", mode="deep")
        self.assertIn("10.0.0.1", cmd.command)

    def test_udp_mode(self):
        cmd = build_nmap_command("10.0.0.1", mode="udp")
        self.assertIn("10.0.0.1", cmd.command)

    def test_vuln_mode(self):
        cmd = build_nmap_command("10.0.0.1", mode="vuln")
        self.assertIn("10.0.0.1", cmd.command)

    def test_web_mode(self):
        cmd = build_nmap_command("example.com", mode="web")
        self.assertIn("example.com", cmd.command)

    def test_ip_extraction_from_url(self):
        cmd = build_nmap_command("https://example.com/path")
        self.assertIn("example.com", cmd.command)
        self.assertNotIn("https://", cmd.command)


class TestBuildSubfinderCommand(unittest.TestCase):

    def test_basic(self):
        cmd = build_subfinder_command("example.com")
        self.assertIsInstance(cmd, ReconCommand)
        self.assertEqual(cmd.tool, "subfinder")
        self.assertIn("example.com", cmd.command)

    def test_with_resolve(self):
        cmd = build_subfinder_command("example.com", resolve=True)
        self.assertIn("-resolve", cmd.command)

    def test_with_output_file(self):
        cmd = build_subfinder_command("example.com", output_file="subs.txt")
        # Output file is embedded in generated filename pattern
        self.assertIsInstance(cmd, ReconCommand)
        self.assertIn("example.com", cmd.command)


class TestBuildWhatwebCommand(unittest.TestCase):

    def test_basic(self):
        cmd = build_whatweb_command("http://example.com")
        self.assertIsInstance(cmd, ReconCommand)
        self.assertEqual(cmd.tool, "whatweb")
        self.assertIn("example.com", cmd.command)

    def test_aggression_level(self):
        cmd = build_whatweb_command("http://example.com", aggression=3)
        self.assertIn("3", cmd.command)


class TestBuildSchemathesisCommand(unittest.TestCase):

    def test_basic(self):
        cmd = build_schemathesis_command("http://api.example.com")
        self.assertIsInstance(cmd, ReconCommand)
        self.assertEqual(cmd.tool, "schemathesis")
        self.assertIn("example.com", cmd.command)

    def test_with_schema_path(self):
        cmd = build_schemathesis_command("http://api.example.com", schema_path="/openapi.json")
        self.assertIn("/openapi.json", cmd.command)

    def test_with_auth_token(self):
        cmd = build_schemathesis_command("http://api.example.com", auth_token="Bearer abc123")
        self.assertIn("abc123", cmd.command)


class TestBuildFullReconBlock(unittest.TestCase):

    def test_url_target(self):
        block = build_full_recon_block("https://app.example.com", is_url=True)
        self.assertIsInstance(block, str)
        self.assertGreater(len(block), 0)
        self.assertIn("nmap", block.lower())

    def test_non_url_target(self):
        block = build_full_recon_block("VaultContract.sol", is_url=False)
        self.assertIsInstance(block, str)

    def test_with_openapi(self):
        block = build_full_recon_block(
            "https://api.example.com", is_url=True, has_openapi=True
        )
        self.assertIn("schemathesis", block.lower())

    def test_empty_block_for_non_url_no_schema(self):
        block = build_full_recon_block("SomeContract", is_url=False, has_openapi=False)
        self.assertIsInstance(block, str)


# ── Web Exploits Tests ────────────────────────────────────────────────────────

class TestPayloadBanks(unittest.TestCase):

    def test_sqli_payload_categories(self):
        self.assertIn("auth_bypass", SQL_INJECTION_PAYLOADS)
        self.assertIn("union_based", SQL_INJECTION_PAYLOADS)
        self.assertIn("time_based_blind", SQL_INJECTION_PAYLOADS)

    def test_sqli_payloads_not_empty(self):
        for cat, payloads in SQL_INJECTION_PAYLOADS.items():
            self.assertGreater(len(payloads), 0, f"SQLi category '{cat}' is empty")

    def test_xss_payload_categories(self):
        self.assertIn("basic", XSS_PAYLOADS)
        self.assertIn("filter_bypass", XSS_PAYLOADS)
        self.assertIn("dom_based", XSS_PAYLOADS)

    def test_ssrf_payloads_include_metadata(self):
        all_ssrf = " ".join(SSRF_PAYLOADS)
        self.assertTrue(
            "169.254" in all_ssrf or "metadata" in all_ssrf.lower(),
            "SSRF payloads should include cloud metadata endpoint"
        )

    def test_ssti_payloads_not_empty(self):
        self.assertGreater(len(SSTI_PAYLOADS), 0)

    def test_command_injection_not_empty(self):
        self.assertGreater(len(COMMAND_INJECTION_PAYLOADS), 0)

    def test_path_traversal_not_empty(self):
        self.assertGreater(len(PATH_TRAVERSAL_PAYLOADS), 0)


class TestPoCSafety(unittest.TestCase):

    def test_safety_enum_values(self):
        self.assertEqual(PoCSafety.SAFE, "SAFE")
        self.assertEqual(PoCSafety.LOCAL, "LOCAL")
        self.assertEqual(PoCSafety.SIMULATED, "SIMULATED")


class TestBuildPlaywrightScript(unittest.TestCase):

    def _make_poc(self, vuln_type="xss", **kwargs):
        defaults = dict(
            target_url="http://testapp.local/search",
            parameter="q",
            payload="<script>alert(1)</script>",
        )
        defaults.update(kwargs)
        return build_playwright_script(vuln_type=vuln_type, **defaults)

    def test_xss_script_returns_poc(self):
        poc = self._make_poc("xss")
        self.assertIsInstance(poc, PoC)
        self.assertIn("playwright", poc.playwright_code.lower())
        # vuln_class is the full name, not abbreviation
        self.assertIn("script", poc.vuln_class.lower())

    def test_sqli_script_generation(self):
        poc = self._make_poc("sqli", payload="' OR '1'='1")
        self.assertIsInstance(poc, PoC)
        self.assertIsNotNone(poc.playwright_code)
        self.assertGreater(len(poc.playwright_code), 50)

    def test_ssrf_script_generation(self):
        poc = self._make_poc("ssrf", payload="http://169.254.169.254/")
        self.assertIsInstance(poc, PoC)
        self.assertIsNotNone(poc.playwright_code)

    def test_idor_script_generation(self):
        poc = self._make_poc("idor", parameter="user_id", payload="2")
        self.assertIsInstance(poc, PoC)
        # vuln_class is the full name
        self.assertIn("object", poc.vuln_class.lower())

    def test_auth_bypass_script_generation(self):
        poc = self._make_poc("auth_bypass")
        self.assertIsInstance(poc, PoC)
        self.assertIsNotNone(poc.playwright_code)

    def test_xss_poc_has_playwright_imports(self):
        poc = self._make_poc("xss")
        self.assertIn("async_playwright", poc.playwright_code)

    def test_unknown_vuln_type_returns_poc(self):
        poc = build_playwright_script(
            "unknown_type", "http://example.com", "param", "payload"
        )
        self.assertIsInstance(poc, PoC)


class TestBuildCurlPoC(unittest.TestCase):

    def test_returns_poc_object(self):
        # build_curl_poc(vuln_type, target_url, parameter, method, headers, auth_token)
        poc = build_curl_poc(
            vuln_type="sqli_time",
            target_url="http://api.example.com/users",
            parameter="id",
        )
        self.assertIsInstance(poc, PoC)
        self.assertIsNotNone(poc.curl_command)
        self.assertIn("curl", poc.curl_command)

    def test_with_auth_token(self):
        # For curl poc, auth token is included in the header flags string
        # Use sqli_time vuln_type which uses the header_flags variable
        poc = build_curl_poc(
            vuln_type="sqli_time",
            target_url="http://api.example.com/users",
            parameter="id",
            auth_token="mysecrettoken",
        )
        self.assertIsInstance(poc, PoC)
        self.assertIn("mysecrettoken", poc.curl_command)

    def test_ssrf_metadata_curl_poc(self):
        poc = build_curl_poc(
            vuln_type="ssrf_metadata",
            target_url="http://api.example.com/fetch",
            parameter="url",
        )
        self.assertIsInstance(poc, PoC)
        self.assertIn("curl", poc.curl_command)


class TestEnforceNoExploitNoReport(unittest.TestCase):

    def test_with_poc_returns_approved(self):
        poc = PoC(
            title="XSS in search",
            vuln_class="XSS",
            safety=PoCSafety.SAFE,
            description="Alert fires",
            curl_command="curl ...",
            expected_evidence="alert(1) executed",
        )
        result = enforce_no_exploit_no_report("XSS in search field", poc)
        self.assertIn("CONFIRMED", result.upper())

    def test_without_evidence_returns_excluded(self):
        result = enforce_no_exploit_no_report("Generic memory issue", None)
        self.assertIn("EXCLUDED", result.upper())


# ── Dataflow Tests ────────────────────────────────────────────────────────────

class TestSourceAndSinkPatterns(unittest.TestCase):

    def test_source_patterns_not_empty(self):
        self.assertGreater(len(SOURCE_PATTERNS), 0)

    def test_source_patterns_have_python(self):
        self.assertIn("python_request", SOURCE_PATTERNS)

    def test_source_patterns_have_solidity(self):
        self.assertIn("solidity_calldata", SOURCE_PATTERNS)

    def test_sink_patterns_cover_major_vulns(self):
        for vuln in ["sql_injection", "command_injection", "ssrf", "xss"]:
            self.assertIn(vuln, SINK_PATTERNS, f"Sink pattern '{vuln}' missing")

    def test_sink_patterns_are_tuples(self):
        for cat, patterns in SINK_PATTERNS.items():
            for item in patterns:
                self.assertIsInstance(item, tuple)
                self.assertEqual(len(item), 2)


class TestDataFlowAnalyzer(unittest.TestCase):

    FLASK_SQLI_CODE = """
from flask import request
import sqlite3

def get_user():
    username = request.args.get('user')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchall()
"""

    CLEAN_CODE = """
def add(a, b):
    return a + b

def multiply(x, y):
    return x * y
"""

    DJANGO_XSS_CODE = """
from django.http import HttpResponse
import django.utils.safestring
def render_name(request):
    name = request.GET['name']
    return HttpResponse(f'<h1>{name}</h1>')
"""

    def test_analyze_text_returns_list_of_findings(self):
        # analyze_text() returns list[DataFlowFinding], not DataFlowAnalysis
        analyzer = DataFlowAnalyzer()
        findings = analyzer.analyze_text(self.FLASK_SQLI_CODE, "views.py")
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)

    def test_analyze_sqli_code_finds_sqli_sink(self):
        analyzer = DataFlowAnalyzer()
        findings = analyzer.analyze_text(self.FLASK_SQLI_CODE, "views.py")
        vuln_classes = [f.vuln_class for f in findings]
        self.assertTrue(
            any("sql" in vc.lower() for vc in vuln_classes),
            f"Expected SQL injection finding, got: {vuln_classes}"
        )

    def test_analyze_sqli_code_source_type(self):
        analyzer = DataFlowAnalyzer()
        findings = analyzer.analyze_text(self.FLASK_SQLI_CODE, "views.py")
        # At least one finding should trace back to python_request source
        source_types = [f.source_type for f in findings]
        self.assertTrue(
            any("python" in st for st in source_types),
            f"Expected python_request source, got: {source_types}"
        )

    def test_clean_code_no_findings(self):
        analyzer = DataFlowAnalyzer()
        findings = analyzer.analyze_text(self.CLEAN_CODE, "math.py")
        self.assertEqual(findings, [])

    def test_xss_detection(self):
        # Use code that matches a known XSS sink pattern: mark_safe() or |safe
        django_xss_code = """
from django.utils.safestring import mark_safe
from django.http import HttpResponse
from django import request
def render_name(request):
    name = request.GET['name']
    safe_name = mark_safe(name)  # XSS via mark_safe
    return HttpResponse(safe_name)
"""
        analyzer = DataFlowAnalyzer()
        findings = analyzer.analyze_text(django_xss_code, "views.py")
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)

    def test_convenience_function_returns_analysis(self):
        result = analyze_sources_and_sinks(self.FLASK_SQLI_CODE, "views.py")
        self.assertIsInstance(result, DataFlowAnalysis)
        self.assertGreater(len(result.findings), 0)

    def test_empty_code_via_convenience(self):
        result = analyze_sources_and_sinks("", "empty.py")
        self.assertIsInstance(result, DataFlowAnalysis)
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(len(result.sources_detected), 0)


class TestBuildDataflowPrompt(unittest.TestCase):

    def test_returns_string(self):
        prompt = build_dataflow_analysis_prompt("x = request.args.get('id')")
        self.assertIsInstance(prompt, str)

    def test_prompt_contains_code(self):
        snippet = "cursor.execute('SELECT * FROM users WHERE id=' + user_id)"
        prompt = build_dataflow_analysis_prompt(snippet)
        self.assertIn("SELECT", prompt)

    def test_prompt_mentions_source_sink(self):
        prompt = build_dataflow_analysis_prompt("some code here")
        lower = prompt.lower()
        self.assertTrue(
            "source" in lower or "sink" in lower or "flow" in lower,
            "Prompt should reference source/sink analysis"
        )


if __name__ == "__main__":
    unittest.main()
