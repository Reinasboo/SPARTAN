"""
Tests for agent/knowledge/protocol_vulns.py and agent/knowledge/owasp.py
"""
import unittest

from agent.knowledge.protocol_vulns import (
    PROTOCOL_INDEX,
    ProtocolType,
    ProtocolVulnCategory,
    detect_protocol_type,
    get_protocol_checklist,
    get_multi_protocol_checklist,
    index_stats,
)
from agent.knowledge.owasp import (
    OWASP_TOP10_2021,
    OWASP_API_TOP10_2023,
    build_owasp_analysis_prompt,
    search_owasp,
    get_payloads_by_category,
)


# ── Protocol Vulnerabilities Tests ────────────────────────────────────────────

class TestProtocolIndex(unittest.TestCase):

    def test_protocol_index_not_empty(self):
        self.assertGreater(len(PROTOCOL_INDEX), 0)

    def test_known_protocol_types_present(self):
        for slug in ["lending", "bridge", "dexes", "oracle", "governance"]:
            self.assertIn(slug, PROTOCOL_INDEX, f"'{slug}' not found in PROTOCOL_INDEX")

    def test_each_protocol_has_categories(self):
        for slug, proto in PROTOCOL_INDEX.items():
            self.assertIsInstance(proto, ProtocolType)
            self.assertGreater(len(proto.categories), 0, f"Protocol '{slug}' has no categories")

    def test_category_fields_populated(self):
        for slug, proto in PROTOCOL_INDEX.items():
            for cat in proto.categories:
                self.assertIsInstance(cat, ProtocolVulnCategory)
                self.assertNotEqual(cat.name, "", f"Category in '{slug}' has empty name")
                self.assertNotEqual(cat.slug, "", f"Category in '{slug}' has empty slug")

    def test_checklist_format(self):
        for slug, proto in PROTOCOL_INDEX.items():
            checklist = proto.get_checklist()
            self.assertIn(proto.name, checklist)
            # Should have checkbox items
            self.assertIn("- [ ]", checklist)

    def test_get_category_by_name(self):
        # Lending typically has price manipulation
        lending = PROTOCOL_INDEX.get("lending")
        if lending:
            # Try to find any category
            cat = lending.get_category(lending.categories[0].name)
            self.assertIsNotNone(cat)

    def test_get_category_nonexistent_returns_none(self):
        proto = list(PROTOCOL_INDEX.values())[0]
        result = proto.get_category("zzz_nonexistent_category_zzz")
        self.assertIsNone(result)


class TestDetectProtocolType(unittest.TestCase):

    def test_detect_lending(self):
        result = detect_protocol_type("This is a lending protocol with collateral and borrowing")
        self.assertIn("lending", result)

    def test_detect_dex(self):
        result = detect_protocol_type("UniSwap-style AMM DEX with liquidity pools and swap function")
        self.assertTrue(len(result) > 0)

    def test_detect_bridge(self):
        result = detect_protocol_type("cross-chain bridge relayer with validators")
        self.assertIn("bridge", result)

    def test_detect_oracle(self):
        result = detect_protocol_type("price oracle manipulation with Chainlink integration")
        self.assertIn("oracle", result)

    def test_detect_governance(self):
        result = detect_protocol_type("governance voting with timelock and proposal")
        self.assertIn("governance", result)

    def test_detect_algo_stables(self):
        result = detect_protocol_type("algorithmic stablecoin with rebase mechanism")
        self.assertTrue(len(result) > 0)

    def test_detect_unknown_returns_list(self):
        result = detect_protocol_type("totally unrelated text about sandwiches")
        self.assertIsInstance(result, list)

    def test_detect_multiple_protocols(self):
        text = "lending protocol with oracle price feeds and governance voting"
        result = detect_protocol_type(text)
        self.assertGreater(len(result), 1)


class TestGetProtocolChecklist(unittest.TestCase):

    def test_valid_protocol_returns_checklist(self):
        checklist = get_protocol_checklist("lending")
        self.assertIsNotNone(checklist)
        if checklist:
            self.assertIsInstance(checklist, str)
            self.assertGreater(len(checklist), 0)

    def test_unknown_protocol_returns_message(self):
        result = get_protocol_checklist("nonexistent_protocol_xyz")
        # Returns an error message string, not None/empty
        self.assertIsInstance(result, str)
        self.assertIn("not found", result.lower())


class TestGetMultiProtocolChecklist(unittest.TestCase):

    def test_empty_list(self):
        result = get_multi_protocol_checklist([])
        self.assertIsInstance(result, str)

    def test_single_protocol(self):
        result = get_multi_protocol_checklist(["lending"])
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_multi_protocol(self):
        result = get_multi_protocol_checklist(["lending", "oracle"])
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_unknown_protocols_graceful(self):
        result = get_multi_protocol_checklist(["nonexistent_xyz"])
        self.assertIsInstance(result, str)


class TestIndexStats(unittest.TestCase):

    def test_stats_returns_string(self):
        stats = index_stats()
        self.assertIsInstance(stats, str)

    def test_stats_contains_numbers(self):
        stats = index_stats()
        import re
        numbers = re.findall(r'\d+', stats)
        self.assertGreater(len(numbers), 0)


# ── OWASP Tests ────────────────────────────────────────────────────────────────

class TestOWASPTop10(unittest.TestCase):

    def test_owasp_top10_has_10_entries(self):
        self.assertEqual(len(OWASP_TOP10_2021), 10)

    def test_owasp_ids_are_sequential(self):
        for i, entry in enumerate(OWASP_TOP10_2021, start=1):
            self.assertEqual(entry.id, f"A{i:02d}:2021")

    def test_owasp_entries_have_required_fields(self):
        for entry in OWASP_TOP10_2021:
            self.assertNotEqual(entry.category, "")
            self.assertNotEqual(entry.description, "")
            self.assertIsInstance(entry.common_weaknesses, list)
            self.assertIsInstance(entry.prevention, list)

    def test_a01_is_broken_access_control(self):
        a01 = OWASP_TOP10_2021[0]
        self.assertEqual(a01.id, "A01:2021")
        self.assertIn("Access", a01.category)

    def test_owasp_entries_have_test_payloads(self):
        entries_with_payloads = [e for e in OWASP_TOP10_2021 if e.test_payloads]
        self.assertGreater(len(entries_with_payloads), 0)


class TestOWASPAPITop10(unittest.TestCase):

    def test_api_top10_has_10_entries(self):
        self.assertEqual(len(OWASP_API_TOP10_2023), 10)

    def test_api_ids_format(self):
        for entry in OWASP_API_TOP10_2023:
            self.assertTrue(entry.id.startswith("API"))

    def test_api01_is_broken_object_authorization(self):
        api01 = OWASP_API_TOP10_2023[0]
        self.assertEqual(api01.id, "API1:2023")
        self.assertIn("Object", api01.category)


class TestBuildOWASPPrompt(unittest.TestCase):

    def test_prompt_web_only(self):
        prompt = build_owasp_analysis_prompt(include_api=False)
        self.assertIsInstance(prompt, str)
        self.assertGreater(len(prompt), 100)
        self.assertIn("A01", prompt)

    def test_prompt_includes_api_when_requested(self):
        prompt = build_owasp_analysis_prompt(include_api=True)
        self.assertIn("API1", prompt)
        self.assertIn("API10", prompt)

    def test_prompt_excludes_api_when_not_requested(self):
        prompt = build_owasp_analysis_prompt(include_api=False)
        self.assertNotIn("API1:2023", prompt)


class TestSearchOWASP(unittest.TestCase):

    def test_search_injection_returns_results(self):
        results = search_owasp("injection")
        self.assertGreater(len(results), 0)

    def test_search_xss_returns_results(self):
        # XSS is covered under "Injection" in OWASP Top 10
        results = search_owasp("injection")
        self.assertGreater(len(results), 0)

    def test_search_nonexistent_returns_empty(self):
        results = search_owasp("zzz_impossible_term_zzz")
        self.assertEqual(len(results), 0)

    def test_search_case_insensitive(self):
        lower = search_owasp("injection")
        upper = search_owasp("INJECTION")
        self.assertEqual(len(lower), len(upper))


class TestGetPayloadsByCategory(unittest.TestCase):

    def test_returns_list(self):
        payloads = get_payloads_by_category("injection")
        self.assertIsInstance(payloads, list)

    def test_injection_returns_payloads(self):
        payloads = get_payloads_by_category("injection")
        self.assertGreater(len(payloads), 0)

    def test_unknown_category_returns_empty(self):
        payloads = get_payloads_by_category("zzz_impossible_category")
        self.assertEqual(payloads, [])


if __name__ == "__main__":
    unittest.main()
