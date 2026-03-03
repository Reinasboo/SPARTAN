"""
Tests for agent/knowledge/cvss.py — CVSS v3.1 scoring engine
"""
import unittest

from agent.knowledge.cvss import (
    CVSSVector,
    calculate_cvss,
    score_to_severity,
    score_to_immunefi,
    score_to_hackerone,
    score_to_code4rena,
    full_severity_row,
    score_common,
    COMMON_VECTORS,
)


class TestCVSSVector(unittest.TestCase):

    def test_default_vector_string(self):
        v = CVSSVector()
        s = v.to_string()
        self.assertTrue(s.startswith("CVSS:3.1/"))
        self.assertIn("AV:N", s)
        self.assertIn("AC:L", s)

    def test_from_string_roundtrip(self):
        original = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        v = CVSSVector.from_string(original)
        self.assertEqual(v.AV, "N")
        self.assertEqual(v.AC, "L")
        self.assertEqual(v.PR, "N")
        self.assertEqual(v.UI, "N")
        self.assertEqual(v.S,  "U")
        self.assertEqual(v.C,  "H")
        self.assertEqual(v.I,  "H")
        self.assertEqual(v.A,  "H")

    def test_from_string_partial(self):
        v = CVSSVector.from_string("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N")
        self.assertEqual(v.AV, "L")
        self.assertEqual(v.AC, "H")
        self.assertEqual(v.S,  "C")

    def test_to_string_from_string_roundtrip(self):
        v = CVSSVector("A", "H", "L", "R", "C", "L", "N", "H")
        reconstructed = CVSSVector.from_string(v.to_string())
        self.assertEqual(v.AV, reconstructed.AV)
        self.assertEqual(v.AC, reconstructed.AC)
        self.assertEqual(v.S,  reconstructed.S)
        self.assertEqual(v.C,  reconstructed.C)


class TestCalculateCVSS(unittest.TestCase):

    def test_worst_case_critical(self):
        # Network, Low complexity, No privileges, No user interaction, Scope Changed, All High
        v = CVSSVector("N", "L", "N", "N", "C", "H", "H", "H")
        score = calculate_cvss(v)
        self.assertGreaterEqual(score, 9.0)
        self.assertLessEqual(score, 10.0)

    def test_low_severity_local_physical(self):
        # Physical access, High complexity, High privs, Required UI, Unchanged scope, Low impact
        v = CVSSVector("P", "H", "H", "R", "U", "L", "L", "N")
        score = calculate_cvss(v)
        self.assertGreater(score, 0.0)
        self.assertLess(score, 5.0)

    def test_zero_impact_returns_zero(self):
        # No confidentiality, integrity, or availability impact
        v = CVSSVector("N", "L", "N", "N", "U", "N", "N", "N")
        score = calculate_cvss(v)
        self.assertEqual(score, 0.0)

    def test_score_is_single_decimal(self):
        v = CVSSVector("N", "L", "L", "N", "U", "H", "H", "H")
        score = calculate_cvss(v)
        self.assertEqual(score, round(score, 1))

    def test_score_not_exceed_10(self):
        v = CVSSVector("N", "L", "N", "N", "C", "H", "H", "H")
        score = calculate_cvss(v)
        self.assertLessEqual(score, 10.0)

    def test_scope_changed_higher_than_unchanged(self):
        v_unchanged = CVSSVector("N", "L", "N", "N", "U", "H", "H", "H")
        v_changed   = CVSSVector("N", "L", "N", "N", "C", "H", "H", "H")
        self.assertGreater(calculate_cvss(v_changed), calculate_cvss(v_unchanged))


class TestScoreToSeverity(unittest.TestCase):

    def test_critical(self):
        self.assertEqual(score_to_severity(9.0), "Critical")
        self.assertEqual(score_to_severity(9.8), "Critical")
        self.assertEqual(score_to_severity(10.0), "Critical")

    def test_high(self):
        self.assertEqual(score_to_severity(7.0), "High")
        self.assertEqual(score_to_severity(8.5), "High")
        self.assertEqual(score_to_severity(8.9), "High")

    def test_medium(self):
        self.assertEqual(score_to_severity(4.0), "Medium")
        self.assertEqual(score_to_severity(5.5), "Medium")
        self.assertEqual(score_to_severity(6.9), "Medium")

    def test_low(self):
        self.assertEqual(score_to_severity(0.1), "Low")
        self.assertEqual(score_to_severity(3.9), "Low")

    def test_informational(self):
        self.assertEqual(score_to_severity(0.0), "Informational")


class TestPlatformSeverityMappings(unittest.TestCase):

    def test_immunefi_critical(self):
        self.assertEqual(score_to_immunefi(9.8), "Critical")

    def test_immunefi_high(self):
        self.assertEqual(score_to_immunefi(7.5), "High")

    def test_immunefi_medium(self):
        self.assertEqual(score_to_immunefi(5.0), "Medium")

    def test_immunefi_low(self):
        self.assertEqual(score_to_immunefi(2.0), "Low")

    def test_hackerone_p1(self):
        self.assertIn("P1", score_to_hackerone(9.5))

    def test_hackerone_p2(self):
        self.assertIn("P2", score_to_hackerone(7.5))

    def test_hackerone_p5(self):
        self.assertIn("P5", score_to_hackerone(0.0))

    def test_code4rena_high(self):
        self.assertEqual(score_to_code4rena(7.0), "High")

    def test_code4rena_medium(self):
        self.assertEqual(score_to_code4rena(5.0), "Medium")

    def test_code4rena_low(self):
        self.assertIn("Low", score_to_code4rena(1.0))

    def test_code4rena_gas(self):
        self.assertEqual(score_to_code4rena(0.0), "Gas")

    def test_full_severity_row_contains_all_platforms(self):
        row = full_severity_row(9.0)
        self.assertIn("CVSS", row)
        self.assertIn("Immunefi", row)
        self.assertIn("HackerOne", row)
        self.assertIn("Code4rena", row)


class TestCommonVectors(unittest.TestCase):

    def test_all_common_vectors_score_above_zero(self):
        for name in COMMON_VECTORS:
            score, severity = score_common(name)
            self.assertGreater(score, 0.0, f"Vector '{name}' should score > 0")
            self.assertIn(severity, ["Low", "Medium", "High", "Critical"])

    def test_unauthenticated_rce_is_critical(self):
        score, severity = score_common("unauthenticated_rce")
        self.assertEqual(severity, "Critical")

    def test_unknown_vector_raises_key_error(self):
        with self.assertRaises(KeyError):
            score_common("not_a_real_vector")


if __name__ == "__main__":
    unittest.main()
