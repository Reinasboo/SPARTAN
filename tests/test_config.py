"""
Tests for config/audit_config.py — AuditConfig, load_config, default_config
"""
import os
import tempfile
import textwrap
import unittest

from config.audit_config import (
    AuditConfig,
    AuthConfig,
    ScopeConfig,
    RulesConfig,
    PipelineConfig,
    TOTPConfig,
    LoginStep,
    default_config,
    load_config,
)


MINIMAL_YAML = textwrap.dedent("""\
    name: "Test Audit"
    scope:
      url: "https://app.example.com"
    authentication:
      login_type: "none"
    rules:
      no_exploit_no_report: true
    pipeline:
      max_concurrent_agents: 2
""")

FULL_YAML = textwrap.dedent("""\
    name: "Full Test"
    scope:
      url: "https://app.example.com"
      openapi_path: "/openapi.json"
      protocol_type: "lending"
      contract_addresses:
        - "0xAbCd1234567890abcdef1234567890abcdef1234"
      chain_id: 1
      rpc_url: "https://mainnet.infura.io/v3/key"
    authentication:
      login_type: "form"
      login_url: "https://app.example.com/login"
      username_selector: "#username"
      password_selector: "#password"
      username: "testuser"
      password: "testpass"
    rules:
      focus:
        - "/api/v1/"
        - "/admin/"
      avoid:
        - "/logout"
      include_owasp_top10: true
      include_api_security_top10: true
      no_exploit_no_report: true
      max_severity_to_report: "CRITICAL"
    pipeline:
      max_concurrent_agents: 4
      timeout_per_phase_seconds: 300
      auto_advance_phases: false
""")


class TestDefaultConfig(unittest.TestCase):

    def test_default_config_creation(self):
        cfg = default_config("https://example.com")
        self.assertIsInstance(cfg, AuditConfig)

    def test_default_config_has_scope(self):
        cfg = default_config("https://example.com")
        self.assertIsNotNone(cfg.scope)

    def test_default_config_no_exploit_enforced(self):
        cfg = default_config("https://example.com")
        self.assertTrue(cfg.rules.no_exploit_no_report)


class TestAuditConfigFromDict(unittest.TestCase):

    def test_minimal_config(self):
        d = {
            "scope": {"url": "https://example.com"},
            "authentication": {"login_type": "none"},
        }
        cfg = AuditConfig.from_dict(d)
        self.assertIsInstance(cfg, AuditConfig)
        self.assertEqual(cfg.scope.url, "https://example.com")
        self.assertEqual(cfg.authentication.login_type, "none")

    def test_full_scope(self):
        d = {
            "scope": {
                "url": "https://app.com",
                "openapi_path": "/api/v2/openapi.yaml",
                "protocol_type": "dexes",
                "contract_addresses": ["0x1234"],
                "chain_id": 137,
            },
        }
        cfg = AuditConfig.from_dict(d)
        self.assertEqual(cfg.scope.protocol_type, "dexes")
        self.assertEqual(cfg.scope.chain_id, 137)
        self.assertIn("0x1234", cfg.scope.contract_addresses)

    def test_rules_config(self):
        d = {
            "rules": {
                "focus": ["/api/", "/admin/"],
                "avoid": ["/logout"],
                "no_exploit_no_report": True,
                "max_severity_to_report": "HIGH",
            }
        }
        cfg = AuditConfig.from_dict(d)
        self.assertIn("/api/", cfg.rules.focus)
        self.assertTrue(cfg.rules.no_exploit_no_report)

    def test_pipeline_config(self):
        d = {"pipeline": {"max_concurrent_agents": 6, "timeout_per_phase_seconds": 600}}
        cfg = AuditConfig.from_dict(d)
        self.assertEqual(cfg.pipeline.max_concurrent_agents, 6)
        self.assertEqual(cfg.pipeline.timeout_per_phase_seconds, 600)

    def test_totp_config(self):
        d = {
            "authentication": {
                "login_type": "totp",
                "totp": {"secret": "BASE32SECRET", "issuer": "TestApp", "digits": 6},
            }
        }
        cfg = AuditConfig.from_dict(d)
        self.assertIsNotNone(cfg.authentication.totp)
        self.assertEqual(cfg.authentication.totp.secret, "BASE32SECRET")

    def test_login_flow_steps(self):
        d = {
            "authentication": {
                "login_type": "form",
                "login_flow": [
                    {"action": "fill", "selector": "#user", "value": "admin"},
                    {"action": "click", "selector": "button[type=submit]"},
                ]
            }
        }
        cfg = AuditConfig.from_dict(d)
        self.assertEqual(len(cfg.authentication.login_flow), 2)
        self.assertIsInstance(cfg.authentication.login_flow[0], LoginStep)
        self.assertEqual(cfg.authentication.login_flow[0].action, "fill")

    def test_empty_dict_gives_defaults(self):
        cfg = AuditConfig.from_dict({})
        self.assertIsNotNone(cfg.scope)
        self.assertIsNotNone(cfg.authentication)
        self.assertIsNotNone(cfg.rules)
        self.assertIsNotNone(cfg.pipeline)


class TestAuditConfigToContextString(unittest.TestCase):

    def test_returns_string(self):
        cfg = AuditConfig.from_dict({"scope": {"url": "https://example.com"}})
        ctx = cfg.to_context_string()
        self.assertIsInstance(ctx, str)

    def test_contains_url(self):
        cfg = AuditConfig.from_dict({"scope": {"url": "https://example.com"}})
        ctx = cfg.to_context_string()
        self.assertIn("example.com", ctx)

    def test_contains_protocol_type_when_set(self):
        cfg = AuditConfig.from_dict({"scope": {"url": "https://app.com", "protocol_type": "lending"}})
        ctx = cfg.to_context_string()
        self.assertIn("lending", ctx)

    def test_contains_focus_rules_when_set(self):
        cfg = AuditConfig.from_dict({"rules": {"focus": ["/api/admin/"]}})
        ctx = cfg.to_context_string()
        self.assertIn("/api/admin/", ctx)

    def test_no_exploit_rule_in_context(self):
        cfg = AuditConfig.from_dict({"rules": {"no_exploit_no_report": True}})
        ctx = cfg.to_context_string()
        lower = ctx.lower()
        self.assertTrue("exploit" in lower or "report" in lower)


class TestAuditConfigValidate(unittest.TestCase):

    def test_valid_config_no_errors(self):
        cfg = AuditConfig.from_dict({
            "scope": {"url": "https://example.com"},
            "authentication": {"login_type": "none"},
        })
        errors = cfg.validate()
        self.assertIsInstance(errors, list)
        self.assertEqual(len(errors), 0)

    def test_invalid_login_type_reports_error(self):
        cfg = AuditConfig.from_dict({
            "authentication": {"login_type": "invalid_type_xyz"}
        })
        errors = cfg.validate()
        self.assertGreater(len(errors), 0)


class TestLoadConfig(unittest.TestCase):

    def test_load_minimal_yaml(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(MINIMAL_YAML)
            tmp_path = f.name
        try:
            cfg = load_config(tmp_path)
            self.assertIsInstance(cfg, AuditConfig)
            self.assertEqual(cfg.scope.url, "https://app.example.com")
            self.assertTrue(cfg.rules.no_exploit_no_report)
        finally:
            os.unlink(tmp_path)

    def test_load_full_yaml(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(FULL_YAML)
            tmp_path = f.name
        try:
            cfg = load_config(tmp_path)
            self.assertEqual(cfg.scope.protocol_type, "lending")
            self.assertEqual(cfg.scope.chain_id, 1)
            self.assertEqual(cfg.pipeline.max_concurrent_agents, 4)
            self.assertIn("/api/v1/", cfg.rules.focus)
        finally:
            os.unlink(tmp_path)

    def test_load_nonexistent_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_config("/nonexistent/path/config.yaml")

    def test_load_invalid_yaml_raises(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write("this: is: invalid: yaml: [[[\n")
            tmp_path = f.name
        try:
            with self.assertRaises(Exception):
                load_config(tmp_path)
        finally:
            os.unlink(tmp_path)


class TestAuthConfigGetHeaders(unittest.TestCase):

    def test_api_key_headers(self):
        cfg = AuthConfig(login_type="api_key", api_key="mykey123")
        headers = cfg.get_headers()
        self.assertIsInstance(headers, dict)
        # Should contain API key somewhere in headers
        all_values = " ".join(headers.values())
        self.assertIn("mykey123", all_values)

    def test_bearer_token_headers(self):
        # Bearer token is stored in api_key field; login_type="bearer_token"
        cfg = AuthConfig(login_type="bearer_token", api_key="tok456")
        headers = cfg.get_headers()
        # Headers dict should contain the token somewhere
        all_values = " ".join(headers.values())
        self.assertIn("tok456", all_values)

    def test_none_auth_empty_headers(self):
        cfg = AuthConfig(login_type="none")
        headers = cfg.get_headers()
        self.assertIsInstance(headers, dict)


if __name__ == "__main__":
    unittest.main()
