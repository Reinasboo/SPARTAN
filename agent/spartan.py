"""
SPARTAN v2.0 — Core Agent
Orchestrates phases, session memory, LLM interactions, and response formatting.
"""

from __future__ import annotations

import re
from typing import Any

from agent.formatter import (
    spartan_header, spartan_footer, format_finding_badge,
    format_session_banner, truncate_for_context, format_authorization_check,
)
from agent.llm_client import chat, get_active_model
from agent.session import Finding, Session, SessionRegistry
from agent.phases.recon import build_recon_prompt, build_recon_system_prompt, _detect_web3, _is_url
from agent.phases.analysis import build_analysis_prompt, build_analysis_system_prompt
from agent.phases.validation import build_validation_prompt, build_validation_system_prompt
from agent.phases.report import build_report_prompt, build_report_system_prompt, save_report
from agent.phases.remediation import build_remediation_prompt, build_remediation_system_prompt
from config.prompts import SPARTAN_SYSTEM_PROMPT
from config.settings import SAVE_SESSIONS, AUTO_ADVANCE_PHASES


# ── Trigger detection ─────────────────────────────────────────────────────────

AUTHORIZATION_TRIGGERS = [
    r"\b(hack|exploit|attack|pwn|crack|breach)\b.*\b(live|production|real|actual)\b",
]

SUSPICIOUS_TARGETS = [
    r"(google\.com|facebook\.com|twitter\.com|amazon\.com|microsoft\.com)$",
]

FIX_INDICATORS = [
    "here's the fix", "i've fixed", "updated code", "patch applied",
    "here is the fix", "fixed version", "new implementation",
]


# ── Main Agent Class ──────────────────────────────────────────────────────────

class SpartanAgent:
    """
    SPARTAN v2.0 — Autonomous Security Audit Agent.
    Manages session, phase orchestration, and LLM interactions.
    """

    def __init__(self, session: Session | None = None):
        self.session = session or Session()
        self._pending_auth_check = False
        self.audit_config = None  # Optional AuditConfig loaded from YAML

    # ── Public API ────────────────────────────────────────────────────────────

    def set_target(self, target: str) -> str:
        """Set or update the audit target. Resets phase to Recon."""
        old_target = self.session.target
        if old_target != "unset" and old_target != target:
            msg = (
                f"Previous engagement on '{old_target}' closed.\n"
                f"Starting new audit: {target}\n"
            )
        else:
            msg = f"Target set: {target}\n"

        self.session.target = target
        self.session.set_phase("Recon")
        self._save()
        return msg

    def process_input(self, user_input: str) -> str:
        """
        Main entry point — route user input to the appropriate handler.
        Returns the agent's response as a string.
        """
        text = user_input.strip()
        lower = text.lower()

        # ── Authorization pending ──────────────────────────────────────────
        if self._pending_auth_check:
            if any(w in lower for w in ["confirmed", "yes", "authorized", "in scope"]):
                self._pending_auth_check = False
                return self._begin_recon(extra_context=text)
            else:
                return (
                    "Authorization not confirmed. "
                    "Please confirm you are authorized to test this target before proceeding."
                )

        # ── No target set ─────────────────────────────────────────────────
        if self.session.target == "unset":
            if not text:
                return (
                    'No target set. Provide a target — repo, URL, contract address, '
                    'spec, or description.\n\nExample: "Audit this Solidity vault contract: ..."'
                )
            # Treat the input as the target / first message
            return self._handle_new_target_input(text)

        # ── Fix/patch provided → Phase 5 ─────────────────────────────────
        if any(phrase in lower for phrase in FIX_INDICATORS):
            self.session.set_phase("Remediation")
            return self._run_remediation(text)

        # ── Explicit phase/command routing ────────────────────────────────
        if lower.startswith("target "):
            new_target = text[7:].strip()
            return self.set_target(new_target) + self._begin_recon()

        if lower in ("continue", "proceed", "next phase"):
            return self._advance_and_continue()

        if lower.startswith("phase "):
            phase_name = text[6:].strip().capitalize()
            try:
                self.session.set_phase(phase_name)
                return self._run_current_phase(user_input=text)
            except ValueError as e:
                return str(e)

        if lower in ("report", "generate report", "full report"):
            self.session.set_phase("Report")
            return self._run_report_phase()

        if lower in ("status",):
            return self._status_response()

        if lower in ("findings", "list findings", "show findings"):
            return self._list_findings()

        if lower.startswith("finding "):
            fid = text[8:].strip().upper()
            return self._show_finding(fid)

        if lower in ("save",):
            path = self.session.save()
            return f"Session saved → {path}"

        if lower in ("model",):
            return f"Active model: {get_active_model()}"

        # ── General message → delegate to current phase ───────────────────
        return self._run_current_phase(user_input=text)

    # ── Phase runners ─────────────────────────────────────────────────────────

    def _handle_new_target_input(self, text: str) -> str:
        """Called when no target is set and user provides first input."""
        # Check for suspicious targets
        if self._is_suspicious_target(text):
            return format_authorization_check(text)

        # Set target from first substantial input
        # Try to extract a target name from the text
        target_name = self._extract_target_name(text)
        self.session.target = target_name
        self.session.set_phase("Recon")
        self._save()
        return self._begin_recon(extra_context=text)

    def _begin_recon(self, extra_context: str = "") -> str:
        """Start Phase 1 reconnaissance."""
        self.session.set_phase("Recon")
        print(spartan_header(self.session.target, "Recon"), end="")

        system = build_recon_system_prompt()
        auth_token = None
        has_openapi = False
        deep_scan = False
        if self.audit_config:
            cfg = self.audit_config
            auth_token = getattr(cfg.authentication, 'api_key', None)
            has_openapi = bool(getattr(cfg.scope, 'openapi_path', None))
            deep_scan = True
        user_prompt = build_recon_prompt(
            self.session.target, extra_context,
            has_openapi=has_openapi, auth_token=auth_token, deep_scan=deep_scan,
        )

        response = self._llm_call(system, user_prompt)
        self.session.add_message("assistant", response)

        if AUTO_ADVANCE_PHASES:
            next_action = (
                "Proceeding to Phase 2 — Vulnerability Analysis. "
                "Provide source code, ABI, or describe specific components to analyze. "
                "Or type 'continue' to proceed with available information."
            )
        else:
            next_action = "Type 'continue' to advance to Phase 2 — Vulnerability Analysis."

        print(spartan_footer(next_action), end="")
        self._save()
        return ""  # already printed via streaming

    def _run_current_phase(self, user_input: str = "") -> str:
        """Run the agent in the current phase with the given user input."""
        phase = self.session.phase

        print(spartan_header(self.session.target, phase), end="")

        if phase == "Recon":
            system = build_recon_system_prompt()
            auth_token = None
            has_openapi = False
            deep_scan = False
            if self.audit_config:
                auth_token = getattr(self.audit_config.authentication, 'api_key', None)
                has_openapi = bool(getattr(self.audit_config.scope, 'openapi_path', None))
                deep_scan = True
            user_prompt = build_recon_prompt(
                self.session.target, user_input,
                has_openapi=has_openapi, auth_token=auth_token, deep_scan=deep_scan,
            )
        elif phase == "Analysis":
            system = build_analysis_system_prompt()
            attack_surface = self._get_last_recon_summary()
            is_web3 = _detect_web3(self.session.target + " " + user_input)
            user_prompt = build_analysis_prompt(
                target=self.session.target,
                attack_surface_summary=attack_surface,
                context=user_input,
                include_web2=not is_web3,
                include_web3=is_web3,
                source_code=user_input if len(user_input) > 200 else None,
            )
        elif phase == "Validation":
            system = build_validation_system_prompt()
            findings_summary = self._get_findings_summary_text()
            user_prompt = build_validation_prompt(
                target=self.session.target,
                findings_summary=findings_summary,
                context=user_input,
            )
        elif phase == "Report":
            return self._run_report_phase()
        elif phase == "Remediation":
            return self._run_remediation(user_input)
        else:
            system = SPARTAN_SYSTEM_PROMPT
            user_prompt = user_input

        # Add this user message to history
        if user_input:
            self.session.add_message("user", user_input)

        response = self._llm_call(system, user_prompt)
        self.session.add_message("assistant", response)

        # Auto-extract findings from Analysis/Validation responses
        if phase in ("Analysis", "Validation"):
            self._extract_and_register_findings(response, phase)

        next_action = self._determine_next_action(phase, response)
        print(spartan_footer(next_action), end="")
        self._save()
        return ""

    def _run_report_phase(self) -> str:
        """Run Phase 4 — Report Generation."""
        print(spartan_header(self.session.target, "Report"), end="")

        findings_text = self._get_all_findings_detailed()
        user_prompt = build_report_prompt(
            target=self.session.target,
            session_id=self.session.session_id,
            all_findings_text=findings_text,
        )
        system = build_report_system_prompt()

        response = self._llm_call(system, user_prompt)
        self.session.add_message("assistant", response)

        # Save report to file
        report_path = save_report(response, self.session.target, self.session.session_id)

        next_action = (
            f"Report saved → {report_path}\n"
            "Provide fixes/patches to enter Phase 5 — Remediation Review."
        )
        print(spartan_footer(next_action), end="")
        self._save()
        return ""

    def _run_remediation(self, fix_content: str) -> str:
        """Run Phase 5 — Remediation Review."""
        self.session.set_phase("Remediation")
        print(spartan_header(self.session.target, "Remediation"), end="")

        original_findings = self._get_findings_summary_text()
        user_prompt = build_remediation_prompt(
            target=self.session.target,
            original_findings=original_findings,
            fix_content=fix_content,
        )
        system = build_remediation_system_prompt()

        response = self._llm_call(system, user_prompt)
        self.session.add_message("assistant", response)

        next_action = (
            "Provide additional fixes to review, or type 'report' to regenerate the full report."
        )
        print(spartan_footer(next_action), end="")
        self._save()
        return ""

    def _advance_and_continue(self) -> str:
        """Advance to the next phase and run it."""
        next_phase = self.session.advance_phase()
        if not next_phase:
            return f"Already at final phase ({self.session.phase}). Type 'report' to generate full audit report."
        return self._run_current_phase()

    # ── LLM interaction ───────────────────────────────────────────────────────

    def _llm_call(self, system_prompt: str, user_content: str) -> str:
        """Build the messages array and call the LLM."""
        # Start with the full SPARTAN system prompt + phase-specific instructions
        full_system = SPARTAN_SYSTEM_PROMPT + "\n\n" + system_prompt
        # Inject audit config context if loaded
        if self.audit_config is not None:
            try:
                config_ctx = self.audit_config.to_context_string()
                if config_ctx:
                    full_system += "\n\n" + config_ctx
            except Exception:
                pass

        messages: list[dict] = [{"role": "system", "content": full_system}]

        # Add conversation history (last N turns to manage context)
        history = self.session.messages[-20:]  # last 20 messages
        for msg in history:
            messages.append(msg)

        # Add the new user message
        messages.append({"role": "user", "content": truncate_for_context(user_content, 6000)})

        return chat(messages)

    # ── Finding management ────────────────────────────────────────────────────

    def _extract_and_register_findings(self, response: str, phase: str) -> None:
        """
        Heuristically extract findings from LLM response and register them in session.
        """
        # Look for "Potential Finding:" or "## [FINDING" patterns
        patterns = [
            r"(?:Potential Finding|###\s*Potential Finding):\s*(.+?)(?:\n|$)",
            r"\[FINDING-\d+\]\s*[—-]\s*(.+?)(?:\n|$)",
        ]

        severity_pattern = re.compile(
            r"(?:Severity|Preliminary Severity):\s*(Critical|High|Medium|Low|Informational|Gas)",
            re.IGNORECASE,
        )
        category_pattern = re.compile(
            r"(?:Class|Category|CWE):\s*(.+?)(?:\n|$)",
            re.IGNORECASE,
        )

        severities  = severity_pattern.findall(response)
        categories  = category_pattern.findall(response)
        confirmed   = "[UNCONFIRMED" not in response

        for pattern in patterns:
            titles = re.findall(pattern, response)
            for i, title in enumerate(titles):
                title = title.strip()
                if not title or len(title) > 150:
                    continue

                # Skip if already registered
                existing_titles = [f.title for f in self.session.findings]
                if title in existing_titles:
                    continue

                severity = severities[i] if i < len(severities) else "Medium"
                category = categories[i].strip() if i < len(categories) else "Unknown"

                fid = self.session.next_finding_id()
                finding = Finding(
                    finding_id=fid,
                    title=title,
                    severity=severity,
                    category=category,
                    target=self.session.target,
                    confirmed=confirmed,
                    phase_found=phase,
                    raw_report=response[:500],  # store excerpt
                )
                self.session.add_finding(finding)

    def register_finding_manually(
        self,
        title: str,
        severity: str,
        category: str,
        summary: str = "",
        cvss_score: float = 0.0,
        cvss_vector: str = "",
        poc: str = "",
    ) -> Finding:
        """Manually register a confirmed finding."""
        fid = self.session.next_finding_id()
        finding = Finding(
            finding_id=fid,
            title=title,
            severity=severity,
            category=category,
            target=self.session.target,
            summary=summary,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            confirmed=True,
            poc=poc,
            phase_found=self.session.phase,
        )
        self.session.add_finding(finding)
        return finding

    # ── Status & summaries ────────────────────────────────────────────────────

    def _status_response(self) -> str:
        return (
            f"\n{self.session.status_block()}\n"
            f"Model: {get_active_model()}\n"
        )

    def _list_findings(self) -> str:
        if not self.session.findings:
            return "No findings registered yet."
        lines = [f"\nFindings for {self.session.target}:\n"]
        for f in self.session.findings:
            lines.append(f.one_liner())
        lines.append(f"\n{self.session.severity_summary()}")
        return "\n".join(lines)

    def _show_finding(self, finding_id: str) -> str:
        f = self.session.get_finding(finding_id)
        if not f:
            return f"Finding {finding_id} not found."
        lines = [
            format_finding_badge(f.finding_id, f.severity, f.title, f.confirmed),
            f"\n**Category:** {f.category}",
            f"**Target:** {f.target}",
            f"**Phase Found:** {f.phase_found}",
            f"**CVSS:** {f.cvss_score} {f.cvss_vector}",
            f"**Remediation Status:** {f.remediation_status}",
        ]
        if f.summary:
            lines.append(f"\n**Summary:** {f.summary}")
        if f.poc:
            lines.append(f"\n**PoC:**\n```\n{f.poc}\n```")
        return "\n".join(lines)

    def _get_last_recon_summary(self) -> str:
        """Return the last recon output from session history."""
        for msg in reversed(self.session.messages):
            if msg["role"] == "assistant" and len(msg["content"]) > 200:
                return truncate_for_context(msg["content"], 3000)
        return "(No recon output yet)"

    def _get_findings_summary_text(self) -> str:
        """Return a text summary of all findings."""
        if not self.session.findings:
            return "(No findings recorded yet — analyze target first)"
        lines = []
        for f in self.session.findings:
            lines.append(
                f"- {f.finding_id}: {f.title} | {f.severity} | {f.category} | "
                f"{'Confirmed' if f.confirmed else 'Unconfirmed'}"
            )
        return "\n".join(lines)

    def _get_all_findings_detailed(self) -> str:
        """Return detailed findings text for report generation."""
        if not self.session.findings:
            return "(No findings recorded — generate from conversation context)"
        lines = []
        for f in self.session.findings:
            lines.append(
                f"### {f.finding_id}: {f.title}\n"
                f"Severity: {f.severity}\n"
                f"Category: {f.category}\n"
                f"Target: {f.target}\n"
                f"CVSS: {f.cvss_score} {f.cvss_vector}\n"
                f"Confirmed: {f.confirmed}\n"
                f"Summary: {f.summary}\n"
                f"PoC: {f.poc}\n"
                f"Phase: {f.phase_found}\n"
                f"Raw: {f.raw_report[:300]}\n"
            )
        return "\n\n".join(lines)

    def _determine_next_action(self, phase: str, response: str) -> str:
        """Determine the appropriate NEXT ACTION message."""
        actions = {
            "Recon": (
                "Provide source code, ABI, API schema, or additional details, "
                "then type 'continue' to advance to Phase 2 — Vulnerability Analysis."
            ),
            "Analysis": (
                "Review findings above. Type 'continue' to advance to Phase 3 — Exploit Validation, "
                "or provide more source code/context for deeper analysis."
            ),
            "Validation": (
                "PoCs generated above. Type 'report' to generate full audit report, "
                "or 'continue' for Phase 4 — Report Generation."
            ),
            "Report": (
                "Full report generated. Provide fixes/patches for Phase 5 — Remediation Review."
            ),
            "Remediation": (
                "Remediation review complete. Provide additional fixes to review, "
                "or type 'report' to regenerate the updated report."
            ),
        }
        return actions.get(phase, "Provide additional context or type 'continue' to proceed.")

    # ── Authorization checks ──────────────────────────────────────────────────

    def _is_suspicious_target(self, text: str) -> bool:
        """Check if the target appears to be a major production system without clear context."""
        lower = text.lower()
        for pattern in SUSPICIOUS_TARGETS:
            if re.search(pattern, lower):
                return True
        # Check for explicit attack language against live systems
        for pattern in AUTHORIZATION_TRIGGERS:
            if re.search(pattern, lower):
                return True
        return False

    def _extract_target_name(self, text: str) -> str:
        """Extract a short target name from user input."""
        # Try to extract URL
        url_match = re.search(r'https?://[^\s]+', text)
        if url_match:
            return url_match.group(0)[:60]

        # Try contract address
        addr_match = re.search(r'0x[a-fA-F0-9]{40}', text)
        if addr_match:
            return addr_match.group(0)

        # Try to find a protocol/contract name
        name_match = re.search(
            r'(?:audit|review|analyze|test|check)\s+(?:the\s+)?([A-Za-z0-9_\-]+)',
            text, re.IGNORECASE
        )
        if name_match:
            return name_match.group(1)

        # Use first ~40 chars
        words = text.split()
        return " ".join(words[:5])[:40] if words else "Unknown Target"

    # ── Session management ────────────────────────────────────────────────────

    def _save(self) -> None:
        if SAVE_SESSIONS:
            try:
                self.session.save()
            except Exception:
                pass  # Never crash on save

    def load_config_file(self, config_path: str) -> str:
        """Load a YAML audit config and apply scope/auth settings to this session."""
        try:
            from config.audit_config import load_config
            self.audit_config = load_config(config_path)
            cfg = self.audit_config
            # Auto-set target from config scope if not yet set
            scope_url = getattr(cfg.scope, 'url', None)
            if scope_url and self.session.target == "unset":
                self.session.target = scope_url
                self.session.set_phase("Recon")
            name = getattr(cfg, 'name', config_path)
            return f"Config loaded: {name}"
        except Exception as exc:
            return f"Config load error: {exc}"

    @classmethod
    def new_session(cls, target: str = "unset") -> "SpartanAgent":
        return cls(Session(target=target))

    @classmethod
    def load_session(cls, session_id: str) -> "SpartanAgent":
        session = Session.load(session_id)
        return cls(session)

    @classmethod
    def load_latest_session(cls) -> "SpartanAgent | None":
        session = SessionRegistry.load_latest()
        if session:
            return cls(session)
        return None
