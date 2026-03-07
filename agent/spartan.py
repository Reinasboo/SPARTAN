"""
SPARTAN v2.0 — Core Agent
Orchestrates phases, session memory, LLM interactions, and response formatting.
"""

from __future__ import annotations

import json as _json
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
        self.audit_config = None          # Optional AuditConfig loaded from YAML
        self._github_source_cache: str = ""   # ephemeral: cleared after analysis
        self._scanner_cache: str = ""         # ephemeral: cleared after analysis
        self._confidence_threshold: int = 60  # min confidence for report inclusion
        self._platform: str = "general"       # report platform target

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
            # Combine user input with any cached GitHub/scanner source
            combined_context = user_input
            if self._github_source_cache:
                combined_context = self._github_source_cache + "\n\n" + combined_context
                self._github_source_cache = ""  # consume once
            if self._scanner_cache:
                combined_context = self._scanner_cache + "\n\n" + combined_context
                self._scanner_cache = ""  # consume once
            user_prompt = build_analysis_prompt(
                target=self.session.target,
                attack_surface_summary=attack_surface,
                context=combined_context,
                include_web2=not is_web3,
                include_web3=is_web3,
                source_code=combined_context if len(combined_context) > 200 else None,
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

        findings_text = self._get_all_findings_detailed(
            min_confidence=self._confidence_threshold
        )
        user_prompt = build_report_prompt(
            target=self.session.target,
            session_id=self.session.session_id,
            all_findings_text=findings_text,
            platform=self._platform,
        )
        system = build_report_system_prompt(self._platform)

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

    # ── Semantic deduplication helpers ────────────────────────────────────────

    @staticmethod
    def _jaccard(a: str, b: str) -> float:
        """Jaccard similarity between two strings based on word sets."""
        set_a = set(re.findall(r"\w+", a.lower()))
        set_b = set(re.findall(r"\w+", b.lower()))
        if not set_a or not set_b:
            return 0.0
        return len(set_a & set_b) / len(set_a | set_b)

    def _is_duplicate(self, title: str, file_path: str, line_number: int) -> bool:
        """
        Return True if an equivalent finding already exists.
        Same file+line = definite dup. Jaccard similarity >= 0.7 = likely dup.
        """
        for f in self.session.findings:
            if file_path and f.file_path == file_path and line_number and f.line_number == line_number:
                return True
            if self._jaccard(title, f.title) >= 0.70:
                return True
        return False

    def _extract_and_register_findings(self, response: str, phase: str) -> None:
        """
        Extract structured JSON findings from LLM response and register them.

        P0 rules:
        - Finding must be inside a ```json block
        - Must have file_path OR vulnerable_snippet OR line_number (evidence required)
        - status == "CONFIRMED" only if LLM says so AND has evidence
        - Each CONFIRMED finding runs a devil's advocate check
        - Semantic deduplication via Jaccard similarity
        - CVSS mismatch (|computed - claimed| > 1.0) → NEEDS_REVIEW flag
        """
        # Parse all JSON blocks from the LLM response
        json_blocks = re.findall(r"```json\s*\n(.*?)\n```", response, re.DOTALL)

        for raw_block in json_blocks:
            try:
                data = _json.loads(raw_block)
            except _json.JSONDecodeError:
                continue

            # Support both a single finding dict and a list of findings
            candidates: list[dict] = data if isinstance(data, list) else [data]

            for fd in candidates:
                if not isinstance(fd, dict):
                    continue

                title = str(fd.get("title", "")).strip()
                if not title or len(title) > 150:
                    continue

                # ── Evidence gate (P0) ──────────────────────────────────
                file_path        = str(fd.get("file_path", "")).strip()
                line_number      = int(fd.get("line_number") or 0)
                vuln_snippet     = str(fd.get("vulnerable_snippet", "")).strip()
                has_evidence     = bool(file_path or vuln_snippet or line_number)

                if not has_evidence:
                    # No grounding → silently discard (anti-hallucination)
                    continue

                # ── Semantic dedup (P3) ─────────────────────────────────
                if self._is_duplicate(title, file_path, line_number):
                    continue

                # ── Normalise fields ────────────────────────────────────
                raw_severity = str(fd.get("severity", "Medium")).strip().capitalize()
                severity = raw_severity if raw_severity in (
                    "Critical", "High", "Medium", "Low", "Informational", "Gas"
                ) else "Medium"

                category             = str(fd.get("category", "Unknown")).strip()
                attack_prerequisite  = str(fd.get("attack_prerequisite", "")).strip()
                impact_justification = str(fd.get("impact_justification", "")).strip()
                confidence           = max(0, min(100, int(fd.get("confidence") or 0)))
                cvss_score           = float(fd.get("cvss_score") or 0.0)
                cvss_vector          = str(fd.get("cvss_vector", "")).strip()
                poc                  = str(fd.get("poc", "")).strip()
                summary              = impact_justification or str(fd.get("summary", "")).strip()

                # ── Confirmed logic fix (P0) ────────────────────────────
                # CONFIRMED only if LLM explicitly says so AND evidence exists
                llm_status = str(fd.get("status", "DRAFT")).strip().upper()
                if llm_status == "CONFIRMED" and has_evidence:
                    status = "CONFIRMED"
                elif llm_status == "REJECTED":
                    status = "REJECTED"
                else:
                    status = "DRAFT"

                # ── CVSS recomputation mismatch flag (P1) ───────────────
                if cvss_score > 0.0 and cvss_vector:
                    computed = _estimate_cvss_from_vector(cvss_vector)
                    if computed is not None and abs(computed - cvss_score) > 1.0:
                        status = "NEEDS_REVIEW"  # flag for human review

                # ── Devil's advocate check for CONFIRMED findings (P0) ──
                rejection_reason = ""
                if status == "CONFIRMED":
                    from agent.tools.devil_advocate import devil_advocate_check
                    verdict = devil_advocate_check(
                        title=title,
                        severity=severity,
                        category=category,
                        file_path=file_path,
                        line_number=line_number,
                        vulnerable_snippet=vuln_snippet,
                        attack_prerequisite=attack_prerequisite,
                        impact_justification=impact_justification,
                        source_context=self._get_last_source_context(),
                    )
                    if verdict.verdict == "REJECTED":
                        status = "REJECTED"
                        rejection_reason = f"Devil's advocate: {verdict.reason}"
                    elif verdict.verdict == "NEEDS_MORE_EVIDENCE":
                        status = "DRAFT"
                        rejection_reason = f"Needs more evidence: {verdict.reason}"
                    # Update confidence with devil's advocate own confidence
                    if verdict.confidence > 0 and status == "CONFIRMED":
                        confidence = max(confidence, verdict.confidence)

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
                    confirmed=(status == "CONFIRMED"),
                    poc=poc,
                    phase_found=phase,
                    raw_report=response[:500],
                    file_path=file_path,
                    line_number=line_number,
                    vulnerable_snippet=vuln_snippet,
                    attack_prerequisite=attack_prerequisite,
                    impact_justification=impact_justification,
                    confidence=confidence,
                    status=status,
                    rejection_reason=rejection_reason,
                )
                self.session.add_finding(finding)

    def _get_last_source_context(self) -> str:
        """Return the most recent user-provided source code context for devil's advocate."""
        for msg in reversed(self.session.messages):
            if msg["role"] == "user" and len(msg["content"]) > 300:
                return msg["content"][:2000]
        return ""

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

    def _get_all_findings_detailed(self, min_confidence: int = 0) -> str:
        """Return detailed findings text for report generation.

        Only includes findings with confidence >= min_confidence and
        status not REJECTED.
        """
        reportable = [
            f for f in self.session.findings
            if f.status != "REJECTED" and f.confidence >= min_confidence
        ]
        if not reportable:
            return "(No reportable findings — check confidence threshold or generate from conversation context)"
        lines = []
        for f in reportable:
            conf_tier = (
                "CONFIRMED" if f.confidence >= 85 else
                "NEEDS_VERIFICATION" if f.confidence >= 60 else
                "LOW_CONFIDENCE"
            )
            lines.append(
                f"### {f.finding_id}: {f.title}\n"
                f"Severity: {f.severity}\n"
                f"Category: {f.category}\n"
                f"Target: {f.target}\n"
                f"File: {f.file_path} line {f.line_number}\n"
                f"CVSS: {f.cvss_score} {f.cvss_vector}\n"
                f"Status: {f.status} | Confidence: {f.confidence}% ({conf_tier})\n"
                f"Confirmed: {f.confirmed}\n"
                f"Summary: {f.summary}\n"
                f"Vulnerable Snippet: {f.vulnerable_snippet}\n"
                f"Attack Prerequisite: {f.attack_prerequisite}\n"
                f"Impact: {f.impact_justification}\n"
                f"PoC: {f.poc}\n"
                f"Phase: {f.phase_found}\n"
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

    def inject_github_source(self, github_url: str) -> str:
        """
        Fetch source files from a GitHub repo and store them as context.
        Returns a summary string. Source is prepended to the next analysis prompt.
        """
        from agent.tools.github_fetcher import fetch_github_repo, is_github_url
        if not is_github_url(github_url):
            return f"Not a recognisable GitHub URL: {github_url}"
        result = fetch_github_repo(github_url)
        if result.error:
            return f"GitHub fetch failed: {result.error}"
        # Store source as a session note so analysis phase can pick it up
        from agent.tools.code_chunker import chunk_source_dict, chunks_to_prompt
        chunks = chunk_source_dict(result.files)
        context_block = chunks_to_prompt(chunks, max_chars=30_000)
        summary = result.summary()
        self.session.notes.append(f"[GITHUB SOURCE]\n{summary}\n\n{context_block}")
        self._github_source_cache = context_block  # ephemeral cache
        return summary

    def run_scanner_on_source(self, source_path: str) -> str:
        """
        Run semgrep/slither on a local path and inject findings as analysis context.
        Returns a human-readable summary.
        """
        from agent.tools.scanner import scan_source
        result = scan_source(source_path)
        context = result.to_context_string()
        if result.has_findings:
            self.session.notes.append(f"[SCANNER PRE-SCAN]\n{context}")
            self._scanner_cache = context
        tools = ", ".join(result.tools_run) if result.tools_run else "none"
        skipped = ", ".join(result.skipped) if result.skipped else "none"
        return (
            f"Scanner run: {len(result.findings)} findings | "
            f"tools: {tools} | skipped: {skipped}"
        )


# ── Module-level CVSS helpers ─────────────────────────────────────────────────

# Simplified AV/AC/PR/UI/S/C/I/A scoring table (CVSS v3.1 numerics)
_CVSS_AV   = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_CVSS_AC   = {"L": 0.77, "H": 0.44}
_CVSS_PR   = {"N": 0.85, "L": 0.62, "H": 0.27}
_CVSS_PR_S = {"N": 0.85, "L": 0.68, "H": 0.50}   # scope changed
_CVSS_UI   = {"N": 0.85, "R": 0.62}
_CVSS_CIA  = {"N": 0.00, "L": 0.22, "H": 0.56}
_CVSS_SCOPE_CHANGED = "C"


def _estimate_cvss_from_vector(vector: str) -> float | None:
    """
    Compute an approximate CVSS v3.1 base score from an AV:../AC:../...
    vector string. Returns None if the vector cannot be parsed.
    """
    try:
        parts: dict[str, str] = {}
        for segment in vector.split("/"):
            if ":" in segment:
                k, v = segment.split(":", 1)
                parts[k.upper()] = v.upper()

        av = _CVSS_AV.get(parts.get("AV", ""), None)
        ac = _CVSS_AC.get(parts.get("AC", ""), None)
        scope = parts.get("S", "U")
        pr_table = _CVSS_PR_S if scope == _CVSS_SCOPE_CHANGED else _CVSS_PR
        pr = pr_table.get(parts.get("PR", ""), None)
        ui = _CVSS_UI.get(parts.get("UI", ""), None)
        c  = _CVSS_CIA.get(parts.get("C", ""), None)
        i  = _CVSS_CIA.get(parts.get("I", ""), None)
        a  = _CVSS_CIA.get(parts.get("A", ""), None)

        if any(x is None for x in (av, ac, pr, ui, c, i, a)):
            return None

        iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            return 0.0

        if scope == "U":
            score = min(impact + exploitability, 10)
        else:
            score = min(1.08 * (impact + exploitability), 10)

        # Roundup to 1 decimal
        import math
        score = math.ceil(score * 10) / 10
        return round(score, 1)
    except Exception:
        return None

