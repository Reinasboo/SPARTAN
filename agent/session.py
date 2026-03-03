"""
SPARTAN v2.0 — Session Memory
Persistent audit workspace tracking targets, phases, and findings.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config.settings import SESSIONS_DIR, REPORTS_DIR, SEVERITY_COLORS, RESET_COLOR, BOLD


# ── Data models ──────────────────────────────────────────────────────────────

class Finding:
    """Represents a single security finding."""

    def __init__(
        self,
        finding_id: str,
        title: str,
        severity: str,
        category: str,
        target: str,
        summary: str = "",
        cvss_score: float = 0.0,
        cvss_vector: str = "",
        confirmed: bool = False,
        poc: str = "",
        raw_report: str = "",
        phase_found: str = "",
    ):
        self.finding_id  = finding_id
        self.title       = title
        self.severity    = severity
        self.category    = category
        self.target      = target
        self.summary     = summary
        self.cvss_score  = cvss_score
        self.cvss_vector = cvss_vector
        self.confirmed   = confirmed
        self.poc         = poc
        self.raw_report  = raw_report
        self.phase_found = phase_found
        self.timestamp   = datetime.now(timezone.utc).isoformat()
        self.remediation_status: str = "open"   # open | fixed | residual_risk

    def to_dict(self) -> dict:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        f = cls.__new__(cls)
        f.__dict__.update(data)
        return f

    def one_liner(self) -> str:
        color  = SEVERITY_COLORS.get(self.severity, "")
        conf   = "" if self.confirmed else " [UNCONFIRMED]"
        return (
            f"  {color}{BOLD}{self.finding_id}{RESET_COLOR} — "
            f"{color}{self.severity}{RESET_COLOR} | "
            f"{self.title}{conf}"
        )


# ── Session ──────────────────────────────────────────────────────────────────

class Session:
    """Represents a complete SPARTAN audit session."""

    VALID_PHASES = ["Recon", "Analysis", "Validation", "Report", "Remediation"]

    def __init__(
        self,
        target: str = "unset",
        session_id: str | None = None,
    ):
        self.session_id:  str           = session_id or str(uuid.uuid4())[:8]
        self.target:      str           = target
        self.phase:       str           = "Recon"
        self.findings:    list[Finding] = []
        self.finding_seq: int           = 0
        self.messages:    list[dict]    = []   # full LLM conversation history
        self.started_at:  str           = datetime.now(timezone.utc).isoformat()
        self.last_active: str           = self.started_at
        self.notes:       list[str]     = []   # analyst notes

    # ── Finding management ───────────────────────────────────────────────────

    def next_finding_id(self) -> str:
        self.finding_seq += 1
        return f"FINDING-{self.finding_seq:03d}"

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self._touch()

    def get_finding(self, finding_id: str) -> Finding | None:
        return next((f for f in self.findings if f.finding_id == finding_id), None)

    # ── Phase management ─────────────────────────────────────────────────────

    def set_phase(self, phase: str) -> None:
        if phase not in self.VALID_PHASES:
            raise ValueError(f"Invalid phase: {phase}. Must be one of {self.VALID_PHASES}")
        self.phase = phase
        self._touch()

    def advance_phase(self) -> str | None:
        idx = self.VALID_PHASES.index(self.phase)
        if idx + 1 < len(self.VALID_PHASES):
            self.phase = self.VALID_PHASES[idx + 1]
            self._touch()
            return self.phase
        return None

    # ── Message history ──────────────────────────────────────────────────────

    def add_message(self, role: str, content: str) -> None:
        self.messages.append({"role": role, "content": content})
        self._touch()

    # ── Severity summary ─────────────────────────────────────────────────────

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def severity_summary(self) -> str:
        counts = self.severity_counts()
        if not counts:
            return "No findings yet."
        parts = []
        for sev in ["Critical", "High", "Medium", "Low", "Informational", "Gas"]:
            if sev in counts:
                color = SEVERITY_COLORS.get(sev, "")
                parts.append(f"{color}{counts[sev]} {sev}{RESET_COLOR}")
        return " | ".join(parts)

    # ── Status overview ──────────────────────────────────────────────────────

    def status_block(self) -> str:
        lines = [
            f"{BOLD}Session ID:{RESET_COLOR}  {self.session_id}",
            f"{BOLD}Target:{RESET_COLOR}      {self.target}",
            f"{BOLD}Phase:{RESET_COLOR}       {self.phase}",
            f"{BOLD}Findings:{RESET_COLOR}    {self.severity_summary()}",
            f"{BOLD}Started:{RESET_COLOR}     {self.started_at[:19]}Z",
            f"{BOLD}Last Active:{RESET_COLOR} {self.last_active[:19]}Z",
        ]
        if self.findings:
            lines.append(f"\n{BOLD}Finding List:{RESET_COLOR}")
            for f in self.findings:
                lines.append(f.one_liner())
        return "\n".join(lines)

    # ── Serialization ────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        s = cls.__new__(cls)
        s.__dict__.update(data)
        s.findings = [Finding.from_dict(fd) for fd in data.get("findings", [])]
        return s

    def save(self) -> Path:
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        path = SESSIONS_DIR / f"session_{self.session_id}.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)
        return path

    @classmethod
    def load(cls, session_id: str) -> "Session":
        path = SESSIONS_DIR / f"session_{session_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"Session {session_id} not found at {path}")
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _touch(self) -> None:
        self.last_active = datetime.now(timezone.utc).isoformat()


# ── Session registry ─────────────────────────────────────────────────────────

class SessionRegistry:
    """Manages all sessions on disk."""

    @staticmethod
    def list_sessions() -> list[dict[str, Any]]:
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        sessions = []
        for path in sorted(SESSIONS_DIR.glob("session_*.json")):
            try:
                with open(path, encoding="utf-8") as fh:
                    d = json.load(fh)
                sessions.append({
                    "session_id":  d.get("session_id", "?"),
                    "target":      d.get("target", "?"),
                    "phase":       d.get("phase", "?"),
                    "findings":    len(d.get("findings", [])),
                    "last_active": d.get("last_active", "")[:19],
                })
            except Exception:
                pass
        return sessions

    @staticmethod
    def load_latest() -> Session | None:
        sessions = SessionRegistry.list_sessions()
        if not sessions:
            return None
        latest = max(sessions, key=lambda s: s["last_active"])
        return Session.load(latest["session_id"])
