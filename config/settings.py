"""
SPARTAN v2.0 — Configuration & Settings
"""

import os
from pathlib import Path

# Auto-load .env file if present
try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).resolve().parent.parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path)
except ImportError:
    pass  # python-dotenv not installed — use system environment vars

# ── Base paths ──────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
SESSIONS_DIR = BASE_DIR / "sessions"
REPORTS_DIR  = BASE_DIR / "reports"

# ── LLM Provider ────────────────────────────────────────────
# Supported: "openai" | "anthropic" | "openrouter" | "gemini"
LLM_PROVIDER  = os.getenv("SPARTAN_LLM_PROVIDER", "openai")
LLM_MODEL     = os.getenv("SPARTAN_LLM_MODEL",    "gpt-4o")
LLM_API_KEY   = os.getenv("OPENAI_API_KEY",        "")
ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY",     "")
OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY",   "")
GEMINI_KEY    = os.getenv("GEMINI_API_KEY",         "")

# Model aliases
ANTHROPIC_MODEL   = os.getenv("SPARTAN_ANTHROPIC_MODEL",  "claude-opus-4-5")
OPENROUTER_MODEL  = os.getenv("SPARTAN_OPENROUTER_MODEL", "anthropic/claude-opus-4-5")
GEMINI_MODEL      = os.getenv("SPARTAN_GEMINI_MODEL",     "gemini-2.0-flash")

# ── Generation parameters ────────────────────────────────────
MAX_TOKENS    = int(os.getenv("SPARTAN_MAX_TOKENS",  "8192"))
TEMPERATURE   = float(os.getenv("SPARTAN_TEMPERATURE", "0.2"))

# ── Behaviour flags ──────────────────────────────────────────
AUTO_ADVANCE_PHASES = os.getenv("SPARTAN_AUTO_ADVANCE", "true").lower() == "true"
STREAM_OUTPUT       = os.getenv("SPARTAN_STREAM",       "true").lower() == "true"
SAVE_SESSIONS       = os.getenv("SPARTAN_SAVE_SESSIONS","true").lower() == "true"

# ── CVSS severity thresholds ─────────────────────────────────
CVSS_CRITICAL = 9.0
CVSS_HIGH     = 7.0
CVSS_MEDIUM   = 4.0
CVSS_LOW      = 0.1

# ── Platform severity maps ───────────────────────────────────
IMMUNEFI_SEVERITIES   = ["Critical", "High", "Medium", "Low"]
HACKERONE_SEVERITIES  = ["P1", "P2", "P3", "P4", "P5"]
CODE4RENA_SEVERITIES  = ["High", "Medium", "Low", "Informational", "Gas"]

# ── Finding severity colors (for terminal) ───────────────────
SEVERITY_COLORS = {
    "Critical":      "\033[91m",   # bright red
    "High":          "\033[31m",   # red
    "Medium":        "\033[33m",   # yellow
    "Low":           "\033[34m",   # blue
    "Informational": "\033[36m",   # cyan
    "Gas":           "\033[35m",   # magenta
}
RESET_COLOR = "\033[0m"
BOLD        = "\033[1m"
DIM         = "\033[2m"
