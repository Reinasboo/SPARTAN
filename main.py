"""
SPARTAN v2.0 — Main CLI Entry Point
Interactive terminal interface for the autonomous security audit agent.
"""

from __future__ import annotations

import argparse
import os
import sys

# Ensure workspace root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.formatter import format_help, format_session_banner
from agent.llm_client import get_active_model
from agent.session import Session, SessionRegistry
from agent.spartan import SpartanAgent
from config.settings import BOLD, RESET_COLOR, DIM


# ── Banner ────────────────────────────────────────────────────────────────────

SPARTAN_BANNER = r"""
   _______  ___  ____  ____  ___   _  _
  / __/ _ \/ _ |/ __ \/_  / / _ | / \/ |
  \__ \/ ___/ __ / /_/ //_ < / __ |/ , |
 /___/_/  /_/ |_\____/____//_/ |_/_/|_|

  SPARTAN v2.0 — Autonomous Security Audit & Exploit Agent
  "Think like an attacker. Report like an auditor. Build like an engineer."
  ─────────────────────────────────────────────────────────
  Authorized penetration testing & bug bounty use only.
"""


# ── CLI handler ───────────────────────────────────────────────────────────────

def run_interactive(agent: SpartanAgent) -> None:
    """Run the interactive REPL loop."""
    print(SPARTAN_BANNER)
    print(format_session_banner(
        agent.session.session_id,
        agent.session.target,
        get_active_model(),
    ))

    while True:
        try:
            # Prompt with current phase
            prompt = (
                f"{BOLD}[{agent.session.phase}]>{RESET_COLOR} "
                if sys.stdout.isatty()
                else "> "
            )
            user_input = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{DIM}Saving session and exiting...{RESET_COLOR}")
            agent.session.save()
            sys.exit(0)

        if not user_input:
            continue

        lower = user_input.lower()

        # ── Built-in CLI commands ──────────────────────────────────────────
        if lower in ("exit", "quit", "q"):
            print(f"{DIM}Saving session and exiting SPARTAN.{RESET_COLOR}")
            agent.session.save()
            sys.exit(0)

        if lower in ("help", "?", "h"):
            print(format_help())
            continue

        if lower in ("clear", "cls"):
            agent.session.messages.clear()
            print("Conversation history cleared (findings preserved).")
            continue

        if lower == "sessions":
            sessions = SessionRegistry.list_sessions()
            if not sessions:
                print("No saved sessions found.")
            else:
                print(f"\n{'ID':<10} {'Target':<30} {'Phase':<15} {'Findings':<10} {'Last Active'}")
                print("─" * 80)
                for s in sessions:
                    print(
                        f"{s['session_id']:<10} {s['target']:<30} "
                        f"{s['phase']:<15} {s['findings']:<10} {s['last_active']}"
                    )
            print()
            continue

        if lower.startswith("load "):
            session_id = user_input[5:].strip()
            try:
                agent = SpartanAgent.load_session(session_id)
                print(f"Session {session_id} loaded.")
                print(agent._status_response())
            except FileNotFoundError as e:
                print(f"Error: {e}")
            continue

        if lower == "new":
            agent = SpartanAgent.new_session()
            print(f"New session started: {agent.session.session_id}")
            continue

        # ── Delegate to agent ──────────────────────────────────────────────
        try:
            result = agent.process_input(user_input)
            if result:  # non-empty means it wasn't streamed
                print(result)
        except Exception as e:
            _handle_error(e)


def _handle_error(e: Exception) -> None:
    """Handle errors gracefully with helpful messages."""
    err_str = str(e).lower()

    if "api_key" in err_str or "authentication" in err_str or "unauthorized" in err_str:
        print(
            f"\n{BOLD}API Key Error:{RESET_COLOR} Your LLM API key is missing or invalid.\n"
            "Set it via environment variable:\n"
            "  For OpenAI:     set OPENAI_API_KEY=sk-...\n"
            "  For Anthropic:  set ANTHROPIC_API_KEY=sk-ant-...\n"
            "  For OpenRouter: set OPENROUTER_API_KEY=sk-or-...\n"
            "\nYou can also configure the provider:\n"
            "  set SPARTAN_LLM_PROVIDER=openai|anthropic|openrouter\n"
        )
    elif "not installed" in err_str or "importerror" in err_str or "no module" in err_str:
        print(
            f"\n{BOLD}Import Error:{RESET_COLOR} Missing dependency.\n"
            "Run: pip install -r requirements.txt\n"
        )
    elif "rate limit" in err_str or "429" in err_str:
        print(f"\n{BOLD}Rate Limit:{RESET_COLOR} API rate limit hit. Please wait and try again.\n")
    elif "context" in err_str and "length" in err_str:
        print(
            f"\n{BOLD}Context Length Error:{RESET_COLOR} Message too long for model context window.\n"
            "Type 'clear' to reset conversation history (findings are preserved).\n"
        )
    else:
        print(f"\n{BOLD}Error:{RESET_COLOR} {e}\n")


# ── Non-interactive modes ─────────────────────────────────────────────────────

def run_single_audit(target: str, context_file: str | None = None) -> None:
    """Run a single audit pass non-interactively."""
    context = ""
    if context_file:
        try:
            with open(context_file, encoding="utf-8") as fh:
                context = fh.read()
        except FileNotFoundError:
            print(f"Context file not found: {context_file}")
            sys.exit(1)

    agent = SpartanAgent.new_session(target=target)
    print(SPARTAN_BANNER)
    print(f"Starting automated audit of: {target}\n")

    # Phase 1: Recon
    agent.process_input(f"Begin audit of: {target}. {context}")

    # Phase 2: Analysis
    agent.session.set_phase("Analysis")
    agent.process_input("Continue with full vulnerability analysis.")

    # Phase 3: Validation
    agent.session.set_phase("Validation")
    agent.process_input("Generate PoCs and validate all findings.")

    # Phase 4: Report
    agent.session.set_phase("Report")
    agent.process_input("Generate full audit report.")


def list_sessions_cmd() -> None:
    """Print all saved sessions."""
    sessions = SessionRegistry.list_sessions()
    if not sessions:
        print("No saved sessions found.")
        return
    print(f"\nSaved SPARTAN Sessions ({len(sessions)} total):\n")
    print(f"{'ID':<10} {'Target':<35} {'Phase':<15} {'Findings':<10} {'Last Active'}")
    print("─" * 85)
    for s in sessions:
        print(
            f"{s['session_id']:<10} {s['target']:<35} "
            f"{s['phase']:<15} {s['findings']:<10} {s['last_active']}"
        )
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="spartan",
        description="SPARTAN v2.0 — Autonomous Security Audit & Exploit Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                                            # Interactive mode
  python main.py --target "VaultContract"                  # Start with a target
  python main.py --target "..." --file contract.sol        # With source file
  python main.py --target "..." --file contract.sol --semgrep   # Run semgrep first
  python main.py --github https://github.com/org/repo      # Auto-fetch GitHub source
  python main.py --platform immunefi --github https://...  # Immunefi submission format
  python main.py --platform code4rena --confidence 75      # Code4rena with confidence gate
  python main.py --config audit-config.yaml                # Load YAML config
  python main.py --sessions                                # List all sessions
  python main.py --load <session-id>                       # Resume a session
  python main.py --load <session-id> --config cfg.yaml     # Resume + load config
        """,
    )
    parser.add_argument(
        "--target", "-t",
        help="Audit target (contract name, URL, repo, or description)",
    )
    parser.add_argument(
        "--file", "-f",
        help="Path to source code, ABI, or spec file to include as context",
    )
    parser.add_argument(
        "--sessions", "-s",
        action="store_true",
        help="List all saved sessions",
    )
    parser.add_argument(
        "--load", "-l",
        metavar="SESSION_ID",
        help="Load and resume a specific session by ID",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume the most recent session",
    )
    parser.add_argument(
        "--model", "-m",
        help="Override LLM model (e.g. gpt-4o, claude-opus-4-5)",
    )
    parser.add_argument(
        "--provider", "-p",
        choices=["openai", "anthropic", "openrouter"],
        help="Override LLM provider",
    )
    parser.add_argument(
        "--no-stream",
        action="store_true",
        help="Disable streaming output",
    )
    parser.add_argument(
        "--config", "-c",
        metavar="CONFIG_YAML",
        help="Path to YAML audit config file (scope, auth, rules, pipeline)",
    )
    parser.add_argument(
        "--github", "-g",
        metavar="GITHUB_URL",
        help="GitHub repo URL to auto-fetch source files (e.g. https://github.com/org/repo)",
    )
    parser.add_argument(
        "--platform",
        choices=["immunefi", "hackerone", "code4rena", "internal", "general"],
        default="general",
        help="Report platform format (immunefi/hackerone/code4rena/internal/general)",
    )
    parser.add_argument(
        "--semgrep",
        action="store_true",
        help="Run semgrep/slither static analysis on --file before analysis phase",
    )
    parser.add_argument(
        "--confidence",
        metavar="THRESHOLD",
        type=int,
        default=60,
        help="Minimum confidence (0-100) to include findings in report (default: 60)",
    )

    args = parser.parse_args()

    # Apply CLI overrides to environment
    if args.model:
        os.environ["SPARTAN_LLM_MODEL"] = args.model
    if args.provider:
        os.environ["SPARTAN_LLM_PROVIDER"] = args.provider
    if args.no_stream:
        os.environ["SPARTAN_STREAM"] = "false"

    # ── Mode dispatch ─────────────────────────────────────────────────────
    if args.sessions:
        list_sessions_cmd()
        return

    if args.load:
        try:
            agent = SpartanAgent.load_session(args.load)
            print(f"Resumed session: {args.load}")
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)
        if args.config:
            print(agent.load_config_file(args.config))
        run_interactive(agent)
        return

    if args.resume:
        agent = SpartanAgent.load_latest_session()
        if not agent:
            print("No previous sessions found. Starting fresh.")
            agent = SpartanAgent.new_session()
        else:
            print(f"Resuming session: {agent.session.session_id}")
        if args.config:
            print(agent.load_config_file(args.config))
        run_interactive(agent)
        return

    # Standard startup
    target = args.target or "unset"

    # Load context file if provided
    context = ""
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                context = fh.read()
            print(f"Loaded context from: {args.file} ({len(context)} chars)")
        except FileNotFoundError:
            print(f"File not found: {args.file}")
            sys.exit(1)

    agent = SpartanAgent.new_session(target=target)

    # Apply new 10x flags
    agent._platform = getattr(args, "platform", "general") or "general"
    agent._confidence_threshold = getattr(args, "confidence", 60)

    # Load YAML audit config if provided
    if args.config:
        result = agent.load_config_file(args.config)
        print(result)
        # Update target if config set one
        if agent.session.target != "unset" and agent.session.target != target:
            target = agent.session.target

    # If context file provided with target, auto-start recon
    if target != "unset" and context:
        # Run static analysis pre-scan if requested
        if args.semgrep and args.file:
            print(f"Running static analysis on: {args.file}")
            scan_summary = agent.run_scanner_on_source(args.file)
            print(f"Scanner: {scan_summary}")
        agent.process_input(f"Begin security audit of {target}.\n\nSource code:\n{context[:8000]}")

    # GitHub source auto-fetch
    if args.github:
        print(f"Fetching GitHub source: {args.github}")
        gh_summary = agent.inject_github_source(args.github)
        print(f"GitHub: {gh_summary}")

    run_interactive(agent)


if __name__ == "__main__":
    main()
