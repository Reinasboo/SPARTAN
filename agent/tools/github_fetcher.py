"""
SPARTAN v2.0 — GitHub Source Fetcher

Fetches auditable source files from a public (or token-authenticated) GitHub
repository via the REST API + raw.githubusercontent.com, with no third-party
dependencies beyond the Python standard library.

Rate limits:
  - Anonymous:       60 API req / hr
  - GITHUB_TOKEN:  5 000 API req / hr

Usage:
    from agent.tools.github_fetcher import fetch_github_repo, is_github_url
    result = fetch_github_repo("https://github.com/owner/repo")
    print(result.summary())
    for path, content in result.files.items():
        ...
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────

AUDIT_EXTENSIONS: frozenset[str] = frozenset({
    ".sol", ".vy", ".py", ".js", ".ts", ".rs", ".go", ".cairo", ".move",
})

# Directories that almost never contain auditable code
SKIP_DIRS: frozenset[str] = frozenset({
    "node_modules", ".git", "dist", "build", "out", "artifacts",
    "cache", "__pycache__", "lib", "vendor", "third_party",
    "typechain", "typechain-types", "coverage",
})

MAX_FILE_BYTES  = 200_000   # skip files > 200KB
MAX_FILES       = 150
MAX_TOTAL_CHARS = 600_000   # ~600KB total source — stops before context overrun

_GH_API_BASE = "https://api.github.com"
_GH_RAW_BASE = "https://raw.githubusercontent.com"


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class FetchedRepo:
    owner: str
    repo: str
    ref: str                              # resolved branch / tag / SHA
    files: dict[str, str] = field(default_factory=dict)   # relative path → content
    error: str = ""
    total_chars: int = 0
    skipped_files: int = 0

    def summary(self) -> str:
        if self.error:
            return f"GitHub fetch error: {self.error}"
        return (
            f"Fetched {len(self.files)} file(s) from "
            f"{self.owner}/{self.repo}@{self.ref} — "
            f"{self.total_chars:,} chars "
            f"({self.skipped_files} skipped)"
        )

    def to_source_dict(self) -> dict[str, str]:
        """Alias: return files dict."""
        return self.files


# ── URL parsing ───────────────────────────────────────────────────────────────

_GH_URL_RE = re.compile(
    r"https?://github\.com/([^/\s]+)/([^/\s?#]+)"
    r"(?:/tree/([^/\s?#]+))?",
)


def is_github_url(text: str) -> bool:
    """Return True if *text* contains a recognisable GitHub repository URL."""
    return bool(_GH_URL_RE.search(text.strip()))


def _parse_github_url(url: str) -> tuple[str, str, str]:
    """
    Parse a GitHub URL and return (owner, repo, ref).

    Accepted forms:
      https://github.com/owner/repo
      https://github.com/owner/repo.git
      https://github.com/owner/repo/tree/main
    """
    url = url.split("?")[0].split("#")[0].rstrip("/").removesuffix(".git")
    m = _GH_URL_RE.match(url)
    if not m:
        raise ValueError(f"Cannot parse GitHub URL: {url!r}")
    owner = m.group(1)
    repo  = m.group(2)
    ref   = m.group(3) or "HEAD"
    return owner, repo, ref


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _make_request(url: str, token: str = "") -> bytes:
    """Execute a GET request and return the response body as bytes."""
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("User-Agent", "SPARTAN-Security-Agent/2.0")
    if token:
        req.add_header("Authorization", f"token {token}")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read()


def _gh_api(path: str, token: str = "") -> dict | list:
    """Call the GitHub REST API and return parsed JSON."""
    url = f"{_GH_API_BASE}/{path.lstrip('/')}"
    body = _make_request(url, token)
    return json.loads(body)


def _fetch_raw(owner: str, repo: str, ref: str, path: str, token: str = "") -> str:
    """Fetch a single file's raw text content."""
    url = f"{_GH_RAW_BASE}/{owner}/{repo}/{ref}/{path}"
    body = _make_request(url, token)
    return body.decode("utf-8", errors="replace")


# ── Tree walker ───────────────────────────────────────────────────────────────

def _walk_tree(owner: str, repo: str, tree_sha: str, token: str = "") -> list[dict]:
    """Return all blob entries in the git tree (recursive)."""
    data = _gh_api(
        f"repos/{owner}/{repo}/git/trees/{tree_sha}?recursive=1",
        token,
    )
    return [item for item in data.get("tree", []) if item.get("type") == "blob"]


# ── Public API ────────────────────────────────────────────────────────────────

def fetch_github_repo(
    url: str,
    token: str = "",
    focus_paths: list[str] | None = None,
) -> FetchedRepo:
    """
    Fetch auditable source files from a GitHub repository.

    Args:
        url:         GitHub repo URL.
        token:       GitHub personal access token (or set GITHUB_TOKEN env var).
        focus_paths: If provided, only files whose path starts with one of these
                     prefixes are fetched (e.g. ["contracts/", "src/"]).

    Returns:
        FetchedRepo with .files dict and .summary().
    """
    token = token or os.getenv("GITHUB_TOKEN", "")

    try:
        owner, repo, ref = _parse_github_url(url)
    except ValueError as exc:
        return FetchedRepo(owner="", repo="", ref="", error=str(exc))

    fetched = FetchedRepo(owner=owner, repo=repo, ref=ref)

    # ── Resolve ref → tree SHA ────────────────────────────────────────────
    try:
        commit_data = _gh_api(f"repos/{owner}/{repo}/commits/{ref}", token)
        tree_sha = commit_data["commit"]["tree"]["sha"]
        # Store the resolved SHA as the ref for traceability
        fetched.ref = commit_data.get("sha", ref)[:12]
    except urllib.error.HTTPError as exc:
        fetched.error = f"GitHub API HTTP {exc.code}: {exc.reason}"
        return fetched
    except Exception as exc:
        fetched.error = f"GitHub API error: {exc}"
        return fetched

    # ── Walk tree ─────────────────────────────────────────────────────────
    try:
        blobs = _walk_tree(owner, repo, tree_sha, token)
    except Exception as exc:
        fetched.error = f"Tree walk error: {exc}"
        return fetched

    total_chars = 0
    files_fetched = 0

    for blob in blobs:
        path = blob.get("path", "")
        ext  = Path(path).suffix.lower()

        # Extension filter
        if ext not in AUDIT_EXTENSIONS:
            continue

        # Directory skip list
        parts = path.split("/")
        if any(part in SKIP_DIRS for part in parts[:-1]):
            continue

        # Focus path filter
        if focus_paths and not any(path.startswith(fp) for fp in focus_paths):
            continue

        # Hard caps
        if blob.get("size", 0) > MAX_FILE_BYTES:
            fetched.skipped_files += 1
            continue
        if files_fetched >= MAX_FILES or total_chars >= MAX_TOTAL_CHARS:
            fetched.skipped_files += 1
            continue

        try:
            content = _fetch_raw(owner, repo, fetched.ref, path, token)
            fetched.files[path] = content
            total_chars   += len(content)
            files_fetched += 1
        except Exception:
            fetched.skipped_files += 1

    fetched.total_chars = total_chars
    return fetched


def detect_repo_language(files: dict[str, str]) -> str:
    """Heuristically determine the primary language of a fetched repository."""
    counts: dict[str, int] = {}
    for path in files:
        ext = Path(path).suffix.lower()
        counts[ext] = counts.get(ext, 0) + 1

    if not counts:
        return "unknown"

    dominant = max(counts, key=lambda e: counts[e])
    return {
        ".sol":   "solidity",
        ".vy":    "vyper",
        ".py":    "python",
        ".js":    "javascript",
        ".ts":    "typescript",
        ".rs":    "rust",
        ".go":    "go",
        ".cairo": "cairo",
    }.get(dominant, "text")
