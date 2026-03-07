"""
SPARTAN v2.0 — AST-Aware Code Chunker

Splits source files at semantic boundaries (contract / class / function) so the
LLM always receives complete, coherent units rather than arbitrarily truncated
lines.  Each chunk carries its file path and line range so findings can
reference exact locations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

MAX_CHUNK_CHARS = 12_000   # about 3 000 tokens — safe for most context windows
OVERLAP_LINES   = 5        # lines of context carried across chunk boundaries

AUDIT_EXTENSIONS = {".sol", ".vy", ".py", ".js", ".ts", ".rs", ".go", ".cairo"}


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class CodeChunk:
    """A semantically coherent slice of source code."""

    index: int
    file_path: str
    language: str
    start_line: int    # 1-based
    end_line: int      # 1-based, inclusive
    content: str
    unit_name: str = ""   # contract / class / function name, if known

    def header(self) -> str:
        loc = f"Lines {self.start_line}-{self.end_line}"
        unit = f" | {self.unit_name}" if self.unit_name else ""
        return f"// FILE: {self.file_path} | {loc}{unit}"

    def as_prompt_block(self) -> str:
        return f"{self.header()}\n\n{self.content}"


# ── Language detection ────────────────────────────────────────────────────────

def _detect_language(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    return {
        ".sol":   "solidity",
        ".vy":    "vyper",
        ".py":    "python",
        ".js":    "javascript",
        ".ts":    "typescript",
        ".rs":    "rust",
        ".go":    "go",
        ".cairo": "cairo",
    }.get(ext, "text")


# ── Solidity chunker ──────────────────────────────────────────────────────────

_SOLIDITY_UNIT = re.compile(
    r"^[ \t]*(abstract[ \t]+)?(?:contract|interface|library)[ \t]+(\w+)",
)
_SOLIDITY_FN = re.compile(
    r"^[ \t]*(?:function|modifier|receive|fallback)(?:[ \t]+(\w+))?[ \t]*\(",
)


def _split_solidity(source: str, file_path: str) -> list[CodeChunk]:
    lines = source.splitlines()

    # Locate top-level contract/interface/library boundaries
    boundaries: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        m = _SOLIDITY_UNIT.match(line)
        if m:
            boundaries.append((i, m.group(2)))

    if not boundaries:
        return _split_generic(source, file_path, "solidity")

    boundaries.append((len(lines), "_end"))
    chunks: list[CodeChunk] = []

    for idx, (start, name) in enumerate(boundaries[:-1]):
        end = boundaries[idx + 1][0]
        content = "\n".join(lines[start:end])

        if len(content) > MAX_CHUNK_CHARS:
            chunks.extend(_split_solidity_by_functions(
                lines[start:end], start, file_path, name,
            ))
        else:
            chunks.append(CodeChunk(
                index=len(chunks),
                file_path=file_path,
                language="solidity",
                start_line=start + 1,
                end_line=end,
                content=content,
                unit_name=name,
            ))

    return chunks


def _split_solidity_by_functions(
    lines: list[str],
    base_offset: int,
    file_path: str,
    contract_name: str,
) -> list[CodeChunk]:
    """Further split a large contract body at function/modifier boundaries."""
    fn_starts = [0]
    fn_names  = [contract_name]

    for i, line in enumerate(lines):
        m = _SOLIDITY_FN.match(line)
        if m and i > 0:
            fn_starts.append(i)
            fn_names.append(f"{contract_name}.{m.group(1) or 'receive/fallback'}")

    fn_starts.append(len(lines))
    chunks: list[CodeChunk] = []

    for i, start in enumerate(fn_starts[:-1]):
        end = fn_starts[i + 1]
        actual_start = max(0, start - OVERLAP_LINES) if i > 0 else start
        content = "\n".join(lines[actual_start:end])
        if len(content) > MAX_CHUNK_CHARS:
            content = content[:MAX_CHUNK_CHARS] + "\n// [truncated — chunk too large]"

        chunks.append(CodeChunk(
            index=len(chunks),
            file_path=file_path,
            language="solidity",
            start_line=base_offset + actual_start + 1,
            end_line=base_offset + end,
            content=content,
            unit_name=fn_names[i],
        ))

    return chunks


# ── Python chunker ────────────────────────────────────────────────────────────

_PYTHON_UNIT = re.compile(r"^(?:class|def|async def)[ \t]+(\w+)")


def _split_python(source: str, file_path: str) -> list[CodeChunk]:
    lines = source.splitlines()
    boundaries: list[tuple[int, str]] = [(0, "<module>")]

    for i, line in enumerate(lines):
        m = _PYTHON_UNIT.match(line)
        if m and i > 0:
            boundaries.append((i, m.group(1)))

    boundaries.append((len(lines), "_end"))
    chunks: list[CodeChunk] = []

    for idx, (start, name) in enumerate(boundaries[:-1]):
        end = boundaries[idx + 1][0]
        actual_start = max(0, start - OVERLAP_LINES) if idx > 0 else start
        content = "\n".join(lines[actual_start:end])
        if len(content) > MAX_CHUNK_CHARS:
            content = content[:MAX_CHUNK_CHARS] + "\n# [truncated]"

        chunks.append(CodeChunk(
            index=len(chunks),
            file_path=file_path,
            language="python",
            start_line=actual_start + 1,
            end_line=end,
            content=content,
            unit_name=name,
        ))

    return chunks


# ── Generic fallback chunker ──────────────────────────────────────────────────

_LINES_PER_CHUNK = 200


def _split_generic(source: str, file_path: str, language: str = "text") -> list[CodeChunk]:
    """Split at fixed line intervals with overlap."""
    lines = source.splitlines()
    chunks: list[CodeChunk] = []
    i = 0

    while i < len(lines):
        start = max(0, i - OVERLAP_LINES) if i > 0 else 0
        end   = min(i + _LINES_PER_CHUNK, len(lines))
        content = "\n".join(lines[start:end])
        if len(content) > MAX_CHUNK_CHARS:
            content = content[:MAX_CHUNK_CHARS]

        chunks.append(CodeChunk(
            index=len(chunks),
            file_path=file_path,
            language=language,
            start_line=start + 1,
            end_line=end,
            content=content,
        ))
        i = end

    return chunks


# ── Public API ────────────────────────────────────────────────────────────────

def chunk_source_file(content: str, file_path: str) -> list[CodeChunk]:
    """Auto-detect language and return semantic chunks for a single file."""
    lang = _detect_language(file_path)
    if lang == "solidity":
        return _split_solidity(content, file_path)
    if lang == "python":
        return _split_python(content, file_path)
    return _split_generic(content, file_path, lang)


def chunk_source_dict(files: dict[str, str]) -> list[CodeChunk]:
    """Chunk all files from a {path: content} dict."""
    all_chunks: list[CodeChunk] = []
    for path, content in files.items():
        all_chunks.extend(chunk_source_file(content, path))
    return all_chunks


def chunks_to_prompt(chunks: list[CodeChunk], max_chars: int = 40_000) -> str:
    """
    Combine chunks into a single prompt string respecting max_chars budget.
    Appends a notice if chunks are truncated.
    """
    parts: list[str] = []
    total = 0
    omitted = 0

    for chunk in chunks:
        block = chunk.as_prompt_block()
        if total + len(block) > max_chars:
            omitted += 1
        else:
            parts.append(block)
            total += len(block)

    if omitted:
        parts.append(
            f"\n// [{omitted} chunk(s) omitted — budget exceeded. "
            "Use 'analyze-file <path>' for full per-file analysis.]\n"
        )

    return "\n\n---\n\n".join(parts)
