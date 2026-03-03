"""
SPARTAN v2.0 — Source-to-Sink Data Flow Analyzer (Shannon Integration)
White-box static analysis: trace user-controlled data from sources to dangerous sinks.

Identifies:
  - SQL query construction from user input (SQLi)
  - Shell execution with user data (Command Injection)
  - HTTP client calls with user-supplied URLs (SSRF)
  - Template rendering with user data (SSTI)
  - File operations with user-controlled paths (Path Traversal)
  - Deserialization of user data (Insecure Deserialization)
  - HTML output without encoding (XSS)

Works on source code text without requiring a full AST parse.
For use in SPARTAN's analysis phase when source code is provided.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional


# ── Source patterns (user-controlled inputs) ───────────────────────────────────

SOURCE_PATTERNS: dict[str, list[str]] = {
    # Python / Django / Flask
    "python_request": [
        r"request\.args\[",
        r"request\.args\.get\(",
        r"request\.form\[",
        r"request\.form\.get\(",
        r"request\.json\[",
        r"request\.json\.get\(",
        r"request\.data",
        r"request\.body",
        r"request\.POST\[",
        r"request\.GET\[",
        r"request\.FILES\[",
        r"request\.COOKIES\[",
        r"request\.headers\[",
        r"request\.values\[",
    ],
    # Python generic
    "python_input": [
        r"input\(",
        r"sys\.argv\[",
        r"os\.environ\.get\(",
        r"os\.getenv\(",
    ],
    # JavaScript / Node.js
    "js_request": [
        r"req\.params\.",
        r"req\.query\.",
        r"req\.body\.",
        r"req\.headers\[",
        r"request\.params\.",
        r"request\.query\.",
        r"request\.body\.",
        r"ctx\.params\.",
        r"ctx\.query\.",
        r"ctx\.request\.body",
        r"event\.body",
        r"event\.queryStringParameters",
    ],
    # Java / Spring
    "java_request": [
        r"@RequestParam",
        r"@PathVariable",
        r"@RequestBody",
        r"request\.getParameter\(",
        r"request\.getHeader\(",
        r"request\.getCookies\(",
        r"getQueryString\(",
    ],
    # PHP
    "php_request": [
        r"\$_GET\[",
        r"\$_POST\[",
        r"\$_REQUEST\[",
        r"\$_COOKIE\[",
        r"\$_FILES\[",
        r"\$_SERVER\[",
        r"php://input",
    ],
    # Ruby on Rails
    "ruby_request": [
        r"params\[",
        r"params\.permit",
        r"request\.params",
        r"request\.body\.read",
    ],
    # Go
    "go_request": [
        r"r\.URL\.Query\(\)",
        r"r\.FormValue\(",
        r"r\.PostFormValue\(",
        r"chi\.URLParam\(",
        r"mux\.Vars\(",
    ],
    # Solidity (user-controlled on-chain inputs)
    "solidity_calldata": [
        r"msg\.sender",
        r"msg\.value",
        r"msg\.data",
        r"tx\.origin",
        r"calldata",
        r"_amount\b",
        r"_to\b",
        r"_from\b",
        r"_data\b",
        r"_tokenId\b",
        r"_deadline\b",
    ],
}

# ── Sink patterns (dangerous operations) ──────────────────────────────────────

SINK_PATTERNS: dict[str, list[tuple[str, str]]] = {
    # (pattern, vulnerability_class)
    "sql_injection": [
        (r"execute\(.*%.*\)", "SQL Injection via string formatting"),
        (r"execute\(f['\"]", "SQL Injection via f-string"),
        (r"cursor\.execute\(.*\+", "SQL Injection via concatenation"),
        (r"raw\(.*\+", "SQL Injection in raw query"),
        (r"query\(.*\+", "SQL Injection in query()"),
        (r"\.format\(.*\) *WHERE", "SQL Injection via .format()"),
        (r"\"SELECT.*\" *\+", "SQL Injection via string concat"),
        (r"f\"SELECT", "SQL Injection via f-string SELECT"),
        (r"f\"INSERT", "SQL Injection via f-string INSERT"),
        (r"f\"UPDATE", "SQL Injection via f-string UPDATE"),
        (r"\$\{.*\}.*WHERE", "SQL Injection in template literal (JS)"),
        (r"knex\.raw\(", "SQL Injection in knex.raw()"),
        (r"sequelize\.query\(.*\+", "SQL Injection in Sequelize raw query"),
        (r"mysqli_query\(.*\$", "SQL Injection in PHP mysqli_query"),
        (r'\$wpdb->query\(', "SQL Injection in WordPress wpdb"),
    ],
    "command_injection": [
        (r"os\.system\(.*\+", "Command Injection via os.system()"),
        (r"os\.popen\(.*\+", "Command Injection via os.popen()"),
        (r"subprocess\.run\(.*shell=True", "Command Injection via subprocess (shell=True)"),
        (r"subprocess\.Popen\(.*shell=True", "Command Injection via Popen (shell=True)"),
        (r"subprocess\.call\(.*shell=True", "Command Injection via call (shell=True)"),
        (r"exec\(.*\+", "Code/Command Injection via exec()"),
        (r"eval\(.*\+", "Code Injection via eval()"),
        (r"child_process\.exec\(", "Command Injection in Node.js exec()"),
        (r"child_process\.execSync\(", "Command Injection in Node.js execSync()"),
        (r"shell_exec\(", "Command Injection in PHP shell_exec()"),
        (r"system\(.*\$", "Command Injection in PHP system()"),
        (r"passthru\(", "Command Injection in PHP passthru()"),
        (r"`.*\$.*`", "Command Injection via PHP backtick operator"),
    ],
    "ssrf": [
        (r"requests\.get\(.*\+", "SSRF via requests.get()"),
        (r"requests\.post\(.*\+", "SSRF via requests.post()"),
        (r"urllib\.request\.urlopen\(", "SSRF via urllib.urlopen()"),
        (r"http\.get\(", "SSRF via Node.js http.get()"),
        (r"axios\.get\(", "SSRF via axios.get()"),
        (r"fetch\(", "SSRF via fetch()"),
        (r"curl_exec\(", "SSRF via PHP curl_exec()"),
        (r"file_get_contents\(.*http", "SSRF via PHP file_get_contents()"),
        (r"Net::HTTP\.get\(", "SSRF via Ruby Net::HTTP"),
        (r"http\.NewRequest\(", "SSRF via Go http.NewRequest()"),
    ],
    "ssti": [
        (r"render_template_string\(.*\+", "SSTI via Flask render_template_string()"),
        (r"jinja2\.Template\(.*\)\.render", "SSTI via Jinja2 Template from user input"),
        (r"env\.from_string\(", "SSTI via Jinja2 Environment.from_string()"),
        (r"Mustache\.render\(", "SSTI via Mustache"),
        (r"ejs\.render\(", "SSTI via EJS"),
        (r"pug\.render\(", "SSTI via Pug/Jade"),
        (r"\.render\(.*\$_", "SSTI via template engine (PHP with user input)"),
    ],
    "path_traversal": [
        (r"open\(.*\+", "Path Traversal via open()"),
        (r"open\(f['\"]", "Path Traversal via f-string in open()"),
        (r"os\.path\.join\(.*\+", "Path Traversal via os.path.join()"),
        (r"readFile\(.*\+", "Path Traversal via Node.js readFile()"),
        (r"readFileSync\(.*\+", "Path Traversal via readFileSync()"),
        (r"fopen\(.*\$", "Path Traversal via PHP fopen()"),
        (r"include\s*\(.*\$", "Path Traversal via PHP include"),
        (r"require\s*\(.*\$", "Path Traversal via PHP require"),
        (r"ioutil\.ReadFile\(", "Path Traversal via Go ioutil.ReadFile()"),
    ],
    "deserialization": [
        (r"pickle\.loads\(", "Insecure Deserialization via pickle.loads()"),
        (r"pickle\.load\(", "Insecure Deserialization via pickle.load()"),
        (r"yaml\.load\(", "Insecure Deserialization via yaml.load() without Loader"),
        (r"yaml\.load\(.*Loader=yaml\.Loader\)", "Insecure Deserialization via yaml.load(Loader=yaml.Loader)"),
        (r"marshal\.loads\(", "Insecure Deserialization via marshal.loads()"),
        (r"ObjectInputStream", "Java Insecure Deserialization via ObjectInputStream"),
        (r"unserialize\(", "PHP Object Injection via unserialize()"),
        (r"JSON\.parse\(.*eval", "JS Code Injection via JSON.parse + eval"),
        (r"node-serialize", "Insecure Deserialization via node-serialize"),
    ],
    "xss": [
        (r"innerHTML\s*=\s*.*\+", "DOM XSS via innerHTML"),
        (r"document\.write\(.*\+", "DOM XSS via document.write()"),
        (r"\.html\(.*\+", "XSS via jQuery .html()"),
        (r"render\(.*unsafe", "XSS via dangerouslySetInnerHTML (React)"),
        (r"dangerouslySetInnerHTML", "XSS via React dangerouslySetInnerHTML"),
        (r"v-html=", "XSS via Vue v-html directive"),
        (r"mark_safe\(", "XSS via Django mark_safe()"),
        (r"\|\s*safe\b", "XSS via Jinja2 |safe filter"),
        (r"echo\s+\$_", "XSS via PHP echo of user input"),
        (r"print\s+.*request\.", "XSS via direct print of request data"),
    ],
    "xxe": [
        (r"etree\.parse\(", "XXE via ElementTree without secure parser"),
        (r"lxml\.etree\.fromstring\(", "XXE via lxml (check resolve_entities)"),
        (r"DocumentBuilder", "XXE via Java DocumentBuilder"),
        (r"SAXParser", "XXE via Java SAXParser"),
        (r"simplexml_load_string\(", "XXE via PHP simplexml_load_string"),
        (r"new\s+DOMDocument\(\)", "XXE via PHP DOMDocument"),
    ],
}


@dataclass
class DataFlowFinding:
    """A detected source-to-sink data flow vulnerability."""
    file_path: str
    line_number: int
    line_content: str
    source_type: str
    sink_type: str
    vuln_class: str
    risk: str  # HIGH, MEDIUM, LOW
    description: str
    recommendation: str

    def format(self) -> str:
        return (
            f"[{self.risk}] {self.vuln_class}\n"
            f"  File: {self.file_path}:{self.line_number}\n"
            f"  Source: {self.source_type}\n"
            f"  Sink: {self.sink_type}\n"
            f"  Code: {self.line_content.strip()}\n"
            f"  Fix: {self.recommendation}"
        )


@dataclass
class DataFlowAnalysis:
    """Result of a complete source-to-sink analysis."""
    target_description: str
    files_analyzed: int
    findings: list[DataFlowFinding] = field(default_factory=list)
    sources_detected: list[tuple[str, int, str]] = field(default_factory=list)
    # (file, line, pattern)

    def summary(self) -> str:
        if not self.findings:
            return (
                f"Data flow analysis: {self.files_analyzed} files analyzed — "
                f"No direct source-to-sink flows detected.\n"
                f"Note: Analysis is regex-based; manual review recommended for complex flows."
            )
        by_risk: dict[str, list[DataFlowFinding]] = {"HIGH": [], "MEDIUM": [], "LOW": []}
        for f in self.findings:
            by_risk.get(f.risk, by_risk["LOW"]).append(f)
        lines = [
            f"Data Flow Analysis — {self.files_analyzed} files, {len(self.findings)} potential flows\n",
            f"  HIGH risk:   {len(by_risk['HIGH'])}",
            f"  MEDIUM risk: {len(by_risk['MEDIUM'])}",
            f"  LOW risk:    {len(by_risk['LOW'])}",
            "",
        ]
        for risk in ("HIGH", "MEDIUM", "LOW"):
            if by_risk[risk]:
                lines.append(f"## {risk} Risk Findings")
                for finding in by_risk[risk]:
                    lines.append(finding.format())
                    lines.append("")
        return "\n".join(lines)


class DataFlowAnalyzer:
    """
    Regex-based source-to-sink data flow analyzer.
    
    Usage:
        analyzer = DataFlowAnalyzer()
        result = analyzer.analyze_text("code_here", "filename.py")
        result = analyzer.analyze_file("/path/to/file.py")
    """

    RISK_MAP: dict[str, str] = {
        "sql_injection": "HIGH",
        "command_injection": "HIGH",
        "ssrf": "HIGH",
        "deserialization": "HIGH",
        "ssti": "HIGH",
        "path_traversal": "MEDIUM",
        "xss": "MEDIUM",
        "xxe": "MEDIUM",
    }

    REMEDIATION_MAP: dict[str, str] = {
        "sql_injection": "Use parameterized queries. Never build SQL from string concatenation.",
        "command_injection": "Use subprocess list form (no shell=True). Validate input against allowlist.",
        "ssrf": "Validate URLs against allowlist of permitted hosts/IP ranges. Block RFC-1918 and metadata IPs.",
        "deserialization": "Never deserialize untrusted data. Use JSON with schema validation.",
        "ssti": "Never pass user input to template engine as template source. Only as data.",
        "path_traversal": "Use os.path.realpath() and verify result starts with intended base directory.",
        "xss": "HTML-encode all user data before output. Use Content Security Policy.",
        "xxe": "Disable external entity processing. Use safe XML parser settings.",
    }

    def analyze_text(self, code: str, file_path: str = "<code>") -> list[DataFlowFinding]:
        """Analyze a string of source code for data flow vulnerabilities."""
        findings: list[DataFlowFinding] = []
        lines = code.splitlines()

        for line_no, line in enumerate(lines, 1):
            # Check if line contains a dangerous sink
            for sink_category, patterns in SINK_PATTERNS.items():
                for pattern, description in patterns:
                    if re.search(pattern, line):
                        # Look back in surrounding context for source taint
                        context_start = max(0, line_no - 20)
                        context = "\n".join(lines[context_start:line_no])

                        source_found = None
                        for src_type, src_patterns in SOURCE_PATTERNS.items():
                            for sp in src_patterns:
                                if re.search(sp, context):
                                    source_found = src_type
                                    break
                            if source_found:
                                break

                        risk = self.RISK_MAP.get(sink_category, "LOW")
                        # Downgrade risk if no source taint detected nearby
                        if not source_found:
                            risk = "LOW"

                        findings.append(DataFlowFinding(
                            file_path=file_path,
                            line_number=line_no,
                            line_content=line,
                            source_type=source_found or "unknown/indirect",
                            sink_type=sink_category,
                            vuln_class=description,
                            risk=risk,
                            description=description,
                            recommendation=self.REMEDIATION_MAP.get(sink_category, "Review and sanitize user input."),
                        ))

        return findings

    def deduplicate(self, findings: list[DataFlowFinding]) -> list[DataFlowFinding]:
        """Remove duplicate findings (same file, line, vuln_class)."""
        seen: set[tuple] = set()
        result = []
        for f in findings:
            key = (f.file_path, f.line_number, f.vuln_class)
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result


def analyze_sources_and_sinks(code: str, file_path: str = "<code>") -> DataFlowAnalysis:
    """
    Convenience function: analyze code for source-to-sink data flows.
    Returns a DataFlowAnalysis with findings and summary.
    """
    analyzer = DataFlowAnalyzer()
    raw_findings = analyzer.analyze_text(code, file_path)
    findings = analyzer.deduplicate(raw_findings)

    # Detect sources
    sources_detected = []
    lines = code.splitlines()
    for line_no, line in enumerate(lines, 1):
        for src_type, patterns in SOURCE_PATTERNS.items():
            for p in patterns:
                if re.search(p, line):
                    sources_detected.append((file_path, line_no, src_type))
                    break

    return DataFlowAnalysis(
        target_description=file_path,
        files_analyzed=1,
        findings=findings,
        sources_detected=sources_detected,
    )


def build_dataflow_analysis_prompt(code_snippet: str) -> str:
    """
    Generate a data flow analysis block for inclusion in SPARTAN analysis phase.
    Analyzes provided code and returns formatted findings for the LLM context.
    """
    analysis = analyze_sources_and_sinks(code_snippet, "<provided_code>")

    if not analysis.findings and not analysis.sources_detected:
        return (
            "## Data Flow Analysis\n\n"
            "No user-input sources or dangerous sinks detected in provided code.\n"
            "This may be a configuration, library, or infrastructure file.\n"
        )

    lines = [
        "## Automated Data Flow Analysis (Source → Sink)\n",
        f"Sources detected: {len(analysis.sources_detected)}",
        f"Potential vulnerable flows: {len(analysis.findings)}\n",
    ]

    if analysis.sources_detected:
        lines.append("### Detected Input Sources")
        for _file, lineno, src_type in analysis.sources_detected[:10]:
            lines.append(f"  Line {lineno}: {src_type}")
        if len(analysis.sources_detected) > 10:
            lines.append(f"  ... and {len(analysis.sources_detected) - 10} more")
        lines.append("")

    if analysis.findings:
        lines.append("### Potential Vulnerable Flows")
        for finding in analysis.findings[:20]:
            lines.append(finding.format())
            lines.append("")
        if len(analysis.findings) > 20:
            lines.append(f"  ... and {len(analysis.findings) - 20} more (truncated)")

    lines.append(
        "\n> Above findings are regex-heuristic detections. "
        "Manual code review and confirmed PoC required per 'No Exploit, No Report' policy."
    )

    return "\n".join(lines)
