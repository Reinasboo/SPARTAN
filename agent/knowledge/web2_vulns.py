"""
SPARTAN v2.0 — Web2 / API / Infrastructure Vulnerability Knowledge Base
Full taxonomy with detection hints, CVSS guidance, and remediation pointers.
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class VulnClass:
    name: str
    cwe: list[str]
    description: str
    detection_hints: list[str]
    attack_patterns: list[str]
    cvss_guidance: str
    remediation: str
    references: list[str] = field(default_factory=list)


WEB2_VULNERABILITIES: list[VulnClass] = [

    VulnClass(
        name="SQL Injection (SQLi)",
        cwe=["CWE-89"],
        description="Attacker injects SQL code into input that is concatenated into a database query, "
                    "allowing unauthorized data access, modification, or command execution.",
        detection_hints=[
            "String concatenation in SQL query construction",
            "Raw query execution without parameterization",
            "ORM raw() / execute() called with user-controlled input",
            "Error messages leaking DB schema information",
        ],
        attack_patterns=[
            "' OR '1'='1",
            "'; DROP TABLE users;--",
            "UNION SELECT username, password FROM users--",
            "Time-based blind: '; IF(1=1) WAITFOR DELAY '0:0:5'--",
        ],
        cvss_guidance=(
            "Critical (9.8) if unauthenticated with direct data access. "
            "High (8.x) if post-auth but sensitive data exposed."
        ),
        remediation=(
            "Use parameterized queries / prepared statements exclusively. "
            "Apply least-privilege DB accounts. Validate and sanitize all inputs. "
            "Use ORM safely (avoid raw queries). Implement WAF as defense-in-depth."
        ),
        references=["https://owasp.org/www-community/attacks/SQL_Injection", "CWE-89"],
    ),

    VulnClass(
        name="NoSQL Injection (NoSQLi)",
        cwe=["CWE-943"],
        description="Injection into NoSQL query operators (e.g., MongoDB $where, $gt) via unvalidated "
                    "user-controlled objects, bypassing authentication or extracting data.",
        detection_hints=[
            "JSON body parsed directly into DB query",
            "MongoDB: query built from req.body without sanitization",
            "Mongoose.find({username: req.body.username})",
        ],
        attack_patterns=[
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            '{"$where": "this.password.length > 0"}',
        ],
        cvss_guidance="Critical if auth bypass possible. High if data extraction only.",
        remediation=(
            "Validate and sanitize all user input before DB queries. "
            "Use allowlist for accepted query fields. "
            "Disable dangerous operators ($where, $regex on sensitive fields)."
        ),
        references=["CWE-943", "https://owasp.org/www-project-web-security-testing-guide/"],
    ),

    VulnClass(
        name="Server-Side Request Forgery (SSRF)",
        cwe=["CWE-918"],
        description="Attacker induces the server to make HTTP requests to internal resources, "
                    "cloud metadata endpoints, or arbitrary external hosts.",
        detection_hints=[
            "Application fetches user-supplied URLs",
            "Webhook, import, export, or screenshot features",
            "DNS rebinding potential",
            "Cloud metadata reachable at 169.254.169.254",
        ],
        attack_patterns=[
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://internal-service:8080/admin",
            "file:///etc/passwd",
            "dict://localhost:6379/",
        ],
        cvss_guidance=(
            "Critical if cloud metadata with IAM creds accessible. "
            "High if internal services reachable. Medium if DNS-only."
        ),
        remediation=(
            "Allowlist permitted URL schemes and hosts. "
            "Block metadata IP ranges (169.254.x.x, 100.100.x.x). "
            "Use a dedicated egress proxy. Disable unnecessary URL-fetch features."
        ),
        references=["CWE-918", "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/"],
    ),

    VulnClass(
        name="Insecure Direct Object Reference (IDOR)",
        cwe=["CWE-639"],
        description="Attacker accesses or modifies resources belonging to other users by manipulating "
                    "predictable object identifiers (IDs, filenames, UUIDs) in requests.",
        detection_hints=[
            "Sequential or guessable IDs in URL paths or parameters",
            "No server-side ownership check before returning resource",
            "GUIDs used but not verified against authenticated user",
        ],
        attack_patterns=[
            "GET /api/invoices/1001 (attacker changes to /api/invoices/1002)",
            "PUT /api/users/5/email with different user's token",
        ],
        cvss_guidance="High (7.5) for data exposure. Critical if PII or financial records.",
        remediation=(
            "Always verify resource ownership server-side before access. "
            "Use indirect references mapped to user context. "
            "Implement authorization middleware at every endpoint."
        ),
        references=["CWE-639", "https://owasp.org/www-project-web-security-testing-guide/"],
    ),

    VulnClass(
        name="Broken Authentication",
        cwe=["CWE-287", "CWE-384"],
        description="Flaws in authentication mechanisms allowing attackers to assume other users' "
                    "identities through credential stuffing, session fixation, or token weaknesses.",
        detection_hints=[
            "Weak password policy or no lockout",
            "Predictable session tokens",
            "Session not invalidated on logout",
            "Password reset tokens with long expiry or no single-use enforcement",
            "Missing MFA on sensitive actions",
        ],
        attack_patterns=[
            "Credential stuffing with leaked password lists",
            "Session fixation: attacker sets session ID before login",
            "Password reset token brute force",
        ],
        cvss_guidance="Critical (9.x) if unauthenticated admin access possible. High (8.x) otherwise.",
        remediation=(
            "Enforce strong passwords + bcrypt/Argon2 hashing. "
            "Implement account lockout and MFA. "
            "Regenerate session ID on privilege elevation. "
            "Single-use, short-lived password reset tokens."
        ),
        references=["CWE-287", "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
    ),

    VulnClass(
        name="JWT Attacks",
        cwe=["CWE-347"],
        description="Vulnerabilities in JWT implementation: alg:none bypass, weak HMAC secrets, "
                    "RSA/HMAC confusion, claim injection, or lack of expiry validation.",
        detection_hints=[
            "alg header is accepted from client",
            "HS256 used with public key as secret",
            "Short or guessable JWT secret",
            "No exp/nbf claim validation",
            "kid header used in file path or SQL query",
        ],
        attack_patterns=[
            '{"alg":"none"} with empty signature',
            "RS256→HS256 confusion: sign with public key as HMAC secret",
            'kid: "../../dev/null" (null key)',
            "jwt-cracker on weak HS256 secret",
        ],
        cvss_guidance="Critical (9.x) if auth bypass. High if privilege escalation.",
        remediation=(
            "Fix algorithm in server config, never accept from client. "
            "Use strong randomly-generated secrets (≥256 bits). "
            "Validate all standard claims (exp, nbf, iss, aud). "
            "Use asymmetric keys (RS256/ES256) for distributed systems."
        ),
        references=["CWE-347", "https://portswigger.net/web-security/jwt"],
    ),

    VulnClass(
        name="XML External Entity (XXE)",
        cwe=["CWE-611"],
        description="XML parser resolves external entity references, enabling file disclosure, "
                    "SSRF, or denial of service via billion-laughs attacks.",
        detection_hints=[
            "Application parses XML input",
            "DOCTYPE declarations accepted",
            "External entity processing not disabled",
        ],
        attack_patterns=[
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal:8080/">]>',
        ],
        cvss_guidance="High if file read. Critical if combined with SSRF to cloud metadata.",
        remediation=(
            "Disable external entity and DTD processing in XML parser. "
            "Use less complex data formats (JSON) where possible. "
            "Patch/upgrade XML libraries regularly."
        ),
        references=["CWE-611", "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
    ),

    VulnClass(
        name="Server-Side Template Injection (SSTI)",
        cwe=["CWE-94"],
        description="User input is embedded directly in server-side templates and evaluated, "
                    "allowing remote code execution in the template engine context.",
        detection_hints=[
            "User input reflected in rendered HTML without sanitization",
            "Template engine in use (Jinja2, Twig, Velocity, FreeMarker, Pebble)",
            "Expression language in error messages",
        ],
        attack_patterns=[
            "{{7*7}} → 49 (Jinja2/Twig)",
            "${7*7} → 49 (Velocity/FreeMarker)",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        ],
        cvss_guidance="Critical (9.8+) — typically leads to RCE.",
        remediation=(
            "Never concatenate user input into templates. "
            "Use sandboxed template engines. "
            "Validate and encode all user-supplied data before rendering."
        ),
        references=["CWE-94", "https://portswigger.net/research/server-side-template-injection"],
    ),

    VulnClass(
        name="Race Condition / TOCTOU",
        cwe=["CWE-362"],
        description="Time-of-check to time-of-use flaws where state changes between validation "
                    "and use, enabling double-spend, limit bypass, or privilege escalation.",
        detection_hints=[
            "Check-then-act patterns without atomic locking",
            "Concurrent requests to same endpoint modifying shared state",
            "Balance/limit checks before deductions without transactions",
        ],
        attack_patterns=[
            "Parallel requests to /withdraw before balance decremented",
            "Concurrent coupon redemption before used-flag set",
        ],
        cvss_guidance="High (7.x–8.x) for financial impact. Medium for logic bypass.",
        remediation=(
            "Use database transactions with proper isolation levels. "
            "Implement idempotency keys. "
            "Use optimistic/pessimistic locking. "
            "Redis atomic operations (INCR, SETNX) for counters."
        ),
        references=["CWE-362"],
    ),

    VulnClass(
        name="Insecure Deserialization",
        cwe=["CWE-502"],
        description="Deserializing attacker-controlled data in Java, Python Pickle, PHP, or .NET "
                    "can lead to remote code execution or denial of service.",
        detection_hints=[
            "pickle.loads(), unserialize(), ObjectInputStream",
            "User-supplied base64 or binary data fed to deserializer",
            "Java rO0AB or Python pickle magic bytes in request bodies",
        ],
        attack_patterns=[
            "Python: pickle.loads with __reduce__ RCE payload",
            "Java: ysoserial gadget chains via serialized Objects",
        ],
        cvss_guidance="Critical (9.x) — commonly leads to RCE.",
        remediation=(
            "Avoid deserializing untrusted data. "
            "Use safe formats (JSON with schema validation). "
            "Implement integrity checks (HMAC) before deserialization. "
            "Use allowlist deserialization filters."
        ),
        references=["CWE-502", "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
    ),

    VulnClass(
        name="Business Logic Flaw",
        cwe=["CWE-840"],
        description="Application-specific logic errors that allow attackers to abuse intended "
                    "functionality: discount stacking, refund abuse, workflow bypass, rate bypass.",
        detection_hints=[
            "Multi-step workflows with resumable state",
            "Discount/coupon codes without unique-use enforcement",
            "Price or quantity fields modifiable client-side",
            "API endpoints callable out-of-order",
        ],
        attack_patterns=[
            "Negative quantity in order for refund > original price",
            "Skip payment step by directly calling order confirmation endpoint",
            "Stack unlimited coupons",
        ],
        cvss_guidance="Medium–High depending on financial impact.",
        remediation=(
            "Enforce workflow state server-side. "
            "Validate all business constraints on the backend. "
            "Implement rate limiting on sensitive actions. "
            "Audit every state transition in the application flow."
        ),
        references=["CWE-840"],
    ),

    VulnClass(
        name="OAuth2 Misconfiguration",
        cwe=["CWE-601", "CWE-346"],
        description="Flaws in OAuth2 implementation: open redirects in redirect_uri, "
                    "missing state parameter (CSRF), implicit flow token leakage, PKCE bypass.",
        detection_hints=[
            "redirect_uri accepts wildcard or any subdomain",
            "state parameter missing or not validated",
            "Authorization code reuse not prevented",
            "Implicit flow returning tokens in URL fragment",
        ],
        attack_patterns=[
            "Redirect to attacker domain via loose redirect_uri match",
            "CSRF: forge authorization flow without state validation",
            "Code injection: intercept auth code via referrer header",
        ],
        cvss_guidance="Critical if account takeover possible. High for token theft.",
        remediation=(
            "Exact-match redirect_uri validation. "
            "Enforce PKCE for all public clients. "
            "Use authorization code flow, not implicit. "
            "Validate and bind state parameter to session."
        ),
        references=["https://datatracker.ietf.org/doc/html/rfc6749", "https://portswigger.net/web-security/oauth"],
    ),

    VulnClass(
        name="Path Traversal",
        cwe=["CWE-22"],
        description="User-controlled file paths allow traversal outside the intended directory, "
                    "enabling read/write of arbitrary files on the server.",
        detection_hints=[
            "File operations using user-supplied filenames",
            "../ sequences not stripped or blocked",
            "URL-encoded or double-encoded traversal sequences",
        ],
        attack_patterns=[
            "../../../../etc/passwd",
            "..%2F..%2F..%2Fetc/shadow",
            "....//....//etc/passwd (filter bypass)",
        ],
        cvss_guidance="High (7.5) for read. Critical if write/RCE possible.",
        remediation=(
            "Canonicalize paths and verify they remain within allowed root. "
            "Use chroot jails or container isolation. "
            "Reject filenames containing path separators."
        ),
        references=["CWE-22"],
    ),
]

# Build a quick lookup dict
WEB2_VULN_MAP: dict[str, VulnClass] = {v.name: v for v in WEB2_VULNERABILITIES}


def get_web2_checklist() -> str:
    """Return a formatted checklist of all Web2 vulnerability classes."""
    lines = ["## Web2 / API Vulnerability Checklist\n"]
    for v in WEB2_VULNERABILITIES:
        cwe_str = ", ".join(v.cwe)
        lines.append(f"- [ ] **{v.name}** ({cwe_str})")
    return "\n".join(lines)
