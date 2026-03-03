"""
SPARTAN v2.0 — OWASP Knowledge Base
OWASP Top 10 (2021) + OWASP API Security Top 10 (2023)
Used for parallel vulnerability analysis routing (Shannon-style).
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class OWASPEntry:
    id: str
    category: str
    description: str
    common_weaknesses: list[str]
    attack_vectors: list[str]
    detection_methods: list[str]
    prevention: list[str]
    references: list[str] = field(default_factory=list)
    test_payloads: list[str] = field(default_factory=list)


# ── OWASP Top 10 — 2021 ───────────────────────────────────────────────────────
OWASP_TOP10_2021: list[OWASPEntry] = [
    OWASPEntry(
        id="A01:2021",
        category="Broken Access Control",
        description=(
            "Restrictions on what authenticated users are allowed to do are not properly "
            "enforced. Attackers can exploit these flaws to access unauthorized functionality "
            "or data (other users' accounts, sensitive files, admin functions)."
        ),
        common_weaknesses=[
            "IDOR — accessing objects directly via user-controlled parameter",
            "Missing authorization on privileged API endpoints",
            "Privilege escalation (user acting as admin)",
            "JWT token manipulation to escalate role",
            "CORS misconfiguration allowing unauthorized origins",
            "Forced browsing to unauthenticated pages",
        ],
        attack_vectors=[
            "GET /api/users/123 → swap to /api/users/124 for another user's data",
            "POST /api/admin/delete with normal-user JWT",
            "Access /admin panel directly (no redirect enforced server-side)",
            "Modify JWT payload role: 'user' → 'admin' (unsigned or weak HS256)",
        ],
        detection_methods=[
            "Replace user-owned resource IDs with other users' IDs",
            "Access admin endpoints with non-admin tokens",
            "Probe for hidden admin paths (Gobuster / ffuf wordlist)",
            "Check CORS headers for wildcard or sensitive origins",
            "Decode JWT and modify claims without signature change",
        ],
        prevention=[
            "Implement server-side authorization on every endpoint",
            "Deny by default — require explicit allows",
            "Invalidate JWT on logout; use short expiry",
            "Log and alert on access control failures",
            "CORS: allowlist specific trusted domains only",
        ],
        references=["CWE-284", "CWE-285", "CWE-639", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
        test_payloads=[
            "Authorization: Bearer <other_user_token>",
            '{"role": "admin"}  // in JWT payload',
            "GET /api/admin/users  // with regular user token",
        ],
    ),
    OWASPEntry(
        id="A02:2021",
        category="Cryptographic Failures",
        description=(
            "Failures related to cryptography that lead to exposure of sensitive data. "
            "Includes weak algorithms, improper key management, transmitting data in cleartext."
        ),
        common_weaknesses=[
            "MD5/SHA1 used for password hashing",
            "Hardcoded encryption keys in source code",
            "HTTP (not HTTPS) transmitting sensitive data",
            "Weak TLS configurations (SSLv3, TLS 1.0)",
            "Predictable IV or nonce in AES-CBC/CTR",
            "Sensitive data stored in browser localStorage",
        ],
        attack_vectors=[
            "Offline brute force of MD5/SHA1 password hashes",
            "MITM on HTTP traffic to intercept credentials",
            "TLS downgrade attack (POODLE, BEAST) to decrypt traffic",
            "Extract hardcoded key from source/binary",
        ],
        detection_methods=[
            "Check password hashing algorithm (bcrypt/argon2 expected)",
            "Inspect TLS config with testssl.sh",
            "Search source for hardcoded 'secret', 'key', 'password'",
            "Check if HTTPS enforced with HSTS header",
            "Review encryption modes for ECB or static IV usage",
        ],
        prevention=[
            "Use bcrypt, Argon2, or scrypt for password hashing",
            "Enforce HTTPS everywhere with HSTS",
            "Disable TLS < 1.2; prefer TLS 1.3",
            "Use AES-GCM (authenticated encryption)",
            "Rotate keys regularly; use secrets management (Vault, AWS KMS)",
        ],
        references=["CWE-259", "CWE-327", "CWE-331", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
        test_payloads=[],
    ),
    OWASPEntry(
        id="A03:2021",
        category="Injection",
        description=(
            "User-supplied data is not validated, filtered, or sanitized, allowing malicious "
            "data to be interpreted as commands or queries. Covers SQL, NoSQL, OS command, "
            "LDAP, XML, template injection."
        ),
        common_weaknesses=[
            "SQL injection via unparameterized queries",
            "NoSQL injection (MongoDB $where, $regex operators)",
            "OS command injection via subprocess/exec",
            "LDAP injection",
            "Server-Side Template Injection (SSTI)",
            "XPath injection",
        ],
        attack_vectors=[
            "username=' OR '1'='1 in login form → bypass auth",
            "name='; DROP TABLE users;--",
            "cmd=127.0.0.1;cat /etc/passwd in ping field",
            "template={{7*7}} to detect SSTI",
        ],
        detection_methods=[
            "Input single quote ' in all parameters and observe errors",
            "Try sqlmap on parameter endpoints",
            "Send {{7*7}} to detect template injection",
            "Submit shell metacharacters (;, |, &&) in OS-calling inputs",
            "Check error messages for SQL syntax hints",
        ],
        prevention=[
            "Use parameterized queries / prepared statements (ALL queries)",
            "ORM with no raw query construction from user input",
            "Whitelist input validation; reject unexpected characters",
            "Run DB with least privilege (no DROP/CREATE from app user)",
            "Sandboxed template engines with no arbitrary code execution",
        ],
        references=["CWE-74", "CWE-89", "CWE-78", "https://owasp.org/Top10/A03_2021-Injection/"],
        test_payloads=[
            "' OR '1'='1",
            "1; DROP TABLE users;--",
            "{{7*7}}",
            "${7*7}",
            "| id",
            "; cat /etc/passwd",
        ],
    ),
    OWASPEntry(
        id="A04:2021",
        category="Insecure Design",
        description=(
            "Risks related to design and architectural flaws. Missing or ineffective control "
            "design, not just implementation gaps. Requires threat modeling and secure design patterns."
        ),
        common_weaknesses=[
            "No rate limiting on sensitive operations (forgot password, OTP)",
            "Business logic flaws (negative prices, infinite coupon use)",
            "Missing multi-factor authentication for sensitive functions",
            "No account lockout after repeated failed logins",
            "Insecure password reset flows",
        ],
        attack_vectors=[
            "Brute force OTP due to no rate limit",
            "Apply same discount coupon unlimited times",
            "Enumerate user accounts via forgot-password timing difference",
        ],
        detection_methods=[
            "Test rate limits: send 100+ OTP attempts, check for lockout",
            "Apply coupon twice, check if double-discounted",
            "Compare timing diff between valid/invalid account in reset flow",
            "Attempt known credential stuffing without account lockout",
        ],
        prevention=[
            "Threat model during design phase",
            "Rate limit all authentication and sensitive operations",
            "Use anti-automation controls (CAPTCHA, token challenges)",
            "Consistent responses for valid/invalid accounts",
        ],
        references=["https://owasp.org/Top10/A04_2021-Insecure_Design/"],
        test_payloads=[],
    ),
    OWASPEntry(
        id="A05:2021",
        category="Security Misconfiguration",
        description=(
            "Missing security hardening, incorrect permissions, unnecessary features enabled, "
            "default credentials, verbose error messages revealing internal details."
        ),
        common_weaknesses=[
            "Default admin credentials (admin/admin, admin/password)",
            "Verbose stack traces in production error responses",
            "Directory listing enabled on web server",
            "Unnecessary HTTP methods enabled (TRACE, DELETE)",
            "Missing security headers (CSP, X-Frame-Options, HSTS)",
            "Open cloud storage buckets (S3, GCS)",
        ],
        attack_vectors=[
            "Login with default credentials admin/admin",
            "Trigger error to expose stack trace with internal paths/versions",
            "Access /backup or /.git to find sensitive files",
            "SSRF via TRACE method reflection",
        ],
        detection_methods=[
            "Run nikto or testssl.sh for misconfig scanning",
            "Check response headers for missing security headers",
            "Try default credentials on admin panels",
            "Probe /.git, /.env, /backup/, /admin/",
            "Check CORS headers for overly permissive origins",
        ],
        prevention=[
            "Automated security configuration review in CI/CD",
            "Disable all unused features, ports, services",
            "Remove default credentials immediately",
            "Implement security headers (CSP, HSTS, X-Frame-Options)",
            "Different environments have different configurations",
        ],
        references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
        test_payloads=[
            "GET /.env HTTP/1.1",
            "GET /.git/config HTTP/1.1",
            "TRACE / HTTP/1.1",
        ],
    ),
    OWASPEntry(
        id="A06:2021",
        category="Vulnerable and Outdated Components",
        description=(
            "Using components with known vulnerabilities including outdated libraries, "
            "frameworks, or platforms that may be exploitable."
        ),
        common_weaknesses=[
            "Outdated npm/pip packages with published CVEs",
            "Legacy frameworks with unpatched known exploits",
            "Unused but loaded dependencies with vulnerabilities",
        ],
        attack_vectors=[
            "Log4Shell (CVE-2021-44228) via JNDI injection in headers",
            "Apache Struts RCE via content-type header",
            "Known CVE exploitation in identified version-specific component",
        ],
        detection_methods=[
            "Check version strings in response headers (Server:, X-Powered-By:)",
            "Run `npm audit` / `pip-audit` on project dependencies",
            "Search NVD or GHSA for CVEs in identified versions",
            "WhatWeb / Wappalyzer fingerprinting of tech stack",
        ],
        prevention=[
            "Maintain SBOM (Software Bill of Materials)",
            "Automated dependency scanning in CI/CD (Dependabot, Snyk)",
            "Subscribe to security advisories for all dependencies",
            "Remove unused dependencies",
        ],
        references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
        test_payloads=[],
    ),
    OWASPEntry(
        id="A07:2021",
        category="Identification and Authentication Failures",
        description=(
            "Weaknesses in confirming user identity, authentication, and session management. "
            "Includes credential stuffing, weak passwords, improper session handling."
        ),
        common_weaknesses=[
            "No protection against credential stuffing",
            "Weak or default passwords permitted",
            "Plain-text or reversibly encrypted passwords",
            "Missing MFA for privileged operations",
            "Session tokens exposed in URLs",
            "Sessions not invalidated on logout",
            "Session fixation attacks",
        ],
        attack_vectors=[
            "Credential stuffing with known-breached username/password combos",
            "Retrieve session token from browser history (URL-based sessions)",
            "Fix session ID before auth, inherit privilege after victim logs in",
        ],
        detection_methods=[
            "Check if session invalidated after logout (replay old token)",
            "Check if session ID appears in URL parameters",
            "Test password policy: try 'password123'",
            "Check MFA enforcement on admin functions",
        ],
        prevention=[
            "Implement MFA",
            "Enforce strong password policy with breach password checks",
            "Use server-side session management with secure, HttpOnly, SameSite cookies",
            "Invalidate sessions on logout and after inactivity timeout",
            "Rate limit login attempts",
        ],
        references=["CWE-287", "CWE-384", "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
        test_payloads=[],
    ),
    OWASPEntry(
        id="A08:2021",
        category="Software and Data Integrity Failures",
        description=(
            "Code and infrastructure that does not protect against integrity violations. "
            "Includes insecure deserialization, CI/CD pipeline integrity, auto-update without verification."
        ),
        common_weaknesses=[
            "Insecure deserialization (pickle, Java serialization, YAML.load)",
            "Unsigned software updates",
            "JavaScript from untrusted CDNs without SRI",
            "Compromised CI/CD pipeline (dependency confusion)",
        ],
        attack_vectors=[
            "Submit malicious serialized Python pickle object to deserialization endpoint",
            "Dependency confusion attack: publish high-version internal package to PyPI",
            "Supply chain attack via compromised npm package",
        ],
        detection_methods=[
            "Check if pickled / serialized data accepted from user input",
            "Verify SRI on all external script tags",
            "Audit all third-party dependencies for malicious versions",
        ],
        prevention=[
            "Never deserialize data from untrusted sources",
            "Use JSON or XML with schema validation instead of native serialization",
            "SRI for all external resources",
            "Code signing for all CI/CD artifacts",
        ],
        references=["CWE-502", "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"],
        test_payloads=[
            "data=<base64-encoded-pickle-rce-payload>",
        ],
    ),
    OWASPEntry(
        id="A09:2021",
        category="Security Logging and Monitoring Failures",
        description=(
            "Insufficient logging and monitoring that allows attackers to operate undetected, "
            "pivot, and maintain persistent presence."
        ),
        common_weaknesses=[
            "Authentication failures not logged",
            "No alerting on high-volume failed requests",
            "Logs with sensitive data (passwords, PII)",
            "Logs only stored locally (no SIEM)",
        ],
        attack_vectors=[
            "Brute force attack goes undetected due to no logging of failed logins",
            "Log injection: attacker writes fake log entries to cover tracks",
        ],
        detection_methods=[
            "Test if failed login generates log entry",
            "Check if logs are accessible to attackers (exposed /logs endpoint)",
            "Try log injection: input with newlines and log-format tokens",
        ],
        prevention=[
            "Log all authentication events, failures, and privilege changes",
            "Centralize logs in SIEM with tamper protection",
            "Alert on suspicious patterns (brute force, after-hours access)",
            "Never log sensitive data (passwords, tokens, PII)",
        ],
        references=["https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"],
        test_payloads=[],
    ),
    OWASPEntry(
        id="A10:2021",
        category="Server-Side Request Forgery (SSRF)",
        description=(
            "Web application fetches a remote resource based on user-supplied URL without "
            "sufficient validation. Attackers can force the server to make requests to unexpected locations."
        ),
        common_weaknesses=[
            "URL parameter passed to HTTP client without allowlist validation",
            "Internal service accessible via SSRF (metadata API, internal APIs)",
            "File:// protocol supported in URL fetcher",
            "Blind SSRF via webhook or notification URL",
        ],
        attack_vectors=[
            "url=http://169.254.169.254/latest/meta-data/ (AWS metadata)",
            "url=http://localhost:6379 (Redis without auth)",
            "url=file:///etc/passwd",
            "webhook=http://internal.service/admin (blind SSRF)",
        ],
        detection_methods=[
            "Submit cloud metadata URL to all URL-accepting parameters",
            "Submit http://127.0.0.1:PORT to discover internal services",
            "Use Burp Collaborator / interactsh for blind SSRF detection",
            "Try gopher://, file://, dict:// protocol schemes",
        ],
        prevention=[
            "Allowlist of permitted hosts/IP ranges for server-side requests",
            "Block RFC-1918 (private) addresses and metadata IPs",
            "Disable unused URL schemes (file://, gopher://, dict://)",
            "Response body sanitization (don't reflect full response)",
        ],
        references=["CWE-918", "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
        test_payloads=[
            "http://169.254.169.254/latest/meta-data/",
            "http://[::]:22/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            "http://burpcollaborator.net",
        ],
    ),
]


# ── OWASP API Security Top 10 — 2023 ─────────────────────────────────────────
OWASP_API_TOP10_2023: list[OWASPEntry] = [
    OWASPEntry(
        id="API1:2023",
        category="Broken Object Level Authorization (BOLA/IDOR)",
        description=(
            "API endpoints receive object IDs without verifying the caller owns or has rights "
            "to the object. Most common API vulnerability."
        ),
        common_weaknesses=[
            "Numeric or sequential object IDs controllable by user",
            "No server-side ownership check before returning object",
            "UUID-based IDs exposed and guessable via enumeration",
        ],
        attack_vectors=[
            "GET /api/orders/1234 → change to /api/orders/1235",
            "GET /api/users/me/invoices → GET /api/users/456/invoices",
            "PUT /api/accounts/999 with modified object data",
        ],
        detection_methods=[
            "Create two accounts; access one's objects with the other's token",
            "Enumerate sequential IDs in all object-returning endpoints",
            "Look for GUIDs that are exposed and test if others' GUIDs work",
        ],
        prevention=[
            "Validate authorization for every object access at the endpoint level",
            "Use non-sequential, unpredictable IDs (UUID v4)",
            "Prefer user-context-based queries (SELECT WHERE user_id = current_user)",
        ],
        references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
        test_payloads=[
            "GET /api/resource/{other_user_id}",
            "Authorization: Bearer <user_A_token>  # while accessing user B resource",
        ],
    ),
    OWASPEntry(
        id="API2:2023",
        category="Broken Authentication",
        description=(
            "Authentication mechanisms implemented incorrectly allowing attackers to compromise "
            "authentication tokens or exploit implementation flaws to assume other users' identities."
        ),
        common_weaknesses=[
            "Weak JWT secret (HS256 with guessable secret)",
            "JWTs accepted without signature verification",
            "No brute force protection on auth endpoints",
            "Password reset link valid indefinitely",
        ],
        attack_vectors=[
            "Crack weak HS256 JWT secret via hashcat",
            "Change JWT algorithm to 'none' and strip signature",
            "Brute force API key space on /api/auth",
        ],
        detection_methods=[
            "Decode JWT and try algorithm='none' bypass",
            "Submit JWT with modified payload but same signature",
            "Test password brute force without rate limiting",
        ],
        prevention=[
            "Use RS256 (asymmetric) JWT signing for APIs",
            "Validate JWT signature server-side; reject 'alg:none'",
            "Rate limit all auth endpoints",
            "Use short-lived tokens; refresh token with rotation",
        ],
        references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
        test_payloads=[
            '{"alg":"none"}.{"sub":"admin"}.  // JWT none algorithm',
            "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0...",
        ],
    ),
    OWASPEntry(
        id="API3:2023",
        category="Broken Object Property Level Authorization (Mass Assignment)",
        description=(
            "API endpoints expose more object properties than needed. Clients can modify "
            "properties they shouldn't have access to (mass assignment / privilege escalation via body)."
        ),
        common_weaknesses=[
            "ORM auto-mapping user input to model fields",
            "Exposing isAdmin, role, credits fields in request body",
            "Return full internal object (over-exposure)",
        ],
        attack_vectors=[
            'PUT /api/user/profile with {"isAdmin": true}',
            'POST /api/order with {"price": 0.01}',
            'POST /api/register with {"credits": 9999}',
        ],
        detection_methods=[
            "Add admin/privilege fields to update requests and check if accepted",
            "Send extra fields in POST body and check for reflection",
            "Check if all response fields are also writable",
        ],
        prevention=[
            "Use explicit serializer whitelists; never blindly deserialize all fields",
            "Read-only attributes must be explicitly excluded from write operations",
            "Return only necessary fields in responses",
        ],
        references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
        test_payloads=[
            '{"role": "admin", "isActive": true}',
            '{"_id": "000", "balance": 99999}',
        ],
    ),
    OWASPEntry(
        id="API4:2023",
        category="Unrestricted Resource Consumption",
        description=(
            "API endpoints without restrictions on size/number of resources requested allow "
            "DoS attacks, performance degradation, or financial damage via excessive API calls."
        ),
        common_weaknesses=[
            "No pagination on list endpoints; return all records",
            "File upload without size limits",
            "No rate limiting on expensive computations (PDF generation, search)",
        ],
        attack_vectors=[
            "GET /api/users?page_size=999999999 to exhaust memory",
            "Upload 1GB file to processing endpoint",
            "Flood search endpoint with regex queries",
        ],
        detection_methods=[
            "Request large page sizes on paginated endpoints",
            "Submit requests with no rate limit guard (100+ in 1 second)",
            "Upload maximum file size to unguarded endpoints",
        ],
        prevention=[
            "Enforce maximum page size and pagination on all list endpoints",
            "File size and type limits on all upload endpoints",
            "Rate limiting per user/IP on all endpoints",
            "Cost-based rate limits for expensive operations",
        ],
        references=["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"],
        test_payloads=[
            "GET /api/items?limit=99999999",
            "Content-Length: 10000000000  // oversized upload",
        ],
    ),
    OWASPEntry(
        id="API5:2023",
        category="Broken Function Level Authorization (BFLA)",
        description=(
            "Complex access control policies with multi-level hierarchies allow attackers to "
            "access admin or other restricted functions by simply changing HTTP method or endpoint."
        ),
        common_weaknesses=[
            "Admin API endpoints accessible to regular users",
            "Changing HTTP method (GET→DELETE) grants access",
            "Internal APIs exposed on same port without auth",
        ],
        attack_vectors=[
            "DELETE /api/admin/users/123 with regular user token",
            "GET /api/v1/admin/stats with regular user JWT",
            "Access /internal/api/users without authentication",
        ],
        detection_methods=[
            "Probe /admin, /v2/admin, /api/admin with user-level tokens",
            "Change HTTP methods (GET→POST→PUT→DELETE) on endpoints",
            "Look for JS code referencing admin endpoint paths",
        ],
        prevention=[
            "Centralized authorization checks (middleware, not in individual controllers)",
            "Deny by default for admin functions",
            "Separate internal APIs onto internal-only network",
        ],
        references=["https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"],
        test_payloads=[
            "DELETE /api/admin/users/1  // with non-admin token",
            "GET /api/admin/export  // while authenticated as user",
        ],
    ),
    OWASPEntry(
        id="API6:2023",
        category="Unrestricted Access to Sensitive Business Flows",
        description=(
            "Business flows that, if automated, can cause harm or significant business impact "
            "if abused at scale (ticket scalping, bonus farming, inventory depletion)."
        ),
        common_weaknesses=[
            "No CAPTCHA or anti-bot on high-value purchase flows",
            "Referral credit farming via automated account creation",
            "Flash sale bot abuse without purchase limits",
        ],
        attack_vectors=[
            "Automate 1000 ticket purchases to scalp concert tickets",
            "Script account creation to farm referral bonuses",
            "API-direct checkout bypass of front-end purchase limits",
        ],
        detection_methods=[
            "Test if purchase limits enforced at API layer",
            "Check if CAPTCHA enforced on account creation API",
            "Automate transactions directly via API to bypass UI limits",
        ],
        prevention=[
            "Enforce business limits at API/backend layer (not just frontend)",
            "Device fingerprinting and behavioral anomaly detection",
            "One-per-account limits with identity verification",
        ],
        references=["https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"],
        test_payloads=[],
    ),
    OWASPEntry(
        id="API7:2023",
        category="Server Side Request Forgery (SSRF)",
        description="Same as Web SSRF — API accepts user-supplied URL without validation.",
        common_weaknesses=OWASP_TOP10_2021[9].common_weaknesses,
        attack_vectors=OWASP_TOP10_2021[9].attack_vectors,
        detection_methods=OWASP_TOP10_2021[9].detection_methods,
        prevention=OWASP_TOP10_2021[9].prevention,
        references=["https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/"],
        test_payloads=OWASP_TOP10_2021[9].test_payloads,
    ),
    OWASPEntry(
        id="API8:2023",
        category="Security Misconfiguration",
        description="Same insecure defaults, unnecessary HTTP methods, open CORS, verbose errors — API context.",
        common_weaknesses=OWASP_TOP10_2021[4].common_weaknesses,
        attack_vectors=OWASP_TOP10_2021[4].attack_vectors,
        detection_methods=OWASP_TOP10_2021[4].detection_methods,
        prevention=OWASP_TOP10_2021[4].prevention,
        references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
        test_payloads=OWASP_TOP10_2021[4].test_payloads,
    ),
    OWASPEntry(
        id="API9:2023",
        category="Improper Inventory Management",
        description=(
            "Outdated API versions, undocumented endpoints, and shadow APIs expose attack "
            "surfaces that may have weaker security than the current production API."
        ),
        common_weaknesses=[
            "Old API versions (/v1/) left running with fewer controls",
            "Undocumented internal beta endpoints",
            "Different security posture on API versions",
        ],
        attack_vectors=[
            "Use /api/v1/ endpoints that lack /api/v3/ rate limiting or auth",
            "Access /api/internal/ or /api/beta/ endpoints skipping security controls",
        ],
        detection_methods=[
            "Fuzz /api/v1/, /api/v2/, /api/v3/ for all known endpoints",
            "Check if old API versions have same security controls",
            "Look for changelog indicating removed features still accessible on old endpoints",
        ],
        prevention=[
            "Sunset old API versions completely; don't just hide them",
            "Maintain API inventory; document all versions and their status",
            "Apply uniform security controls across all API versions",
        ],
        references=["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
        test_payloads=[],
    ),
    OWASPEntry(
        id="API10:2023",
        category="Unsafe Consumption of APIs",
        description=(
            "Developers trust third-party APIs without proper validation, allowing compromised "
            "third-party APIs to cause vulnerabilities in the consuming application."
        ),
        common_weaknesses=[
            "Third-party data used in SQL queries without sanitization",
            "Third-party API response reflected to client without validation",
            "Blind trust in HTTPS from third parties",
        ],
        attack_vectors=[
            "Compromise third-party API → inject SQL into responses consumed by target",
            "Third-party returns malicious redirect URL → SSRF via trusted source",
        ],
        detection_methods=[
            "Identify all third-party API integrations",
            "Check if third-party responses are sanitized before use",
        ],
        prevention=[
            "Treat third-party API data as untrusted user input",
            "Validate and sanitize data from all external APIs",
            "Use allowlist for expected response shapes",
        ],
        references=["https://owasp.org/API-Security/editions/2023/en/0xa10-unsafe-consumption-of-apis/"],
        test_payloads=[],
    ),
]


# ── Lookup helpers ────────────────────────────────────────────────────────────

def get_owasp_entry(owasp_id: str) -> OWASPEntry | None:
    """Look up an entry by OWASP ID e.g. 'A03:2021' or 'API1:2023'."""
    all_entries = OWASP_TOP10_2021 + OWASP_API_TOP10_2023
    return next((e for e in all_entries if e.id == owasp_id), None)


def search_owasp(term: str) -> list[OWASPEntry]:
    """Find OWASP entries matching keyword in category name or description."""
    term_lower = term.lower()
    all_entries = OWASP_TOP10_2021 + OWASP_API_TOP10_2023
    return [e for e in all_entries
            if term_lower in e.category.lower() or term_lower in e.description.lower()]


def build_owasp_analysis_prompt(include_api: bool = True) -> str:
    """Generate an OWASP-structured analysis prompt block."""
    lines = [
        "\n## OWASP VULNERABILITY ANALYSIS — MANDATORY COVERAGE\n",
        "Analyze the target against every category below. For each: state PRESENT / NOT PRESENT / UNKNOWN.",
        "\n### OWASP Top 10 (2021)\n",
    ]
    for entry in OWASP_TOP10_2021:
        lines.append(f"- **{entry.id} — {entry.category}**")
        lines.append(f"  Attack vectors: {'; '.join(entry.attack_vectors[:2])}\n")

    if include_api:
        lines.append("\n### OWASP API Security Top 10 (2023)\n")
        seen = set()
        for entry in OWASP_API_TOP10_2023:
            if entry.category not in seen:
                seen.add(entry.category)
                lines.append(f"- **{entry.id} — {entry.category}**")

    return "\n".join(lines)


def get_payloads_by_category(category_keyword: str) -> list[str]:
    """Get test payloads for a given OWASP category keyword."""
    all_entries = OWASP_TOP10_2021 + OWASP_API_TOP10_2023
    payloads = []
    kw = category_keyword.lower()
    for entry in all_entries:
        if kw in entry.category.lower():
            payloads.extend(entry.test_payloads)
    return payloads


def owasp_summary() -> str:
    """One-line summaries of all OWASP entries."""
    lines = ["## OWASP Coverage in SPARTAN\n"]
    lines.append("### OWASP Top 10 (2021)")
    for e in OWASP_TOP10_2021:
        lines.append(f"  {e.id:<12} {e.category}")
    lines.append("\n### OWASP API Security Top 10 (2023)")
    for e in OWASP_API_TOP10_2023:
        lines.append(f"  {e.id:<12} {e.category}")
    return "\n".join(lines)
