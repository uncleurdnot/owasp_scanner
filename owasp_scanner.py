#!/usr/bin/env python3
"""
OWASP Top 10 (2021) lightweight scanner
========================================

Checks a handful of low-risk, non-destructive indicators for each OWASP
Top 10 category. This is a *triage* tool, not a substitute for a real
DAST scanner (OWASP ZAP, Burp Suite) or a manual pentest.

IMPORTANT / LEGAL:
  - Only run this against systems you own or have explicit written
    authorization to test. Unauthorized scanning of third-party systems
    is illegal in most jurisdictions (e.g. US CFAA, UK Computer Misuse Act).
  - This script sends normal HTTP requests and a small number of
    reflected-payload probes. It does not attempt to exploit anything,
    exfiltrate data, brute force credentials, or perform DoS.
  - Rate limiting is built in but keep an eye on your target's logs/WAF.

Usage:
    python3 owasp_scanner.py https://example.com
    python3 owasp_scanner.py https://example.com --pages /login /search --delay 0.5

Requires:
    pip install requests --break-system-packages
"""

import argparse
import re
import socket
import ssl
import sys
import time
import urllib.parse
from datetime import datetime, timezone

import requests
from requests.exceptions import RequestException

requests.packages.urllib3.disable_warnings()  # we deliberately check cert issues ourselves

DEFAULT_TIMEOUT = 8
USER_AGENT = "OWASP-Lite-Scanner/1.0 (+authorized-self-test)"

RESULTS = []  # list of dicts: {category, severity, finding, detail}


def log(category, severity, finding, detail=""):
    RESULTS.append(
        {"category": category, "severity": severity, "finding": finding, "detail": detail}
    )
    tag = {"INFO": "\033[36m", "LOW": "\033[33m", "MED": "\033[93m", "HIGH": "\033[91m"}.get(
        severity, ""
    )
    reset = "\033[0m"
    print(f"{tag}[{severity:>4}]{reset} {category}: {finding}" + (f" — {detail}" if detail else ""))


def get(session, url, **kw):
    kw.setdefault("timeout", DEFAULT_TIMEOUT)
    kw.setdefault("verify", True)
    kw.setdefault("allow_redirects", True)
    return session.get(url, **kw)


# ---------------------------------------------------------------------------
# A03 / A05 - Security headers & misconfiguration
# ---------------------------------------------------------------------------
def check_security_headers(session, base_url):
    try:
        r = get(session, base_url)
    except RequestException as e:
        log("A05 Misconfiguration", "HIGH", "Could not connect", str(e))
        return

    headers = {k.lower(): v for k, v in r.headers.items()}

    expected = {
        "strict-transport-security": ("A05", "MED", "Missing HSTS header — allows protocol downgrade attacks"),
        "x-content-type-options": ("A05", "LOW", "Missing X-Content-Type-Options — enables MIME sniffing"),
        "x-frame-options": ("A05", "MED", "Missing X-Frame-Options / frame-ancestors — clickjacking risk"),
        "content-security-policy": ("A05", "MED", "Missing CSP — reduces defense-in-depth against XSS"),
        "referrer-policy": ("A05", "LOW", "Missing Referrer-Policy — may leak URLs to third parties"),
    }
    for h, (cat, sev, msg) in expected.items():
        if h not in headers:
            log(cat, sev, msg)
        else:
            log(cat, "INFO", f"{h} present", headers[h][:100])

    # Frame-ancestors sometimes in CSP instead of X-Frame-Options
    if "content-security-policy" in headers and "frame-ancestors" in headers["content-security-policy"]:
        log("A05", "INFO", "frame-ancestors set via CSP (covers clickjacking)")

    # Info disclosure via headers
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-runtime"):
        if h in headers:
            log("A06 Vulnerable Components", "LOW", f"'{h}' header discloses stack info", headers[h])

    # Cookies
    for cookie in r.cookies:
        flags = []
        if not cookie.secure:
            flags.append("missing Secure")
        raw = str(cookie)
        if "httponly" not in raw.lower():
            flags.append("missing HttpOnly")
        if "samesite" not in raw.lower():
            flags.append("missing SameSite")
        if flags:
            log("A05 Misconfiguration", "MED", f"Cookie '{cookie.name}' issues", ", ".join(flags))


# ---------------------------------------------------------------------------
# A02 - Cryptographic failures (TLS)
# ---------------------------------------------------------------------------
def check_tls(base_url):
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme != "https":
        log("A02 Cryptographic Failures", "HIGH", "Site not served over HTTPS")
        return

    host = parsed.hostname
    port = parsed.port or 443
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days_left = (not_after - datetime.now(timezone.utc)).days
                log("A02 Cryptographic Failures", "INFO", f"TLS protocol negotiated: {proto}")
                if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    log("A02 Cryptographic Failures", "HIGH", f"Obsolete TLS version in use: {proto}")
                if days_left < 14:
                    log("A02 Cryptographic Failures", "MED", f"Certificate expires in {days_left} days")
    except ssl.SSLCertVerificationError as e:
        log("A02 Cryptographic Failures", "HIGH", "Certificate validation failed", str(e))
    except Exception as e:
        log("A02 Cryptographic Failures", "MED", "Could not complete TLS handshake check", str(e))


# ---------------------------------------------------------------------------
# A01 - Broken access control (common exposed paths)
# ---------------------------------------------------------------------------
COMMON_SENSITIVE_PATHS = [
    ".env", ".git/config", ".git/HEAD", "config.php.bak", "web.config",
    "wp-config.php.bak", ".DS_Store", "backup.zip", "backup.sql",
    ".aws/credentials", "id_rsa", "server-status", "actuator/env",
    "actuator/health", ".htpasswd", "phpinfo.php", "debug", "swagger.json",
    "swagger-ui.html", ".well-known/security.txt",
]


def check_exposed_paths(session, base_url):
    for path in COMMON_SENSITIVE_PATHS:
        url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path)
        try:
            r = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        except RequestException:
            continue
        if r.status_code == 200 and len(r.content) > 0:
            sev = "HIGH" if any(k in path for k in (".env", "credentials", "id_rsa", ".git", "backup")) else "LOW"
            log("A01 Broken Access Control", sev, f"Potentially exposed path: /{path}", f"HTTP {r.status_code}")
        time.sleep(0.15)


# ---------------------------------------------------------------------------
# A03 - Injection (reflected XSS / SQLi error-based probes)
# ---------------------------------------------------------------------------
XSS_PROBE = "<owaspscan>\"'><svg onload=alert(1)>"
SQLI_PROBES = ["'", "\" OR \"1\"=\"1", "1' OR '1'='1'--", "' UNION SELECT NULL--"]
SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "ORA-01756", "SQLSTATE", "PostgreSQL.*ERROR",
    "unclosed quotation mark", "quoted string not properly terminated",
    "sqlite3.OperationalError", "pg_query()", "Warning: mysql_",
]


def _reflected_outside_script(html, payload):
    """
    Return True only if the raw, unescaped payload appears in the HTML
    OUTSIDE of <script>...</script> blocks (and not JSON/unicode-escaped).
    Frameworks like Next.js/Nuxt embed the current URL in a JSON blob
    inside a <script> tag for hydration -- that's inert data, not a real
    reflected-XSS sink, and would otherwise cause a false positive.
    """
    # Strip all script blocks first
    stripped = re.sub(r"<script\b[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)

    # Must contain the literal, unescaped payload (real HTML injection),
    # not a \u003c-style JSON-escaped or %-encoded version.
    return payload in stripped


def check_reflected_xss_and_sqli(session, base_url, extra_pages):
    pages = ["/", "/search", "/?q=test"] + list(extra_pages)
    for page in pages:
        url = urllib.parse.urljoin(base_url, page)
        # crude param injection: append or extend query string
        sep = "&" if "?" in url else "?"

        # XSS probe
        try:
            r = session.get(f"{url}{sep}q={urllib.parse.quote(XSS_PROBE)}", timeout=DEFAULT_TIMEOUT)
            if _reflected_outside_script(r.text, XSS_PROBE):
                log("A03 Injection (XSS)", "HIGH", f"Possible reflected XSS at {page}", "Payload echoed unescaped outside <script> context")
        except RequestException:
            pass
        time.sleep(0.15)

        # SQLi probes
        for payload in SQLI_PROBES:
            try:
                r = session.get(f"{url}{sep}id={urllib.parse.quote(payload)}", timeout=DEFAULT_TIMEOUT)
            except RequestException:
                continue
            body_lower = r.text.lower()
            for sig in SQL_ERROR_SIGNATURES:
                if re.search(sig.lower(), body_lower):
                    log(
                        "A03 Injection (SQLi)",
                        "HIGH",
                        f"Possible SQL error disclosure at {page}",
                        f"Payload: {payload} matched signature: {sig}",
                    )
                    break
            time.sleep(0.15)


# ---------------------------------------------------------------------------
# A07 - Identification & Authentication failures (basic checks only)
# ---------------------------------------------------------------------------
def check_auth_hints(session, base_url):
    login_paths = ["/login", "/signin", "/wp-login.php", "/admin"]
    for path in login_paths:
        url = urllib.parse.urljoin(base_url, path)
        try:
            r = session.get(url, timeout=DEFAULT_TIMEOUT)
        except RequestException:
            continue
        if r.status_code == 200:
            log("A07 Auth Failures", "INFO", f"Login endpoint found: {path}", "Manually verify: lockout policy, MFA, rate limiting")
            if "autocomplete" not in r.text.lower():
                log("A07 Auth Failures", "LOW", f"{path}: no autocomplete attribute detected on form (manual check advised)")
        time.sleep(0.15)


# ---------------------------------------------------------------------------
# A06 - Vulnerable & outdated components (very rough JS/lib version sniff)
# ---------------------------------------------------------------------------
LIB_VERSION_RE = re.compile(
    r"(jquery|bootstrap|angular|vue|react|lodash)[.\-]?(?:min\.)?js.{0,15}?(\d+\.\d+\.\d+)",
    re.IGNORECASE,
)


def check_outdated_js_libs(session, base_url):
    try:
        r = session.get(base_url, timeout=DEFAULT_TIMEOUT)
    except RequestException:
        return
    matches = LIB_VERSION_RE.findall(r.text)
    seen = set()
    for lib, version in matches:
        key = (lib.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        log(
            "A06 Vulnerable Components",
            "INFO",
            f"Detected {lib} v{version} in page source",
            "Cross-check against known CVEs for this version",
        )


# ---------------------------------------------------------------------------
# A09 - Security logging & monitoring (can't test remotely — informational)
# ---------------------------------------------------------------------------
def note_logging_reminder():
    log(
        "A09 Logging & Monitoring",
        "INFO",
        "Not remotely testable",
        "Manually verify: auth failures logged, alerts on anomalies, log retention/integrity",
    )


def note_ssrf_deserialization_reminder():
    log(
        "A08/A10 Insecure Deserialization & SSRF",
        "INFO",
        "Not covered by automated probes",
        "Manually review: any endpoint accepting URLs (SSRF), any endpoint deserializing objects/pickles/YAML",
    )


# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Lightweight OWASP Top 10 triage scanner (authorized testing only)")
    parser.add_argument("url", help="Base URL of the site you own, e.g. https://example.com")
    parser.add_argument("--pages", nargs="*", default=[], help="Extra paths to probe for injection, e.g. /search /contact")
    parser.add_argument("--delay", type=float, default=0.15, help="Delay between requests (seconds)")
    args = parser.parse_args()

    base_url = args.url if args.url.startswith("http") else f"https://{args.url}"

    print(f"\n=== OWASP Top 10 lightweight scan: {base_url} ===")
    print("Authorized self-test only. Do not run against systems you don't own.\n")

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    global DEFAULT_TIMEOUT
    check_security_headers(session, base_url)
    check_tls(base_url)
    check_exposed_paths(session, base_url)
    check_reflected_xss_and_sqli(session, base_url, args.pages)
    check_auth_hints(session, base_url)
    check_outdated_js_libs(session, base_url)
    note_logging_reminder()
    note_ssrf_deserialization_reminder()

    # Summary
    print("\n=== Summary ===")
    counts = {}
    for r in RESULTS:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    for sev in ("HIGH", "MED", "LOW", "INFO"):
        if sev in counts:
            print(f"{sev}: {counts[sev]}")

    high = [r for r in RESULTS if r["severity"] == "HIGH"]
    if high:
        print("\nTop priority findings:")
        for r in high:
            print(f" - [{r['category']}] {r['finding']} — {r['detail']}")


if __name__ == "__main__":
    main()
