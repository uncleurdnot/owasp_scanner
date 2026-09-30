# owasp_scanner

Vibe-coded lightweight triage scanner that checks a website you own against indicators from the [OWASP Top 10 (2021)](https://owasp.org/projects/top-ten).

It is a quick first pass, **not** a replacement for a real DAST scanner (OWASP ZAP, Burp Suite) or a manual pentest.

## Legal / authorization

Only run this against systems you own or have explicit written authorization to test. Unauthorized scanning is illegal in most jurisdictions (e.g. US CFAA, UK Computer Misuse Act).

The scanner sends normal HTTP GET requests plus a small number of reflected-payload probes. It does not exploit anything, exfiltrate data, brute force credentials, or attempt DoS.

## Setup

Requires Python 3 and `requests`.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests
```

## Usage

```bash
python3 owasp_scanner.py <url> [--pages PATH ...] [--delay SECONDS]
```

| Argument | Description |
|----------|-------------|
| `url` | Base URL of the site to scan. `https://` is prepended if no scheme is given. |
| `--pages` | Extra paths to probe for XSS/SQLi, e.g. `/search /contact`. |
| `--delay` | Delay between requests in seconds (default `0.15`). |

Examples:

```bash
python3 owasp_scanner.py https://example.com
python3 owasp_scanner.py example.com --pages /login /search --delay 0.5
```

## What it checks

| OWASP category | Check |
|----------------|-------|
| A01 Broken Access Control | Probes ~20 commonly exposed paths (`.env`, `.git/config`, backups, `actuator/env`, `phpinfo.php`, ...) |
| A02 Cryptographic Failures | HTTPS in use, negotiated TLS version, certificate validity and expiry (<14 days) |
| A03 Injection | Reflected XSS probe (ignores payloads echoed only inside `<script>` blocks) and error-based SQLi probes on `/`, `/search`, and `--pages` |
| A05 Security Misconfiguration | Missing HSTS, X-Content-Type-Options, X-Frame-Options/CSP `frame-ancestors`, CSP, Referrer-Policy; cookie `Secure`/`HttpOnly`/`SameSite` flags |
| A06 Vulnerable Components | Server/stack version headers; rough sniff of jQuery/Bootstrap/Angular/Vue/React/Lodash versions in page source |
| A07 Auth Failures | Detects login endpoints (`/login`, `/signin`, `/wp-login.php`, `/admin`) for manual follow-up |
| A09 Logging & Monitoring | Reminder only (not remotely testable) |
| A08 / A10 | Reminder only (deserialization, SSRF need manual review) |

A04 (Insecure Design) is not covered.

## Output

Findings print as `[SEVERITY] category: finding — detail`, colored by severity (`INFO`, `LOW`, `MED`, `HIGH`). The run ends with a count per severity and a list of the `HIGH` findings.

## Limitations

- Results are heuristics; expect false positives and false negatives. Verify manually.
- Some probes (for example, login endpoint and path checks) treat any HTTP 200 as a hit, so sites that return 200 for unknown routes (single-page apps) will produce noise.
- Findings are not written to a file; redirect stdout if you want to keep them.
- `--delay` is parsed but not currently applied; requests use a fixed 0.15s sleep.
