"""
Web Application Security Scan — AI‑IDS (OWASP ZAP Baseline methodology)

Performs automated security checks against the running Streamlit app:
  - Security headers audit
  - Information disclosure checks
  - Cookie security analysis
  - Form/endpoint discovery
  - Common vulnerability patterns

Generates an HTML report (security_report/zap_report.html) and JSON output.

Usage:
    python scripts/security_scan.py
"""
import sys, os, json, time, html as html_mod
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
os.chdir(str(_PROJECT_ROOT))
REPORT_DIR = _PROJECT_ROOT / "security_report"
REPORT_DIR.mkdir(exist_ok=True)

sys.stdout = open(1, 'w', encoding='utf-8', closefd=False)

import requests
from bs4 import BeautifulSoup

BASE_URL = "http://localhost:8501"
TIMEOUT = 10

findings = []  # list of dicts


def add_finding(alert: str, risk: str, url: str, description: str,
                solution: str, extra: str = ""):
    findings.append({
        "alert": alert,
        "risk": risk,
        "url": url,
        "description": description,
        "solution": solution,
        "extra": extra,
    })
    risk_icon = {"High": "!", "Medium": "~", "Low": "-", "Informational": "i"}
    print(f"  [{risk_icon.get(risk, '?')}] {risk:14s} {alert[:60]}")


def scan_url(url: str, source: str = "discovered"):
    """Scan a single URL for security issues."""
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        add_finding("Connection Error", "Medium", url,
                    f"Failed to connect: {e}", "Ensure the application is running and reachable.")
        return None
    headers = resp.headers
    ct = headers.get("Content-Type", "")

    # ── 1. Missing Security Headers ──
    security_headers = {
        "X-Content-Type-Options": ("nosniff", "Low",
            "Prevents MIME-type sniffing. Without it, older browsers may interpret files as executable scripts.",
            "Add 'X-Content-Type-Options: nosniff' to response headers."),
        "X-Frame-Options": ("DENY", "Medium",
            "Missing anti-clickjacking header. The page could be embedded in an iframe on malicious sites.",
            "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'."),
        "Content-Security-Policy": (None, "Medium",
            "CSP not set, increasing risk of XSS and data injection attacks.",
            "Define a Content-Security-Policy header appropriate to your application."),
        "Strict-Transport-Security": (None, "Low",
            "HSTS not set. While on localhost this is low-risk, production deployment requires it.",
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."),
        "Referrer-Policy": (None, "Low",
            "Referrer-Policy not set, potentially leaking URL parameters in the Referer header.",
            "Add 'Referrer-Policy: strict-origin-when-cross-origin'."),
        "Permissions-Policy": (None, "Low",
            "Permissions-Policy not set, allowing all browser features by default.",
            "Add a Permissions-Policy header restricting unnecessary features."),
    }

    for hdr, (expected, risk, desc, sol) in security_headers.items():
        val = headers.get(hdr)
        if val is None:
            add_finding(f"Missing {hdr}", risk, url, desc, sol)
        elif expected and val.strip().lower() != expected.lower():
            add_finding(f"Weak {hdr}: {val}", "Low", url,
                        f"Expected '{expected}', got '{val}'.", sol)

    # ── 2. Server Information Disclosure ──
    server = headers.get("Server")
    if server:
        add_finding("Server Version Disclosure", "Medium", url,
                    f"Server header reveals: '{server}'. Attackers can target known vulnerabilities.",
                    "Remove or obfuscate the Server header.")
    x_powered = headers.get("X-Powered-By")
    if x_powered:
        add_finding("X-Powered-By Disclosure", "Low", url,
                    f"Reveals: '{x_powered}'. Provides technology fingerprinting information.",
                    "Remove the X-Powered-By header.")

    # ── 3. Cookie Security ──
    set_cookie = headers.get("Set-Cookie", "")
    if set_cookie:
        if "HttpOnly" not in set_cookie:
            add_finding("Cookie Missing HttpOnly Flag", "Medium", url,
                        "Cookies accessible via JavaScript, increasing XSS impact.",
                        "Add HttpOnly flag to all cookies.")
        if "Secure" not in set_cookie and url.startswith("https"):
            add_finding("Cookie Missing Secure Flag", "High", url,
                        "Cookie sent over unencrypted connections.",
                        "Add Secure flag to all cookies.")
        if "SameSite" not in set_cookie:
            add_finding("Cookie Missing SameSite Attribute", "Low", url,
                        "CSRF protection may be weakened without SameSite.",
                        "Add SameSite=Lax or Strict to cookies.")

    # ── 4. Content Type Issues ──
    if "text/html" in ct:
        if "X-Content-Type-Options" not in headers:
            pass  # already reported above

    # ── 5. Form Analysis ──
    soup = BeautifulSoup(resp.text, "html.parser")
    forms = soup.find_all("form")
    for form in forms:
        action = form.get("action", url)
        method = form.get("method", "get").upper()
        inputs = form.find_all("input")
        if method == "GET" and any(inp.get("type") == "password" for inp in inputs):
            add_finding("Password Field in GET Form", "High",
                        urljoin(url, action),
                        "Password transmitted in URL query string — visible in logs and history.",
                        "Use POST method for forms with sensitive data.")

    # ── 6. Directory/Path Discovery (basic) ──
    common_paths = ["/admin", "/config", "/.env", "/api", "/robots.txt", "/sitemap.xml"]
    for path in common_paths:
        try:
            test_url = urljoin(url, path)
            r2 = requests.get(test_url, timeout=5, allow_redirects=False)
            if r2.status_code == 200 and r2.status_code != 404:
                add_finding(f"Accessible Path: {path}", "Low", test_url,
                            f"Returns {r2.status_code}. May expose sensitive endpoints.",
                            "Restrict access or return 404 for non-public paths.")
        except requests.RequestException:
            pass

    return resp


def main():
    print(f"\n{'='*60}")
    print("AI-IDS Web Security Scan (OWASP ZAP Baseline Methodology)")
    print(f"{'='*60}")
    print(f"Target: {BASE_URL}")
    print(f"Started: {datetime.now().isoformat()}")
    print()

    # ── Scrape all discoverable pages ──
    try:
        home = requests.get(BASE_URL, timeout=TIMEOUT)
        print(f"Home page: {home.status_code}")
    except requests.RequestException as e:
        print(f"ERROR: Cannot reach {BASE_URL}: {e}")
        sys.exit(1)

    soup = BeautifulSoup(home.text, "html.parser")
    discovered_urls = {BASE_URL}

    # Find all links
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith("/") or href.startswith(BASE_URL):
            full = urljoin(BASE_URL, href)
            if full.startswith(BASE_URL):
                discovered_urls.add(full)

    # Also try known application pages
    for path in ["/", "/detection", "/live_capture", "/alerts",
                 "/dashboard", "/models", "/logs", "/settings",
                 "/whitelist", "/blacklist", "/monitoring"]:
        discovered_urls.add(urljoin(BASE_URL, path))

    print(f"Discovered {len(discovered_urls)} URLs to scan\n")

    # ── Scan each URL ──
    for url in sorted(discovered_urls):
        print(f"Scanning: {url}")
        scan_url(url)

    # ── Summary Statistics ──
    risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        risk_counts[f["risk"]] = risk_counts.get(f["risk"], 0) + 1

    high_risk = [f for f in findings if f["risk"] == "High"]

    print(f"\n{'='*60}")
    print("SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"Total alerts: {len(findings)}")
    print(f"  High:          {risk_counts.get('High', 0)}")
    print(f"  Medium:        {risk_counts.get('Medium', 0)}")
    print(f"  Low:           {risk_counts.get('Low', 0)}")
    print(f"  Informational: {risk_counts.get('Informational', 0)}")

    if high_risk:
        print(f"\nHIGH RISK FINDINGS:")
        for h in high_risk:
            print(f"  ! {h['alert']}")
            print(f"    URL: {h['url']}")
            print(f"    Description: {h['description']}")

    # ── Generate HTML Report ──
    risk_colors = {"High": "#e74c3c", "Medium": "#f39c12",
                   "Low": "#3498db", "Informational": "#95a5a6"}
    risk_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}

    sorted_findings = sorted(findings, key=lambda x: risk_order.get(x["risk"], 99))

    rows_html = ""
    for f in sorted_findings:
        color = risk_colors.get(f["risk"], "#999")
        rows_html += f"""
        <tr>
            <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:3px;font-weight:bold">{f['risk']}</span></td>
            <td>{html_mod.escape(f['alert'])}</td>
            <td style="word-break:break-all">{html_mod.escape(f['url'])}</td>
            <td>{html_mod.escape(f['description'])}</td>
            <td>{html_mod.escape(f['solution'])}</td>
        </tr>"""

    html_report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ZAP Baseline Security Report — AI-IDS</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f6fa; color: #2c3e50; }}
h1 {{ color: #1f3a5f; }}
.header {{ background: #1f3a5f; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
.header h1 {{ margin:0; color:white; }}
.header p {{ margin:5px 0 0; opacity:0.8; }}
.summary {{ display:flex; gap:15px; margin:20px 0; }}
.summary-card {{ background:white; padding:15px 20px; border-radius:8px; box-shadow:0 2px 4px rgba(0,0,0,0.1); flex:1; text-align:center; }}
.summary-card .count {{ font-size:28px; font-weight:bold; }}
.summary-card .label {{ font-size:12px; text-transform:uppercase; color:#7f8c8d; }}
table {{ width:100%; border-collapse:collapse; background:white; border-radius:8px; overflow:hidden; box-shadow:0 2px 4px rgba(0,0,0,0.1); }}
th {{ background:#1f3a5f; color:white; padding:12px; text-align:left; font-size:13px; }}
td {{ padding:10px 12px; border-bottom:1px solid #ecf0f1; font-size:13px; }}
tr:hover {{ background:#f8f9fa; }}
.footer {{ margin-top:20px; font-size:12px; color:#95a5a6; text-align:center; }}
</style>
</head>
<body>
<div class="header">
    <h1>OWASP ZAP Baseline Security Report</h1>
    <p>Target: {html_mod.escape(BASE_URL)} | Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
</div>
<div class="summary">
    <div class="summary-card"><div class="count" style="color:{risk_colors['High']}">{risk_counts.get('High',0)}</div><div class="label">High</div></div>
    <div class="summary-card"><div class="count" style="color:{risk_colors['Medium']}">{risk_counts.get('Medium',0)}</div><div class="label">Medium</div></div>
    <div class="summary-card"><div class="count" style="color:{risk_colors['Low']}">{risk_counts.get('Low',0)}</div><div class="label">Low</div></div>
    <div class="summary-card"><div class="count">{len(findings)}</div><div class="label">Total Alerts</div></div>
</div>
<table>
<thead><tr><th>Risk</th><th>Alert</th><th>URL</th><th>Description</th><th>Solution</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>
<div class="footer">
    <p>Generated by OWASP ZAP Baseline methodology | AI-IDS Security Scan | {
        'Some alerts may be expected for local development environments.' if risk_counts.get('High',0) == 0 else 'Review and remediate High alerts before production deployment.'
    }</p>
</div>
</body>
</html>"""

    report_path = REPORT_DIR / "zap_report.html"
    report_path.write_text(html_report, encoding="utf-8")
    print(f"\nHTML report: {report_path}")

    # JSON output
    json_path = REPORT_DIR / "zap_report.json"
    json_data = {
        "scan_date": datetime.now().isoformat(),
        "target": BASE_URL,
        "risk_counts": risk_counts,
        "total_alerts": len(findings),
        "alerts": sorted_findings,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    print(f"JSON report: {json_path}")

    return risk_counts, high_risk


if __name__ == "__main__":
    main()
