import requests
import ssl, socket
from urllib.parse import urlparse, urljoin
from datetime import datetime

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
]

COMMON_ENDPOINTS = [
    "robots.txt", ".git/", ".env", "admin/", "wp-login.php",
    "package.json", "composer.lock", "server-status"
]

UNSAFE_CSP = ["'unsafe-inline'", "'unsafe-eval'", "*", "data:", "blob:"]

def norm_url(url):
    p = urlparse(url)
    return url if p.scheme else "https://" + url

def fetch(url):
    try:
        return requests.get(url, timeout=10, verify=True)
    except:
        return None

def check_headers(resp):
    hdrs = {k.lower(): v for k,v in resp.headers.items()}
    out = {}
    for h in SECURITY_HEADERS:
        out[h] = hdrs.get(h, None)
    return out

def analyze_csp(csp):
    if not csp:
        return {"present": False, "issues": ["Missing CSP header"]}
    issues = []
    for bad in UNSAFE_CSP:
        if bad in csp:
            issues.append(f"Uses unsafe directive: {bad}")
    return {"present": True, "issues": issues or ["No unsafe directives found"]}

def check_endpoints(base):
    results = []
    for ep in COMMON_ENDPOINTS:
        url = urljoin(base + "/", ep)
        try:
            r = requests.get(url, timeout=5)
            results.append((ep, r.status_code))
        except:
            results.append((ep, None))
    return results

def tls_info(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                exp = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                return (exp - datetime.utcnow()).days
    except:
        return None

def scan_url(url):
    url = norm_url(url)
    resp = fetch(url)
    if not resp:
        return None

    headers = check_headers(resp)
    csp_analysis = analyze_csp(headers.get("content-security-policy"))
    endpoints = check_endpoints(url)
    tls_days = tls_info(urlparse(url).hostname)

    score = sum(1 for v in headers.values() if v) + (10 if tls_days else 0)
    recommendations = []
    if not csp_analysis["present"] or len(csp_analysis["issues"])>0:
        recommendations.append("Review CSP headers.")
    return {
        "target": url,
        "checks": headers,
        "csp_analysis": csp_analysis,
        "endpoints": endpoints,
        "tls_days_remaining": tls_days,
        "score": score,
        "recommendations": recommendations
    }
