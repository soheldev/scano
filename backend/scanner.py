import requests, ssl, socket
from urllib.parse import urlparse, urljoin
from datetime import datetime
import ipaddress
import dns.resolver

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

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
]

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return True

def norm_url(url):
    p = urlparse(url)
    if not p.scheme:
        url = "https://" + url
        p = urlparse(url)
    try:
        host_ip = socket.gethostbyname(p.hostname)
        if is_private_ip(host_ip):
            return None
    except:
        return None
    return url

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
        return {"present": False, "issues": ["Missing CSP header"], "status": "Not Configured"}
    issues = []
    for bad in UNSAFE_CSP:
        if bad in csp:
            issues.append(bad)
    status = "Weak" if issues else "Secure"
    return {"present": True, "issues": issues or ["No unsafe directives found"], "status": status}

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
                days_remaining = (exp - datetime.utcnow()).days
                return {
                    "issuer": dict(cert.get('issuer')[0]).get('organizationName', '') if cert.get('issuer') else '',
                    "valid_from": cert.get('notBefore'),
                    "valid_to": cert.get('notAfter'),
                    "days_remaining": days_remaining,
                    "tls_version": ss.version()
                }
    except:
        return {"error": "TLS verification failed"}

def dns_info(hostname):
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        return [str(a) for a in answers]
    except:
        return []

def detect_cdn(headers):
    server = headers.get("server", "").lower()
    via = headers.get("via", "").lower()
    if "cloudflare" in server or "cloudflare" in via:
        return "Cloudflare"
    if "akamai" in server or "akamai" in via:
        return "Akamai"
    return "Direct / Unknown"

def calculate_score(headers, tls, csp_status, cdn_status, endpoints):
    score = 0
    score += sum(1 for v in headers.values() if v) * 10
    if tls.get("days_remaining", 0) > 0:
        score += 20
    if csp_status == "Secure":
        score += 10
    if cdn_status != "Direct / Unknown":
        score += 10
    score -= sum(1 for ep, status in endpoints if status is None) * 5
    return min(score, 100)

def recommendations(headers, csp_status, tls):
    recs = []
    if not headers.get("strict-transport-security"):
        recs.append("Enable HSTS with an appropriate max-age")
    if csp_status != "Secure":
        recs.append("Harden CSP headers")
    if tls.get("days_remaining", 0) < 30:
        recs.append("TLS certificate expiring soon")
    return recs

def scan_url(url):
    url = norm_url(url)
    if not url:
        return None
    resp = fetch(url)
    if not resp:
        return None

    headers = check_headers(resp)
    csp_analysis = analyze_csp(headers.get("content-security-policy"))
    endpoints = check_endpoints(url)
    tls = tls_info(urlparse(url).hostname)
    dns = dns_info(urlparse(url).hostname)
    cdn = detect_cdn(resp.headers)
    score = calculate_score(headers, tls, csp_analysis['status'], cdn, endpoints)
    recs = recommendations(headers, csp_analysis['status'], tls)

    return {
        "target": url,
        "headers": headers,
        "csp_analysis": csp_analysis,
        "tls": tls,
        "dns": dns,
        "cdn": cdn,
        "endpoints": endpoints,
        "score": score,
        "recommendations": recs
    }

