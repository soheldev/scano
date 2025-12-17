import httpx, ssl, socket
from urllib.parse import urlparse
from datetime import datetime

HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
]

def normalize(url: str):
    return url if url.startswith("http") else "https://" + url

async def fetch_headers(url):
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url)
        return {h: h in r.headers for h in HEADERS}, r.headers

def tls_info(host):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            cert = ss.getpeercert()
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            start = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
            return {
                "issuer": dict(x[0] for x in cert["issuer"])["organizationName"],
                "valid_from": start.strftime("%b %d %Y"),
                "valid_to": exp.strftime("%b %d %Y"),
                "days_remaining": (exp - datetime.utcnow()).days,
                "tls_version": ss.version()
            }

async def scan(url):
    url = normalize(url)
    host = urlparse(url).hostname

    headers, raw = await fetch_headers(url)
    tls = tls_info(host)

    score = sum(headers.values()) * 10
    if tls["tls_version"] == "TLSv1.3":
        score += 30

    csp = raw.get("content-security-policy", "")
    csp_status = "Weak" if "unsafe-inline" in csp else "Strong"

    recs = []
    if csp_status == "Weak":
        recs.append("Harden CSP headers")

    cdn = "Cloudflare" if "cf-ray" in raw else "Unknown"

    return {
        "target": url,
        "score": min(score, 100),
        "headers": headers,
        "csp_status": csp_status,
        "tls": tls,
        "cdn": cdn,
        "recommendations": recs
    }

