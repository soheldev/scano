import httpx
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
import geoip2.database

# =========================
# GEOIP DATABASE PATHS
# =========================
CITY_DB = "/geoip/GeoLite2-City.mmdb"
ASN_DB = "/geoip/GeoLite2-ASN.mmdb"

city_reader = geoip2.database.Reader(CITY_DB)
asn_reader = geoip2.database.Reader(ASN_DB)

# =========================
# SECURITY HEADERS
# =========================
HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

# =========================
# DNS RESOLVERS
# =========================
DNS_RESOLVERS = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
}

# =========================
# HELPERS
# =========================
def normalize(url: str):
    return url if url.startswith("http") else "https://" + url


async def fetch_headers(url):
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        r = await client.get(url)
        return {h: h in r.headers for h in HEADERS}, r.headers


# =========================
# TLS INFO
# =========================
def tls_info(host):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            cert = ss.getpeercert()

            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            start = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")

            issuer = dict(x[0] for x in cert["issuer"]).get("organizationName")

            return {
                "issuer": issuer or "Unknown",
                "valid_from": start.strftime("%Y-%m-%d"),
                "valid_to": exp.strftime("%Y-%m-%d"),
                "days_remaining": (exp - datetime.utcnow()).days,
                "tls_version": ss.version(),
            }


# =========================
# GEO LOOKUP
# =========================
def geo_lookup(ip: str):
    if not ip:
        return "-", "-"

    provider = "Unknown"
    location = "Unknown"

    try:
        asn = asn_reader.asn(ip)
        provider = asn.autonomous_system_organization or "Unknown"
    except Exception:
        pass

    # CDN hides location
    cdn_orgs = ["cloudflare", "akamai", "fastly", "edgecast"]
    if any(c in provider.lower() for c in cdn_orgs):
        return "Location hidden (CDN)", provider

    try:
        city = city_reader.city(ip)
        location = f"{city.city.name or 'Unknown'}, {city.country.name or 'Unknown'}"
    except Exception:
        pass

    return location, provider


# =========================
# DNS PANEL
# =========================
def dns_panel(domain: str):
    results = []
    resolved_ip = None

    try:
        resolved_ip = socket.gethostbyname(domain)
    except Exception:
        pass

    location, provider = geo_lookup(resolved_ip)

    for resolver in DNS_RESOLVERS.keys():
        results.append({
            "resolver": resolver,
            "location": location,
            "provider": provider,
            "ips": [resolved_ip] if resolved_ip else [],
        })

    return {
        "domain": domain,
        "resolved_ip": resolved_ip,
        "results": results,
    }


# =========================
# CDN DETECTION (CORRECT)
# =========================
def detect_cdn(headers: dict, ip: str):
    # 1️⃣ ASN — ONLY real CDNs
    try:
        asn = asn_reader.asn(ip)
        org = (asn.autonomous_system_organization or "").lower()

        if "akamai" in org:
            return "Akamai"
        if "cloudflare" in org:
            return "Cloudflare"
        if "fastly" in org:
            return "Fastly"
        if "edgecast" in org or "verizon" in org:
            return "Edgecast"

        # ❌ Hosting ≠ CDN
        if any(x in org for x in ["amazon", "aws", "google", "microsoft", "azure"]):
            return "Unknown"

    except Exception:
        pass

    # 2️⃣ Header-based fallback
    if "cf-ray" in headers:
        return "Cloudflare"
    if "x-akamai" in headers or "akamai" in str(headers).lower():
        return "Akamai"
    if "x-fastly" in headers:
        return "Fastly"
    if "x-amz-cf-id" in headers:
        return "AWS CloudFront"

    return "Unknown"


# =========================
# SERVER DETECTION
# =========================
def detect_server(headers: dict):
    server = headers.get("server")
    if not server:
        return "Unknown"

    s = server.lower()
    if "nginx" in s:
        return "Nginx"
    if "apache" in s:
        return "Apache"
    if "iis" in s:
        return "Microsoft IIS"

    return server


# =========================
# MAIN SCAN FUNCTION
# =========================
async def scan(url):
    url = normalize(url)
    host = urlparse(url).hostname

    headers, raw = await fetch_headers(url)
    tls = tls_info(host)
    dns = dns_panel(host)

    score = sum(headers.values()) * 10
    if tls.get("tls_version") == "TLSv1.3":
        score += 30
    score = min(score, 100)

    cdn = detect_cdn(raw, dns.get("resolved_ip"))
    server = detect_server(raw)

    return {
        "target": url,
        "score": score,
        "headers": headers,
        "tls": tls,
        "infrastructure": {
            "cdn": cdn,
            "server": server,
        },
        "dns": dns,
    }

