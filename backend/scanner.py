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
# CDN & HOSTING MAPS
# =========================
ASN_CDN_MAP = {
    "akamai": "Akamai",
    "cloudflare": "Cloudflare",
    "fastly": "Fastly",
    "amazon": "AWS CloudFront",
    "aws": "AWS CloudFront",
    "google": "Google Cloud CDN",
    "microsoft": "Azure CDN",
    "edgecast": "Edgio / Edgecast",
    "stackpath": "StackPath",
}

HOSTING_MAP = {
    "unifiedlayer": "Bluehost / HostGator",
    "hostinger": "Hostinger",
    "digitalocean": "DigitalOcean",
    "linode": "Akamai Linode",
    "ovh": "OVH",
    "hetzner": "Hetzner",
}

# =========================
# HELPERS
# =========================
def normalize(url: str):
    return url if url.startswith("http") else "https://" + url

async def fetch_headers(url):
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.get(url)
            return {h: h in r.headers for h in HEADERS}, r.headers
    except Exception:
        return {h: False for h in HEADERS}, {}

# =========================
# TLS INFO
# =========================
def tls_info(host):
    try:
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
    except Exception:
        return {"issuer": "-", "valid_from": "-", "valid_to": "-", "days_remaining": "-", "tls_version": "Not Enabled"}

# =========================
# GEO LOOKUP
# =========================
def geo_lookup(ip: str):
    if not ip:
        return "-", "-"
    try:
        asn = asn_reader.asn(ip)
        provider = asn.autonomous_system_organization or "Unknown"
        # CDN hides location
        cdn_orgs = ["cloudflare", "akamai", "fastly", "edgecast"]
        if any(c in provider.lower() for c in cdn_orgs):
            return "Location hidden (CDN)", provider
        city = city_reader.city(ip)
        location = f"{city.city.name or 'Unknown'}, {city.country.name or 'Unknown'}"
        return location, provider
    except Exception:
        return "Unknown", "Unknown"

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
    return {"domain": domain, "resolved_ip": resolved_ip, "results": results}

# =========================
# CDN DETECTION
# =========================
def detect_cdn(headers: dict, ip: str):
    h = {k.lower(): str(v).lower() for k, v in headers.items()}
    # header-based
    if "cf-ray" in h:
        return "Cloudflare"
    if any("akamai" in v for v in h.values()):
        return "Akamai"
    if "x-fastly" in h:
        return "Fastly"
    if "x-amz-cf-id" in h:
        return "AWS CloudFront"
    # ASN-based
    try:
        asn = asn_reader.asn(ip)
        org = (asn.autonomous_system_organization or "").lower()
        for k, v in ASN_CDN_MAP.items():
            if k in org:
                return v
    except Exception:
        pass
    return "Unknown"

# =========================
# HOSTING PROVIDER
# =========================
def detect_hosting_provider(ip: str):
    try:
        asn = asn_reader.asn(ip)
        org = (asn.autonomous_system_organization or "").lower()
        for k, v in HOSTING_MAP.items():
            if k in org:
                return v
        return asn.autonomous_system_organization or "Unknown"
    except Exception:
        return "Unknown"

# =========================
# WAF DETECTION
# =========================
def detect_waf(headers: dict):
    h = {k.lower(): str(v).lower() for k, v in headers.items()}
    if "cf-ray" in h:
        return "Cloudflare WAF"
    if any("akamai" in v for v in h.values()):
        return "Akamai Kona Site Defender"
    if "x-sucuri-id" in h:
        return "Sucuri WAF"
    if "x-incapsula" in h:
        return "Imperva WAF"
    return "Not Detected"

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
# MAIN SCAN
# =========================
async def scan(url):
    url = normalize(url)
    host = urlparse(url).hostname
    headers, raw = await fetch_headers(url)
    tls = tls_info(host)
    dns = dns_panel(host)
    ip = dns.get("resolved_ip")

    score = sum(headers.values()) * 10
    if tls.get("tls_version") == "TLSv1.3":
        score += 30
    score = min(score, 100)

    return {
        "target": url,
        "score": score,
        "headers": headers,
        "tls": tls,
        "infrastructure": {
            "server": detect_server(raw),
            "cdn": detect_cdn(raw, ip),
            "hosting_provider": detect_hosting_provider(ip),
            "waf": detect_waf(raw),
        },
        "dns": dns,
    }

