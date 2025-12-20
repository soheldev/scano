import httpx
import ssl
import socket
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime
import geoip2.database

CITY_DB = "/geoip/GeoLite2-City.mmdb"
ASN_DB = "/geoip/GeoLite2-ASN.mmdb"

HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

DNS_RESOLVERS = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
}

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

            issuer = dict(x[0] for x in cert["issuer"]).get("organizationName")

            return {
                "issuer": issuer,
                "valid_from": start.strftime("%Y-%m-%d"),
                "valid_to": exp.strftime("%Y-%m-%d"),
                "days_remaining": (exp - datetime.utcnow()).days,
                "tls_version": ss.version(),
                "ssl_provider": issuer
            }

def geo_lookup(ip):
    city = country = provider = "Unknown"

    try:
        with geoip2.database.Reader(CITY_DB) as reader:
            r = reader.city(ip)
            city = r.city.name or "Unknown"
            country = r.country.name or "Unknown"
    except:
        city = country = "Unknown"

    try:
        with geoip2.database.Reader(ASN_DB) as reader:
            r = reader.asn(ip)
            provider = r.autonomous_system_organization or "Unknown"
    except:
        provider = "Unknown"

    # Friendly location for CDN IPs
    cdn_providers = ["Cloudflare", "Akamai", "Fastly", "Amazon", "Microsoft"]
    if any(cdn.lower() in (provider or "").lower() for cdn in cdn_providers):
        city = country = f"Behind {provider} / Location not revealed"

    return city, country, provider

def dns_panel(domain):
    results = []
    primary_ip = None

    for resolver_name, ns in DNS_RESOLVERS.items():
        try:
            r = dns.resolver.Resolver()
            r.nameservers = [ns]
            answers = r.resolve(domain, "A", lifetime=4)

            ips = sorted({str(a) for a in answers})
            if not primary_ip and ips:
                primary_ip = ips[0]

            city = country = provider = None
            if ips:
                city, country, provider = geo_lookup(ips[0])

            results.append({
                "resolver": resolver_name,
                "location": f"{city}, {country}",
                "provider": provider,
                "ips": ips,
            })
        except:
            results.append({
                "resolver": resolver_name,
                "location": "Unknown",
                "provider": "Unknown",
                "ips": [],
            })

    return {
        "domain": domain,
        "resolved_ip": primary_ip,
        "results": results,
    }

# =========================
# SERVER DETECTION
# =========================
def detect_server(headers: dict) -> str | None:
    server = headers.get("server")
    if not server:
        return None

    s = server.lower()
    if "cloudflare" in s:
        return "Cloudflare"
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

    score = sum(headers.values()) * 10
    if tls.get("tls_version") == "TLSv1.3":
        score += 30
    score = min(score, 100)

    csp_header = raw.get("content-security-policy", "")
    csp = {
        "status": "Weak" if "unsafe-inline" in csp_header else "Strong",
        "issues": ["Remove unsafe-inline from CSP"] if "unsafe-inline" in csp_header else [],
    }

    recommendations = []
    if csp["status"] == "Weak":
        recommendations.append("Harden Content Security Policy")

    cdn = "Cloudflare" if "cf-ray" in raw else "Unknown"
    dns = dns_panel(host)

    return {
        "target": url,
        "score": score,
        "headers": headers,
        "csp": csp,
        "tls": tls,
        "infrastructure": {
            "cdn": cdn,
            "server": detect_server(raw),
        },
        "dns": dns,
        "recommendations": recommendations,
    }

