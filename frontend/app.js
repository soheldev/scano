const BACKEND_URL = `${window.location.protocol}//${window.location.hostname}:8000`;
const result = document.getElementById("result");
const dnsDiv = document.getElementById("dns-result");
const scanBtn = document.getElementById("scanBtn");
const pdfBtn = document.getElementById("pdfBtn");

scanBtn.onclick = async () => {
    const url = document.getElementById("urlInput").value.trim();
    if (!url) return alert("Enter a URL");

    result.innerHTML = "<p class='loading'>Scanning...</p>";
    dnsDiv.innerHTML = "<p class='loading'>Loading DNS info...</p>";

    try {
        const res = await fetch(`${BACKEND_URL}/api/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        if (!res.ok) throw new Error("Scan failed");

        const data = await res.json();
        render(data);
        renderDNS(data.dns);
    } catch (err) {
        console.error(err);
        result.innerHTML = "<p class='error'>Scan failed</p>";
        dnsDiv.innerHTML = "<p class='error'>DNS info not available</p>";
    }
};

pdfBtn.onclick = () => {
    const url = document.getElementById("urlInput").value.trim();
    if (!url) return alert("Enter a URL");
    window.open(`${BACKEND_URL}/api/scan/pdf?url=${encodeURIComponent(url)}`);
};

function render(d) {
    result.innerHTML = `
        <div class="card">
            <h2>${d.target}</h2>
            <div class="summary">
                <span class="score">Score: ${d.score}/100</span>
                <span class="badge">TLS: ${d.tls?.tls_version || "N/A"} (${d.tls?.days_remaining || "?"} days)</span>
                <span class="badge warn">CSP: ${d.csp?.status || "Unknown"}</span>
            </div>
        </div>

        ${tlsBlock(d.tls)}
        ${headersBlock(d.headers)}
        ${cspBlock(d.csp)}
        ${infraBlock(d.infrastructure)}
        ${recommendationsBlock(d.recommendations)}
    `;
}

function renderDNS(dns) {
    if (!dns) {
        dnsDiv.innerHTML = "<p>No DNS information available</p>";
        return;
    }

    let html = `<h3>DNS Resolution for ${dns.domain}</h3>
        <table>
            <tr>
                <th>Resolver</th>
                <th>Location</th>
                <th>Provider</th>
                <th>IPs</th>
            </tr>
            ${dns.results.map(r => `
                <tr>
                    <td>${r.resolver}</td>
                    <td>${r.city}, ${r.country}</td>
                    <td>${r.provider}</td>
                    <td>${r.ips.join(", ") || "-"}</td>
                </tr>`).join("")}
        </table>
        <p>Resolves to: <strong>${dns.resolved_ip || "-"}</strong></p>
        <p>Server Type: <strong>${dns.server_type || "-"}</strong></p>
        <p>Certificate Expiration: <strong>${dns.cert_days_remaining || "N/A"} days</strong></p>
    `;
    dnsDiv.innerHTML = html;
}

function tlsBlock(t) {
    if (!t) return "";
    return `
    <div class="card">
        <h3>TLS Information</h3>
        <table>
            <tr><td>Issuer</td><td>${t.issuer}</td></tr>
            <tr><td>Valid From</td><td>${t.valid_from}</td></tr>
            <tr><td>Valid To</td><td>${t.valid_to}</td></tr>
            <tr><td>Days Remaining</td><td>${t.days_remaining}</td></tr>
            <tr><td>TLS Version</td><td>${t.tls_version}</td></tr>
        </table>
    </div>`;
}

function headersBlock(h) {
    if (!h) return "";
    return `
    <div class="card">
        <h3>Security Headers</h3>
        <table>
            ${Object.entries(h).map(([k,v]) => `
                <tr>
                    <td>${k}</td>
                    <td class="${v ? "ok" : "bad"}">${v ? "Present" : "Missing"}</td>
                </tr>`).join("")}
        </table>
    </div>`;
}

function cspBlock(c) {
    if (!c) return "";
    return `
    <div class="card">
        <h3>Content Security Policy</h3>
        <p>Status: <strong class="warn">${c.status}</strong></p>
        <ul>${c.issues.map(i => `<li>${i}</li>`).join("")}</ul>
    </div>`;
}

function infraBlock(i) {
    if (!i) return "";
    return `
    <div class="card">
        <h3>Infrastructure</h3>
        <p>CDN / Proxy: <strong>${i.cdn}</strong></p>
    </div>`;
}

function recommendationsBlock(r) {
    if (!r || r.length === 0) return "";
    return `
    <div class="card">
        <h3>Recommendations</h3>
        <ul class="recommend">${r.map(x => `<li>${x}</li>`).join("")}</ul>
    </div>`;
}

