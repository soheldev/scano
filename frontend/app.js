// Backend is accessed via SAME DOMAIN through nginx
// nginx: location /api/ → http://127.0.0.1:8000/
const BACKEND_URL = "/api";

const scanBtn = document.getElementById("scanBtn");
const pdfBtn  = document.getElementById("pdfBtn");

/* =========================
   RESET UI (DNS SAFE)
========================= */
function resetUI() {
    document.getElementById("scoreValue").innerText = "--";
    document.getElementById("targetDisplay").innerText = "Ready to Scan";
    document.getElementById("targetSub").innerText = "Enter a URL to begin security audit";
    document.getElementById("scoreGauge").className = "gauge";

    ["tls","headers","infra","recommendations"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = "<p>Loading…</p>";
    });

    document.getElementById("dns").innerHTML = `
        <h3><i class="fas fa-globe"></i> DNS</h3>
        <p>Resolving DNS…</p>
    `;
}

/* =========================
   SCAN
========================= */
async function scan() {
    const url = document.getElementById("urlInput").value.trim();
    if (!url) return alert("Enter a URL");

    resetUI();

    try {
        const res = await fetch(`${BACKEND_URL}/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });

        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        renderAll(data);
    } catch (err) {
        console.error("Scan error:", err);
        alert("Failed to fetch scan data. Check console.");
    }
}

/* =========================
   PDF DOWNLOAD
========================= */
function downloadPDF() {
    const url = document.getElementById("urlInput").value.trim();
    if (!url) return alert("Enter a URL first");

    window.open(
        `${BACKEND_URL}/scan/pdf?url=${encodeURIComponent(url)}`,
        "_blank"
    );
}

/* =========================
   RENDER
========================= */
function renderAll(data) {
    renderHero(data);
    renderTLS(data.tls);
    renderHeaders(data.headers);
    renderInfra(data.infrastructure);
    renderDNS(data.dns);
    renderRecommendations(data.recommendations);
}

/* HERO */
function renderHero(data) {
    const gauge = document.getElementById("scoreGauge");
    const score = data.score ?? "--";
    document.getElementById("scoreValue").innerText = score;
    gauge.className = `gauge ${score < 50 ? "bad" : "ok"}`;
    document.getElementById("targetDisplay").innerText = data.target || "-";
    document.getElementById("targetSub").innerText = "Scan completed";
}

/* TLS */
function renderTLS(tls) {
    document.getElementById("tls").innerHTML = `
        <h3><i class="fas fa-lock"></i> TLS</h3>
        <table>
            <tr><td>Issuer</td><td>${tls?.issuer || "-"}</td></tr>
            <tr><td>Version</td><td>${tls?.tls_version || "-"}</td></tr>
            <tr><td>Expires (days)</td><td>${tls?.days_remaining ?? "-"}</td></tr>
        </table>
    `;
}

/* HEADERS */
function renderHeaders(headers) {
    const rows = Object.entries(headers || {}).map(([k,v]) => `
        <tr>
            <td>${k}</td>
            <td class="status-badge ${v ? "present":"missing"}">
                ${v ? "Present":"Missing"}
            </td>
        </tr>
    `).join("");

    document.getElementById("headers").innerHTML = `
        <h3><i class="fas fa-list-check"></i> Headers</h3>
        <table>${rows}</table>
    `;
}

/* INFRASTRUCTURE */
function renderInfra(infra) {
    document.getElementById("infra").innerHTML = `
        <h3><i class="fas fa-server"></i> Infrastructure</h3>
        <table>
            <tr><td>Server</td><td>${infra?.server || "-"}</td></tr>
            <tr><td>CDN</td><td>${infra?.cdn || "-"}</td></tr>
            <tr><td>Hosting</td><td>${infra?.hosting_provider || "-"}</td></tr>
            <tr><td>WAF</td><td>${infra?.waf || "-"}</td></tr>
        </table>
    `;
}

/* DNS */
function renderDNS(dns) {
    if (!dns || !dns.results) {
        document.getElementById("dns").innerHTML = `
            <h3><i class="fas fa-globe"></i> DNS</h3>
            <p>No DNS data available</p>
        `;
        return;
    }

    const rows = dns.results.map(r => `
        <tr>
            <td>${r.resolver || "-"}</td>
            <td>${r.location || "-"}</td>
            <td>${r.provider || "-"}</td>
            <td>${(r.ips && r.ips.join(", ")) || "-"}</td>
        </tr>
    `).join("");

    document.getElementById("dns").innerHTML = `
        <h3><i class="fas fa-globe"></i> DNS</h3>
        <table class="dns-table">
            <thead>
                <tr>
                    <th>Source</th>
                    <th>Location</th>
                    <th>Provider</th>
                    <th>IPs</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
        <p><strong>Primary IP:</strong> ${dns.resolved_ip || "-"}</p>
    `;
}

/* RECOMMENDATIONS */
function renderRecommendations(recs) {
    const el = document.getElementById("recommendations");
    if (!recs || recs.length === 0) {
        el.innerHTML = `
            <h3><i class="fas fa-bolt"></i> Recommendations</h3>
            <p>🎉 No issues</p>
        `;
        return;
    }

    el.innerHTML = `
        <h3><i class="fas fa-bolt"></i> Recommendations</h3>
        ${recs.map(r => `<div class="action-item">${r}</div>`).join("")}
    `;
}

/* =========================
   EVENTS
========================= */
scanBtn.addEventListener("click", scan);
pdfBtn.addEventListener("click", downloadPDF);

