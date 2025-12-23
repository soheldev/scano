const BACKEND_URL = `${window.location.protocol}//${window.location.hostname}:8000`;

const scanBtn = document.getElementById("scanBtn");
const pdfBtn  = document.getElementById("pdfBtn");

/* =========================
   RESET UI (DNS SAFE)
========================= */
function resetUI() {
    document.getElementById("scoreValue").innerText = "--";
    document.getElementById("targetDisplay").innerText = "Scanning...";
    document.getElementById("targetSub").innerText = "Please wait…";
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

    const res = await fetch(`${BACKEND_URL}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
    });

    const data = await res.json();
    renderAll(data);
}

/* =========================
   PDF
========================= */
function downloadPDF() {
    const url = document.getElementById("urlInput").value.trim();
    if (!url) return alert("Enter a URL first");

    window.open(
        `${BACKEND_URL}/api/scan/pdf?url=${encodeURIComponent(url)}`,
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
    document.getElementById("scoreValue").innerText = data.score;
    gauge.className = `gauge ${data.score < 50 ? "bad" : "ok"}`;
    document.getElementById("targetDisplay").innerText = data.target;
    document.getElementById("targetSub").innerText = "Scan completed";
}

/* TLS */
function renderTLS(tls) {
    document.getElementById("tls").innerHTML = `
        <h3><i class="fas fa-lock"></i> TLS</h3>
        <table>
            <tr><td>Issuer</td><td>${tls.issuer || "-"}</td></tr>
            <tr><td>Version</td><td>${tls.tls_version || "-"}</td></tr>
            <tr><td>Expires (days)</td><td>${tls.days_remaining ?? "-"}</td></tr>
        </table>
    `;
}

/* HEADERS */
function renderHeaders(headers) {
    const rows = Object.entries(headers).map(([k,v]) => `
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

/* INFRA */
function renderInfra(infra) {
    document.getElementById("infra").innerHTML = `
        <h3><i class="fas fa-server"></i> Infrastructure</h3>
        <table>
            <tr><td>Server</td><td>${infra.server || "-"}</td></tr>
            <tr><td>CDN</td><td>${infra.cdn || "-"}</td></tr>
        </table>
    `;
}

/* =========================
   DNS (FIXED — MATCHES BACKEND)
========================= */
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
            <tbody>
                ${rows}
            </tbody>
        </table>
        <p><strong>Primary IP:</strong> ${dns.resolved_ip || "-"}</p>
    `;
}

/* RECOMMENDATIONS */
function renderRecommendations(recs) {
    const el = document.getElementById("recommendations");

    if (!recs || recs.length === 0) {
        el.innerHTML = "<h3><i class='fas fa-bolt'></i> Recommendations</h3><p>🎉 No issues</p>";
        return;
    }

    el.innerHTML = `
        <h3><i class="fas fa-bolt"></i> Recommendations</h3>
        ${recs.map(r => `<div class="action-item">${r}</div>`).join("")}
    `;
}

scanBtn.addEventListener("click", scan);
pdfBtn.addEventListener("click", downloadPDF);

