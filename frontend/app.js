const BACKEND_URL = `${window.location.protocol}//${window.location.hostname}:8000`;

const scanBtn = document.getElementById("scanBtn");
const pdfBtn = document.getElementById("pdfBtn");
const urlInput = document.getElementById("urlInput");

const resultDiv = document.getElementById("result");
const tlsDiv = document.getElementById("tls");
const headersDiv = document.getElementById("headers");
const cspDiv = document.getElementById("csp");
const dnsDiv = document.getElementById("dns");
const infraDiv = document.getElementById("infra");
const recDiv = document.getElementById("recommendations");

/* =========================
   EVENTS
========================= */
scanBtn.addEventListener("click", scan);

pdfBtn.onclick = () => {
    const url = urlInput.value.trim();
    if (!url) return alert("Enter a URL");
    window.open(`${BACKEND_URL}/api/scan/pdf?url=${encodeURIComponent(url)}`);
};

/* =========================
   SCAN
========================= */
async function scan() {
    const url = urlInput.value.trim();
    if (!url) {
        alert("Enter a URL");
        return;
    }

    resetUI();
    if (resultDiv) resultDiv.innerHTML = "<p class='loading'>Scanning...</p>";

    try {
        const res = await fetch(`${BACKEND_URL}/api/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });

        if (!res.ok) throw new Error("Scan failed");

        const data = await res.json();
        renderAll(data);
    } catch (err) {
        console.error(err);
        if (resultDiv) resultDiv.innerHTML = "<p class='error'>Scan failed</p>";
    }
}

/* =========================
   RESET UI
========================= */
function resetUI() {
    const sections = [resultDiv, tlsDiv, headersDiv, cspDiv, dnsDiv, infraDiv, recDiv];
    sections.forEach(el => {
        if (el !== null) el.innerHTML = "";
    });
}

/* =========================
   RENDER ALL
========================= */
function renderAll(data) {
    renderSummary(data);
    renderTLS(data.tls);
    renderHeaders(data.headers);
    renderDNS(data.dns);
    renderInfra(data.infrastructure || { cdn: data.cdn });
    renderRecommendations(data.recommendations);
}

/* =========================
   SUMMARY
========================= */
function renderSummary(data) {
    if (!resultDiv) return;

    resultDiv.innerHTML = `
        <h2>${data.target}</h2>
        <p><strong>Score:</strong> ${data.score}/100</p>
    `;
}

/* =========================
   TLS / SSL
========================= */
function renderTLS(tls) {
    if (!tls || !tlsDiv) return;

    tlsDiv.innerHTML = `
        <h3>TLS / SSL Information</h3>
        <table>
            <tr><td>Issuer</td><td>${tls.issuer || "-"}</td></tr>
            <tr><td>Valid From</td><td>${tls.valid_from || "-"}</td></tr>
            <tr><td>Valid To</td><td>${tls.valid_to || "-"}</td></tr>
            <tr><td>Days Remaining</td><td>${tls.days_remaining ?? "-"}</td></tr>
            <tr><td>TLS Version</td><td>${tls.tls_version || "-"}</td></tr>
        </table>
    `;
}

/* =========================
   HEADERS
========================= */
function renderHeaders(headers) {
    if (!headers || !headersDiv) return;

    headersDiv.innerHTML = `
        <h3>Security Headers</h3>
        <table>
            ${Object.entries(headers).map(([k, v]) => `
                <tr>
                    <td>${k}</td>
                    <td class="${v ? "ok" : "bad"}">${v ? "Present" : "Missing"}</td>
                </tr>
            `).join("")}
        </table>
    `;
}

/* =========================
   DNS
========================= */
function renderDNS(dns) {
    if (!dnsDiv) return;

    if (!dns || !dns.results || dns.results.length === 0) {
        dnsDiv.innerHTML = "<h3>DNS Resolution</h3><p>No DNS information available</p>";
        return;
    }

    dnsDiv.innerHTML = `
        <h3>DNS Resolution for ${dns.domain}</h3>
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
                    <td>${r.location || "-"}</td>
                    <td>${r.provider || "-"}</td>
                    <td>${(r.ips || []).join("<br>")}</td>
                </tr>
            `).join("")}
        </table>
        <p style="margin-top:10px"><strong>Primary Resolved IP:</strong> ${dns.resolved_ip || "-"}</p>
    `;
}

/* =========================
   INFRASTRUCTURE
========================= */
function renderInfra(infra) {
    if (!infra || !infraDiv) return;

    infraDiv.innerHTML = `
        <h3>Infrastructure</h3>
        <table>
            <tr>
                <td>Server</td>
                <td><strong>${infra.server || "-"}</strong></td>
            </tr>
            <tr>
                <td>CDN / Proxy</td>
                <td><strong>${infra.cdn || "-"}</strong></td>
            </tr>
        </table>
    `;
}

/* =========================
   RECOMMENDATIONS
========================= */
function renderRecommendations(recs) {
    if (!recDiv) return;

    if (!recs || recs.length === 0) {
        recDiv.innerHTML = "<h3>Recommendations</h3><p>No recommendations 🎉</p>";
        return;
    }

    recDiv.innerHTML = `
        <h3>Recommendations</h3>
        <ul>
            ${recs.map(r => `<li>${r}</li>`).join("")}
        </ul>
    `;
}

