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

scanBtn.addEventListener("click", scan);

async function scan() {
    const url = urlInput.value.trim();
    if (!url) {
        alert("Enter a URL");
        return;
    }

    resetUI();
    resultDiv.innerHTML = "<p class='loading'>Scanning...</p>";

    try {
        const res = await fetch(`${BACKEND_URL}/api/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        if (!res.ok) throw new Error("Scan failed");

        const data = await res.json();
        renderAll(data);

    } catch (err) {
        console.error(err);
        resultDiv.innerHTML = "<p class='error'>Scan failed</p>";
    }
}

pdfBtn.onclick = () => {
    const url = urlInput.value.trim();
    if (!url) return alert("Enter a URL");
    window.open(`${BACKEND_URL}/api/scan/pdf?url=${encodeURIComponent(url)}`);
};

function resetUI() {
    resultDiv.innerHTML = "";
    tlsDiv.innerHTML = "";
    headersDiv.innerHTML = "";
    cspDiv.innerHTML = "";
    dnsDiv.innerHTML = "";
    infraDiv.innerHTML = "";
    recDiv.innerHTML = "";
}

function renderAll(data) {
    renderSummary(data);
    renderTLS(data.tls);
    renderHeaders(data.headers);
    renderCSP(data.csp);
    renderDNS(data.dns);
    renderInfra(data.infrastructure || { cdn: data.cdn });
    renderRecommendations(data.recommendations);
}

/* =========================
   SUMMARY
========================= */
function renderSummary(data) {
    resultDiv.innerHTML = `
        <h2>${data.target}</h2>
        <p>
            <strong>Score:</strong> ${data.score}/100 &nbsp;
            <strong>TLS:</strong> ${data.tls?.tls_version || "N/A"} &nbsp;
            <strong>CSP:</strong>
            <span class="${data.csp_status === "Weak" ? "warn" : "ok"}">
                ${data.csp_status || "Unknown"}
            </span>
        </p>
    `;
}

/* =========================
   TLS / SSL
========================= */
function renderTLS(tls) {
    if (!tls) return;

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
   SECURITY HEADERS
========================= */
function renderHeaders(headers) {
    if (!headers) return;

    headersDiv.innerHTML = `
        <h3>Security Headers</h3>
        <table>
            ${Object.entries(headers).map(([k, v]) => `
                <tr>
                    <td>${k}</td>
                    <td class="${v ? "ok" : "bad"}">
                        ${v ? "Present" : "Missing"}
                    </td>
                </tr>
            `).join("")}
        </table>
    `;
}

/* =========================
   CSP
========================= */
function renderCSP() {
    // CSP analysis already summarized in score section
    return;
}

/* =========================
   DNS PANEL (DNS-ONLY)
========================= */
function renderDNS(dns) {
    if (!dns || !dns.results || dns.results.length === 0) {
        dnsDiv.innerHTML = `
            <h3>DNS Resolution</h3>
            <p>No DNS information available</p>
        `;
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

        <p style="margin-top:10px">
            <strong>Primary Resolved IP:</strong>
            ${dns.resolved_ip || "-"}
        </p>
    `;
}

/* =========================
   INFRASTRUCTURE
========================= */
function renderInfra(infra) {
    if (!infra) return;

    infraDiv.innerHTML = `
        <h3>Infrastructure</h3>
        <p>CDN / Proxy: <strong>${infra.cdn || "-"}</strong></p>
    `;
}

/* =========================
   RECOMMENDATIONS
========================= */
function renderRecommendations(recs) {
    if (!recs || recs.length === 0) {
        recDiv.innerHTML = `
            <h3>Recommendations</h3>
            <p>No recommendations 🎉</p>
        `;
        return;
    }

    recDiv.innerHTML = `
        <h3>Recommendations</h3>
        <ul>
            ${recs.map(r => `<li>${r}</li>`).join("")}
        </ul>
    `;
}

