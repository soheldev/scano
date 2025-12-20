const BACKEND_URL = "http://35.171.47.100:8000"; // change to EC2 IP:8000

const scanBtn = document.getElementById("scan-btn");
const pdfBtn = document.getElementById("pdf-btn");
const urlInput = document.getElementById("url-input");
const resultDiv = document.getElementById("scan-result");

scanBtn.onclick = async () => {
    const url = urlInput.value.trim();
    if (!url) return alert("Enter a URL");
    resultDiv.innerHTML = "Scanning...";

    try {
        const res = await fetch(`${BACKEND_URL}/api/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });
        const data = await res.json();
        display(data);
    } catch {
        resultDiv.innerHTML = "Scan failed";
    }
};

pdfBtn.onclick = () => {
    const url = urlInput.value.trim();
    window.open(`${BACKEND_URL}/api/scan/pdf?url=${encodeURIComponent(url)}`);
};

function display(data) {
    let html = `<h2>${data.target}</h2>`;
    html += `<p>Score: ${data.score}/100</p>`;
    html += "<h3>TLS Info</h3><ul>";
    for (const [k,v] of Object.entries(data.tls || {})) html += `<li>${k}: ${v}</li>`;
    html += "</ul><h3>Headers</h3><ul>";
    for (const [k,v] of Object.entries(data.headers || {})) html += `<li>${k}: ${v ? "Present" : "Missing"}</li>`;
    html += "</ul><h3>CSP</h3>";
    html += `<p>Status: ${data.csp_analysis.status}</p><ul>`;
    for (const i of data.csp_analysis.issues) html += `<li>${i}</li>`;
    html += "</ul>";
    html += `<p>CDN / Proxy: ${data.cdn}</p>`;
    html += "<h3>Recommendations</h3><ul>";
    for (const r of data.recommendations) html += `<li>${r}</li>`;
    html += "</ul>";
    resultDiv.innerHTML = html;
}

