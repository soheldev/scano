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
        if (!res.ok) throw new Error(`Server returned status ${res.status}`);
        const data = await res.json();
        displayResult(data);
    } catch (e) {
        console.error(e);
        resultDiv.innerHTML = "Error scanning URL. Check backend is running and CORS is allowed.";
    }
};

pdfBtn.onclick = () => {
    const url = urlInput.value.trim();
    if (!url) return alert("Enter a URL");
    window.open(`${BACKEND_URL}/api/scan/pdf?url=${encodeURIComponent(url)}`, "_blank");
};

function displayResult(data) {
    let html = `<h2>Scan Results for ${data.target}</h2>`;
    html += `<p>Security Score: ${data.score || 0}/100</p>`;
    html += "<table border='1' cellpadding='5'><tr><th>Check</th><th>Status</th><th>Details</th></tr>";
    for (let [key, val] of Object.entries(data.checks)) {
        html += `<tr>
            <td>${key}</td>
            <td class="${val ? "ok" : "missing"}">${val ? "OK" : "Missing"}</td>
            <td>${val || ""}</td>
        </tr>`;
    }
    html += "</table>";

    if (data.recommendations && data.recommendations.length > 0) {
        html += "<h3>Recommendations:</h3><ul>";
        for (let rec of data.recommendations) {
            html += `<li>${rec}</li>`;
        }
        html += "</ul>";
    }

    resultDiv.innerHTML = html;
}
