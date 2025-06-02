document.addEventListener("DOMContentLoaded", function () {
  document.getElementById("scanButton").addEventListener("click", startScan);
});

async function startScan() {
  const scanButton = document.getElementById("scanButton");
  const progress = document.getElementById("progress");
  const progressText = document.getElementById("progressText");
  const scanLevel = document.getElementById("scanLevel").value;

  scanButton.disabled = true;
  scanButton.textContent = "Scanning...";
  progress.style.display = "block";

  try {
    const response = await fetch(
      `http://localhost:8000/scan-installed?scan_level=${scanLevel}`
    );
    const data = await response.json();

    updateProgress(data.extensions.length, data.extensions.length);
    displayResults(data.extensions);
  } catch (error) {
    console.error("Scan failed:", error);
    alert("Scan failed. Check console for details.");
  } finally {
    scanButton.disabled = false;
    scanButton.textContent = "Start Scan";
    progress.style.display = "none";
  }
}

function updateProgress(current, total) {
  document.getElementById("progressText").textContent = `${current}/${total}`;
}

// Add HTML escaping function
function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function displayResults(extensions) {
  const tbody = document.getElementById("resultsBody");
  tbody.innerHTML = ""; // Clear existing content safely

  extensions.forEach((ext) => {
    const row = document.createElement("tr");
    const safeData = {
      name: escapeHtml(ext.name || "Unknown"),
      extension_id: escapeHtml(ext.extension_id || ""),
      version: escapeHtml(ext.version || ""),
      risk_score: ext.risk_score ? Number(ext.risk_score).toFixed(1) : "N/A",
      risk_level: escapeHtml(ext.risk_level || "unknown"),
    };

    // Create cells individually instead of using innerHTML
    const cells = [
      createCell(safeData.name),
      createCell(safeData.extension_id),
      createCell(safeData.version),
      createCell(safeData.risk_score),
      createCell(safeData.risk_level, getRiskClass(safeData.risk_level)),
    ];

    cells.forEach((cell) => row.appendChild(cell));
    tbody.appendChild(row);
  });
}

function createCell(content, className = "") {
  const td = document.createElement("td");
  td.textContent = content; // Using textContent instead of innerHTML
  if (className) {
    td.className = className;
  }
  return td;
}

function getRiskClass(riskLevel) {
  switch (riskLevel?.toLowerCase()) {
    case "high":
      return "risk-high";
    case "medium":
      return "risk-medium";
    case "low":
      return "risk-low";
    default:
      return "";
  }
}
