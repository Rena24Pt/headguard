// All rendering below uses textContent, never innerHTML: header values and
// messages come from the scanned site, and a scanner that can be XSS'd by
// the site it scans would be embarrassing.

const form = document.getElementById("scan-form");
const urlInput = document.getElementById("url");
const scanButton = document.getElementById("scan-button");
const errorBox = document.getElementById("error");
const resultSection = document.getElementById("result");

const STATUS_LABELS = { ok: "OK", warn: "WARN", missing: "MISSING", info: "INFO" };

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = urlInput.value.trim();
  if (!url) return;

  scanButton.disabled = true;
  scanButton.textContent = "Scanning…";
  errorBox.hidden = true;
  resultSection.hidden = true;

  try {
    const response = await fetch(`/api/scan?url=${encodeURIComponent(url)}`);
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || `scan failed (HTTP ${response.status})`);
    }
    render(data);
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.hidden = false;
  } finally {
    scanButton.disabled = false;
    scanButton.textContent = "Scan";
  }
});

function render(data) {
  const gradeEl = document.getElementById("grade");
  gradeEl.textContent = data.grade;
  gradeEl.className =
    "grade grade-" + (data.grade === "A+" ? "a-plus" : data.grade.toLowerCase());

  document.getElementById("final-url").textContent = data.final_url;
  document.getElementById("score").textContent =
    `Score ${data.score}/${data.max_score} · HTTP ${data.status_code}`;

  const tbody = document.querySelector("#findings tbody");
  tbody.replaceChildren();
  for (const finding of data.findings) {
    const row = document.createElement("tr");

    const headerCell = document.createElement("td");
    headerCell.className = "header-name";
    headerCell.textContent = finding.header;

    const statusCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "badge badge-" + finding.status;
    badge.textContent = STATUS_LABELS[finding.status] || finding.status;
    statusCell.appendChild(badge);

    const detailsCell = document.createElement("td");
    detailsCell.textContent = finding.message;
    if (finding.value) {
      const code = document.createElement("code");
      code.textContent = finding.value;
      detailsCell.appendChild(document.createElement("br"));
      detailsCell.appendChild(code);
    }

    row.append(headerCell, statusCell, detailsCell);
    tbody.appendChild(row);
  }

  const recBox = document.getElementById("recommendations");
  recBox.replaceChildren();
  const recommendations = data.findings.filter((f) => f.recommendation);
  if (recommendations.length > 0) {
    const heading = document.createElement("h2");
    heading.textContent = "Recommendations";
    recBox.appendChild(heading);

    const list = document.createElement("ol");
    for (const finding of recommendations) {
      const item = document.createElement("li");
      const name = document.createElement("strong");
      name.textContent = finding.header + ": ";
      item.appendChild(name);
      item.appendChild(document.createTextNode(finding.recommendation));
      list.appendChild(item);
    }
    recBox.appendChild(list);
  }

  resultSection.hidden = false;
}
