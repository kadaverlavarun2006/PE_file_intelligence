(() => {
  "use strict";

  const MAX_FILE_SIZE = 100 * 1024 * 1024;
  const HISTORY_KEY = "sentinel-pe-history-v1";
  const input = document.getElementById("file-input");
  const dropZone = document.getElementById("drop-zone");
  const analyzeButton = document.getElementById("analyze-button");
  const selectedFileView = document.getElementById("selected-file");
  const errorView = document.getElementById("inline-error");
  const toast = document.getElementById("toast");
  let selectedFile = null;
  let currentReport = null;
  let summaryEnabled = false;
  let toastTimer;
  let currentScanToken = 0;

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    const units = ["KB", "MB", "GB"];
    let value = bytes / 1024;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[unit]}`;
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, character => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    })[character]);
  }

  function showError(message) {
    errorView.textContent = message;
    errorView.hidden = false;
  }

  function clearError() {
    errorView.textContent = "";
    errorView.hidden = true;
  }

  function notify(message) {
    toast.textContent = message;
    toast.classList.add("show");
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => toast.classList.remove("show"), 3200);
  }

  function setFile(file) {
    clearError();
    if (!file) return;
    const extension = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
    if (![".exe", ".dll"].includes(extension)) {
      selectedFile = null;
      selectedFileView.hidden = true;
      analyzeButton.disabled = true;
      showError("Only .exe and .dll files are supported.");
      return;
    }
    if (file.size > MAX_FILE_SIZE) {
      selectedFile = null;
      selectedFileView.hidden = true;
      analyzeButton.disabled = true;
      showError("This file exceeds the 100 MB size limit.");
      return;
    }
    selectedFile = file;
    selectedFileView.replaceChildren();
    const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    icon.setAttribute("viewBox", "0 0 24 24");
    icon.innerHTML = '<path d="M6 3h8l5 5v13H6z"/><path d="M14 3v6h5M9 13h7m-7 4h7"/>';
    const name = document.createElement("span");
    name.className = "selected-file-name";
    name.textContent = file.name;
    const size = document.createElement("span");
    size.className = "selected-file-size";
    size.textContent = formatBytes(file.size);
    const remove = document.createElement("button");
    remove.className = "remove-file";
    remove.type = "button";
    remove.setAttribute("aria-label", "Remove selected file");
    remove.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg>';
    remove.addEventListener("click", clearSelectedFile);
    selectedFileView.append(icon, name, size, remove);
    selectedFileView.hidden = false;
    analyzeButton.disabled = false;
  }

  function clearSelectedFile(event) {
    if (event) event.stopPropagation();
    currentScanToken += 1;
    selectedFile = null;
    input.value = "";
    selectedFileView.hidden = true;
    selectedFileView.replaceChildren();
    analyzeButton.disabled = true;
    analyzeButton.classList.remove("loading");
    analyzeButton.querySelector("span:nth-child(2)").textContent = "Analyze file";
    clearError();
  }

  function renderReport(report, scannedAt) {
    const results = document.getElementById("results-section");
    const verdictLabels = {
      low: ["LOW RISK", "No strong signals", "No high-signal indicators were found by the selected static checks. This is not proof that the file is safe."],
      medium: ["ELEVATED RISK", "Review recommended", "Some indicators deserve further investigation. This heuristic result is not a malware verdict."],
      high: ["HIGHER RISK", "Caution advised", "Multiple concerning indicators were found. Treat this file cautiously and seek a trusted security analysis."],
      critical: ["CRITICAL SIGNAL", "Immediate review advised", "The heuristic score is very high. This is still not proof of malware; handle the file cautiously and seek trusted security analysis."]
    };
    const risk = ["low", "medium", "high", "critical"].includes(report.severity || report.risk) ? (report.severity || report.risk) : "low";
    const score = Math.max(0, Math.min(100, Number(report.score) || 0));
    const colors = { low: "#4bd3a3", medium: "#eabd65", high: "#fa737f", critical: "#ff5367" };
    const [label, title, description] = verdictLabels[risk];
    const resultStatus = document.getElementById("result-status");
    resultStatus.className = `result-status ${risk}`;
    resultStatus.textContent = risk === "low" ? "LOW" : risk === "medium" ? "MEDIUM" : risk === "high" ? "HIGH" : "CRITICAL";
    document.getElementById("verdict-label").textContent = label;
    document.getElementById("verdict-title").textContent = title;
    document.getElementById("verdict-title").style.color = colors[risk];
    document.getElementById("verdict-description").textContent = description;
    document.getElementById("risk-score").textContent = score;
    const ring = document.getElementById("risk-ring");
    ring.style.setProperty("--score-angle", `${score}%`);
    ring.style.setProperty("--ring-color", colors[risk]);
    document.getElementById("risk-marker").style.left = `${Math.max(2, Math.min(98, score))}%`;
    document.getElementById("file-size-result").textContent = formatBytes(report.file_size);
    document.getElementById("result-file-name").textContent = report.file_name;
    document.getElementById("detail-type").textContent = report.is_dll ? "Windows PE · DLL" : "Windows PE · Executable";
    document.getElementById("detail-size").textContent = formatBytes(report.file_size);
    document.getElementById("detail-arch").textContent = report.architecture;
    document.getElementById("detail-entry").textContent = `RVA 0x${Number(report.entry_point.rva).toString(16).toUpperCase()} · VA 0x${Number(report.entry_point.va).toString(16).toUpperCase()}`;
    document.getElementById("detail-sections").textContent = String(report.section_count);
    document.getElementById("detail-hash").textContent = report.sha256;
    document.getElementById("scan-time").textContent = `SCANNED ${new Date(scannedAt).toLocaleString()}`;
    document.getElementById("indicator-bars").innerHTML = report.indicators.map(item => {
      const value = Math.max(0, Math.min(100, Number(item.value) || 0));
      const level = ["normal", "warning", "alert"].includes(item.level) ? item.level : "normal";
      return `<div class="indicator ${level}"><div class="indicator-top"><span>${escapeHtml(item.name)}</span><strong>${value}</strong></div><div class="indicator-track"><span style="width:${value}%"></span></div></div>`;
    }).join("");
    document.getElementById("findings-count").textContent = `${report.findings.filter(item => item.triggered).length} TRIGGERED · ${report.findings.length} RULES`;
    document.getElementById("findings-list").innerHTML = report.findings.map(item => {
      const level = item.triggered ? (item.score_impact >= 18 ? "alert" : "warning") : "info";
      return `<li class="${item.triggered ? "finding-triggered" : ""}"><span class="finding-dot ${level}"></span><span><strong>${escapeHtml(item.title)}:</strong> ${escapeHtml(item.explanation)}</span><span class="finding-impact">${item.triggered ? `+${item.score_impact}` : "0"}</span></li>`;
    }).join("");

    document.getElementById("sections-body").innerHTML = report.sections.length ? report.sections.map(section => `
      <tr><td>${escapeHtml(section.name)}</td><td>0x${Number(section.virtual_address).toString(16).toUpperCase()}</td>
      <td>${formatBytes(section.virtual_size)}</td><td>${formatBytes(section.raw_size)}</td><td>${Number(section.entropy).toFixed(3)}</td></tr>`).join("") :
      '<tr><td colspan="5" class="empty-data">No section records found.</td></tr>';
    const importCount = report.imports.length;
    document.getElementById("import-count").textContent = `${importCount} DLL${importCount === 1 ? "" : "S"}`;
    document.getElementById("imports-list").innerHTML = importCount ? report.imports.map(library => `
      <details class="import-library"><summary><span>${escapeHtml(library.dll)}</span><span>${library.functions.length} FUNCTIONS</span></summary>
      <div class="function-list">${library.functions.length ? library.functions.map(item => `<code>${escapeHtml(item.name || `Ordinal ${item.ordinal}`)}</code>`).join("") : '<span class="empty-data">No named imports.</span>'}</div></details>`).join("") :
      '<div class="empty-data imports-empty">No imported DLLs were listed in the PE import directory.</div>';

    currentReport = report;
    document.getElementById("summary-output").hidden = true;
    document.getElementById("summary-output").textContent = "";
    document.getElementById("summary-message").textContent = summaryEnabled
      ? "Optional: generate a plain-language explanation of the extracted evidence."
      : "AI summary is disabled. Configure the optional API key on the Flask server to enable it.";
    results.hidden = false;
    results.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function getHistory() {
    try {
      const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
      return Array.isArray(history) ? history.filter(item => item && typeof item.fileName === "string" && typeof item.scannedAt === "number") : [];
    } catch {
      notify("Could not read saved scan history from this browser.");
      return [];
    }
  }

  function saveHistory(history) {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 20)));
    } catch {
      notify("Scan completed, but browser storage could not save the history.");
    }
  }

  function renderHistory() {
    const history = getHistory();
    const body = document.getElementById("history-body");
    const empty = document.getElementById("empty-history");
    const table = document.querySelector(".history-table-wrap");
    document.getElementById("clear-history").hidden = history.length === 0;
    empty.hidden = history.length > 0;
    table.hidden = history.length === 0;
    body.innerHTML = history.map(item => {
      const risk = ["low", "medium", "high", "critical"].includes(item.risk) ? item.risk : "low";
      const date = new Date(item.scannedAt);
      const dateLabel = Number.isNaN(date.getTime()) ? "Unknown date" : date.toLocaleString();
      const score = Number.isFinite(Number(item.score)) ? Math.max(0, Math.min(100, Math.round(Number(item.score)))) : 0;
      const status = risk === "low" ? "LOW" : risk === "medium" ? "MEDIUM" : risk === "high" ? "HIGH" : "CRITICAL";
      return `<tr><td><span class="history-file"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3h8l5 5v13H6z"/><path d="M14 3v6h5"/></svg>${escapeHtml(item.fileName)}</span></td><td>${escapeHtml(dateLabel)}</td><td>${escapeHtml(formatBytes(Number(item.size) || 0))}</td><td><span class="history-risk ${risk}">${score}/100</span></td><td><span class="status-pill ${risk === "low" ? "" : risk}">${status}</span></td></tr>`;
    }).join("");
    const safeCount = history.filter(item => item.risk === "low").length;
    document.getElementById("sidebar-total").textContent = String(history.length);
    document.getElementById("sidebar-safe").textContent = String(safeCount);
    document.getElementById("sidebar-flagged").textContent = String(history.length - safeCount);
  }

  async function analyzeSelectedFile() {
    if (!selectedFile) return;
    const file = selectedFile;
    const token = ++currentScanToken;
    clearError();
    analyzeButton.disabled = true;
    analyzeButton.classList.add("loading");
    analyzeButton.querySelector("span:nth-child(2)").textContent = "Analyzing…";
    try {
      const formData = new FormData();
      formData.append("file", file, file.name);
      const response = await fetch("/api/analyze", { method: "POST", body: formData });
      const result = await response.json().catch(() => ({}));
      if (token !== currentScanToken) return;
      if (!response.ok) throw new Error(result.error || `Analysis failed with HTTP ${response.status}.`);
      const scannedAt = Date.now();
      renderReport(result, scannedAt);
      const history = getHistory();
      history.unshift({
        fileName: result.file_name,
        size: result.file_size,
        score: result.score,
        risk: result.risk,
        scannedAt
      });
      saveHistory(history);
      renderHistory();
    } catch (error) {
      if (token !== currentScanToken) return;
      const message = error instanceof Error && error.message === "Failed to fetch"
        ? "Could not connect to the local Flask server. Start it with your Python interpreter and try again."
        : error instanceof Error ? error.message : "An unexpected error occurred while analyzing this file.";
      showError(message);
      notify(message);
    } finally {
      if (token === currentScanToken) {
        analyzeButton.disabled = !selectedFile;
        analyzeButton.classList.remove("loading");
        analyzeButton.querySelector("span:nth-child(2)").textContent = "Analyze file";
      }
    }
  }

  async function loadSummaryAvailability() {
    const button = document.getElementById("summary-button");
    const message = document.getElementById("summary-message");
    try {
      const response = await fetch("/api/status");
      const status = await response.json();
      if (!response.ok) throw new Error(status.error || `Server returned HTTP ${response.status}.`);
      summaryEnabled = status.llm_summary_enabled === true;
      button.disabled = !summaryEnabled;
      button.textContent = summaryEnabled ? "Generate AI explanation" : "AI summary not configured";
      message.textContent = summaryEnabled
        ? "Optional: generate a plain-language explanation. Only extracted evidence—not the binary, filename, or hash—is sent to the configured API."
        : "Optional LLM summary is off. Set SENTINEL_LLM_API_KEY on the Flask server and restart it to enable.";
    } catch {
      summaryEnabled = false;
      button.disabled = true;
      button.textContent = "AI summary unavailable";
      message.textContent = "Could not check the local Flask server's optional summary configuration.";
      message.classList.add("error");
    }
  }

  async function summarizeCurrentReport() {
    if (!summaryEnabled || !currentReport) return;
    const button = document.getElementById("summary-button");
    const message = document.getElementById("summary-message");
    const output = document.getElementById("summary-output");
    button.disabled = true;
    button.textContent = "Generating…";
    message.classList.remove("error");
    message.textContent = "Sending extracted evidence to the configured LLM service…";
    output.hidden = true;
    try {
      const response = await fetch("/api/summarize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report: currentReport })
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Summary failed with HTTP ${response.status}.`);
      output.textContent = result.summary;
      output.hidden = false;
      message.textContent = "AI-generated explanation of heuristic evidence; it is not a malware verdict.";
    } catch (error) {
      message.textContent = error instanceof Error ? error.message : "Could not generate the optional summary.";
      message.classList.add("error");
    } finally {
      button.disabled = !summaryEnabled;
      button.textContent = "Generate AI explanation";
    }
  }

  document.getElementById("browse-button").addEventListener("click", event => {
    event.stopPropagation();
    input.click();
  });
  dropZone.addEventListener("click", event => {
    if (!event.target.closest("button")) input.click();
  });
  dropZone.addEventListener("keydown", event => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      input.click();
    }
  });
  input.addEventListener("change", () => setFile(input.files && input.files[0]));
  ["dragenter", "dragover"].forEach(type => dropZone.addEventListener(type, event => {
    event.preventDefault();
    dropZone.classList.add("dragging");
  }));
  ["dragleave", "drop"].forEach(type => dropZone.addEventListener(type, event => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
  }));
  dropZone.addEventListener("drop", event => setFile(event.dataTransfer && event.dataTransfer.files[0]));
  analyzeButton.addEventListener("click", analyzeSelectedFile);
  document.getElementById("summary-button").addEventListener("click", summarizeCurrentReport);
  document.getElementById("clear-history").addEventListener("click", () => {
    try {
      localStorage.removeItem(HISTORY_KEY);
      renderHistory();
      notify("Scan history cleared.");
    } catch {
      notify("Could not clear scan history from browser storage.");
    }
  });
  renderHistory();
  loadSummaryAvailability();
})();
