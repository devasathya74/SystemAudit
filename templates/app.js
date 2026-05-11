(function () {
  const data = window.__AUDIT_DATA__ || {};
  const $ = (id) => document.getElementById(id);
  const sevColor = { SAFE: "#35d07f", WARNING: "#f3c74f", HIGH: "#ff963d", CRITICAL: "#ff4d5f", INFO: "#6da8ff" };

  function value(v, fallback = "Unknown") {
    if (v === null || v === undefined || v === "") return fallback;
    if (Array.isArray(v)) return v.join(", ");
    if (typeof v === "object") return JSON.stringify(v);
    return String(v);
  }

  function badge(severity) {
    const level = (severity || "INFO").toUpperCase();
    return `<span class="badge ${level}">${level}</span>`;
  }

  function renderCards(id, items) {
    const el = $(id);
    if (!el) return;
    el.innerHTML = items.map(([label, val]) => `<div class="data-item"><span>${label}</span><strong>${value(val)}</strong></div>`).join("");
  }

  function renderTable(id, columns, rows) {
    const el = $(id);
    if (!el) return;
    const body = rows && rows.length
      ? rows.map(row => `<tr>${columns.map(col => `<td>${col.render ? col.render(row) : value(row[col.key])}</td>`).join("")}</tr>`).join("")
      : `<tr><td colspan="${columns.length}">No records detected.</td></tr>`;
    el.innerHTML = `<thead><tr>${columns.map(col => `<th>${col.label}</th>`).join("")}</tr></thead><tbody>${body}</tbody>`;
  }

  function chart(id, type, labels, values, colors) {
    const el = $(id);
    if (!el || !window.Chart) return;
    new Chart(el, {
      type,
      data: { labels, datasets: [{ data: values, backgroundColor: colors, borderColor: colors, borderWidth: 1 }] },
      options: {
        responsive: true,
        plugins: { legend: { labels: { color: "#cbd6e0" } } },
        scales: type === "doughnut" ? {} : {
          x: { ticks: { color: "#91a0ae" }, grid: { color: "#23303c" } },
          y: { ticks: { color: "#91a0ae" }, grid: { color: "#23303c" }, beginAtZero: true, max: 100 }
        }
      }
    });
  }

  function renderOverview() {
    $("hostTitle").textContent = data.overview?.hostname || "Audit Report";
    $("runMeta").textContent = `${data.overview?.generatedAt || ""} | Admin: ${data.overview?.admin ? "Yes" : "No"} | Run: ${data.overview?.runId || ""}`;
    $("riskScore").textContent = data.risk?.overall ?? 0;
    $("riskSeverity").textContent = data.risk?.overallSeverity || "SAFE";
    $("metricGrid").innerHTML = [
      ["Security", data.risk?.security],
      ["Persistence", data.risk?.persistence],
      ["Stability", data.risk?.stability],
      ["Recommendations", data.overview?.recommendationCount]
    ].map(([label, val]) => `<div class="metric"><span>${label}</span><strong>${value(val, "0")}</strong></div>`).join("");
    $("exportJson")?.addEventListener("click", () => {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `${data.overview?.runId || "audit"}.json`;
      link.click();
      URL.revokeObjectURL(link.href);
    });
  }

  function renderStaticSections() {
    renderCards("systemGrid", [
      ["OS", data.system?.os],
      ["Build", data.system?.buildNumber],
      ["CPU", data.system?.cpuModel],
      ["GPU", data.system?.gpuModel],
      ["RAM", data.system?.installedRam],
      ["Uptime", data.system?.uptime],
      ["Secure Boot", data.system?.secureBoot],
      ["TPM Ready", data.system?.tpm?.ready],
      ["Architecture", data.system?.architecture]
    ]);
    renderCards("healthGrid", [
      ["System Source", data.health?.system?.collectionSource],
      ["RAM Source", data.health?.memory?.collectionSource],
      ["Disk Count", data.health?.disk?.diskCount],
      ["Volumes", data.health?.disk?.volumeCount],
      ["Low Space Volumes", data.health?.disk?.lowSpaceVolumes],
      ["High-Risk Ports", data.health?.ports?.highRisk],
      ["VBS", data.health?.security?.vbsEnabled],
      ["HVCI", data.health?.security?.hvci],
      ["Credential Guard", data.health?.security?.credentialGuard]
    ]);
    renderCards("securityGrid", [
      ["Defender Real-Time", data.security?.defender?.realTimeProtection],
      ["Firewall Profiles", (data.security?.firewall || []).map(f => `${f.Name}:${f.Enabled}`).join(", ")],
      ["UAC", data.security?.uacEnabled],
      ["SMBv1", data.security?.smb1],
      ["RDP Enabled", data.security?.rdpEnabled],
      ["Guest Enabled", data.security?.guestEnabled],
      ["Defender Exclusions", (data.security?.defenderExclusions || []).length],
      ["BitLocker Volumes", (data.security?.bitlocker || []).length],
      ["Execution Policies", (data.security?.executionPolicy || []).length]
    ]);
    renderCards("networkGrid", [
      ["Adapters", (data.network?.adapters || []).length],
      ["DNS Servers", data.network?.dnsServers],
      ["Gateways", data.network?.gateways],
      ["Public IP", data.network?.publicIp],
      ["Latency", data.network?.latencyMs ? `${data.network.latencyMs} ms` : null],
      ["DNS Resolution", data.network?.dnsResolution]
    ]);
    renderCards("applicationGrid", [
      ["Installed Apps", (data.applications || []).length],
      ["Risky Apps", (data.riskyApplications || []).length],
      ["Unknown Publishers", data.software?.unknownPublisherCount],
      ["Unsigned Suspicious", data.software?.unsignedSuspiciousCount],
      ["Crack Indicators", data.software?.crackIndicatorCount],
      ["Browser Extensions", (data.browserExtensions || []).length]
    ]);
    renderCards("trustGrid", [
      ["High Priority Services", data.trustAnalysis?.highPriorityServices],
      ["Trusted Services Collapsed", data.trustAnalysis?.collapsedTrustedServices],
      ["Unsigned Binaries", data.trustAnalysis?.unsignedBinaries],
      ["Microsoft Trusted Services", data.trustAnalysis?.microsoftTrustedServices],
      ["Threat Indicators", (data.threatIndicators || []).length],
      ["Persistence Items", (data.persistence || []).length]
    ]);
    renderCards("diffGrid", [
      ["Baseline", data.historicalDiff?.baseline || "No prior report"],
      ["New Services", (data.historicalDiff?.newServices || []).length],
      ["New Ports", (data.historicalDiff?.newPorts || []).length],
      ["New Drivers", (data.historicalDiff?.newDrivers || []).length],
      ["New Startup Items", (data.historicalDiff?.newStartup || []).length]
    ]);
  }

  function renderTables() {
    renderTable("diskTable", [
      { label: "Drive", key: "drive" }, { label: "Label", key: "label" }, { label: "FS", key: "fileSystem" },
      { label: "Health", key: "health" }, { label: "Size", key: "size" }, { label: "Free", key: "free" }, { label: "Free %", key: "freePercent" }
    ], data.disk?.volumes || []);
    renderTable("processTable", [
      { label: "Process", key: "name" }, { label: "PID", key: "pid" }, { label: "CPU", key: "cpu" }, { label: "Memory", key: "memory" }
    ], data.cpu?.topProcesses || []);
    renderTable("startupTable", [
      { label: "Severity", render: r => badge(r.severity) }, { label: "Type", key: "type" }, { label: "Name", key: "name" },
      { label: "Command", key: "command" }, { label: "Signature", key: "signatureStatus" }, { label: "Signals", render: r => value(r.riskSignals || []) }, { label: "Location", key: "location" }
    ], data.startup || []);
    renderTable("scheduledTaskTable", [
      { label: "Severity", render: r => badge(r.severity) }, { label: "Task", key: "name" }, { label: "Triggers", key: "triggers" },
      { label: "Hidden", key: "hidden" }, { label: "Action", key: "command" }, { label: "Signals", render: r => value(r.riskSignals || []) }
    ], data.scheduledTasks || []);
    renderTable("applicationsTable", [
      { label: "Severity", render: r => badge(r.severity) }, { label: "Name", key: "name" }, { label: "Version", key: "version" },
      { label: "Publisher", key: "publisher" }, { label: "Arch", key: "architecture" }, { label: "Running", key: "running" },
      { label: "Startup", key: "startupEnabled" }, { label: "Signed", key: "signatureStatus" }, { label: "Location", key: "installLocation" }
    ], data.applications || []);
    renderTable("servicePriorityTable", [
      { label: "Severity", render: r => badge(r.severity) }, { label: "Service", key: "name" }, { label: "State", key: "state" },
      { label: "Start", key: "startMode" }, { label: "Trust", key: "trustClassification" }, { label: "Score", key: "trustScore" },
      { label: "Signed", key: "signatureStatus" }, { label: "Signals", render: r => value(r.riskSignals || []) }, { label: "Path", key: "path" }
    ], data.highPriorityServices || data.services?.highPriorityServices || []);
    renderTable("unsignedTable", [
      { label: "Severity", render: r => badge(r.severity) }, { label: "Type", key: "type" }, { label: "Name", key: "name" },
      { label: "Trust Score", key: "trustScore" }, { label: "Path", key: "path" }
    ], data.unsignedBinaries || []);
    renderTable("processIntelTable", [
      { label: "Severity", render: r => badge(r.severity) }, { label: "Process", key: "name" }, { label: "PID", key: "pid" },
      { label: "Parent", key: "parentPid" }, { label: "User", key: "user" }, { label: "RAM", key: "ram" },
      { label: "Signed", key: "signatureStatus" }, { label: "Signals", render: r => value(r.riskSignals || []) }, { label: "Command", key: "commandLine" }
    ], data.processes || []);
    renderTable("driverTable", [
      { label: "Severity", render: r => badge(r.severity) }, { label: "Driver", key: "name" }, { label: "State", key: "status" },
      { label: "Start", key: "startType" }, { label: "Signed", key: "signatureStatus" }, { label: "Vendor", key: "vendor" },
      { label: "Signals", render: r => value(r.riskSignals || []) }, { label: "Path", key: "path" }
    ], data.drivers || []);
    renderTable("browserExtensionTable", [
      { label: "Severity", render: r => badge(r.severity) }, { label: "Browser", key: "browser" }, { label: "Extension", key: "name" },
      { label: "Version", key: "version" }, { label: "Permissions", render: r => value(r.permissions || []) },
      { label: "Host Access", render: r => value(r.hostPermissions || []) }, { label: "Signals", render: r => value(r.riskSignals || []) }
    ], data.browserExtensions || []);
    renderTable("persistenceTable", [
      { label: "Severity", render: r => badge(r.severity) }, { label: "Type", key: "type" }, { label: "Name", key: "name" },
      { label: "Command/ID", key: "command" }, { label: "Signals", render: r => value(r.riskSignals || []) }, { label: "Location", key: "location" }
    ], data.persistence || []);
    renderTable("eventTable", [
      { label: "Event ID", key: "eventId" }, { label: "Count", key: "count" }, { label: "Summary", key: "sample" }
    ], data.eventLogs?.summary || []);
    const diffRows = [
      ...(data.historicalDiff?.newServices || []).map(x => ({ type: "Service", name: x.name, detail: x.path || x.displayName, severity: x.severity || "INFO" })),
      ...(data.historicalDiff?.newPorts || []).map(x => ({ type: "Port", name: `${x.protocol}/${x.port}`, detail: x.process, severity: x.severity || "INFO" })),
      ...(data.historicalDiff?.newDrivers || []).map(x => ({ type: "Driver", name: x.name, detail: x.path, severity: x.severity || "INFO" })),
      ...(data.historicalDiff?.newStartup || []).map(x => ({ type: "Startup", name: x.name, detail: x.command, severity: x.severity || "INFO" }))
    ];
    renderTable("diffTable", [
      { label: "Severity", render: r => badge(r.severity) }, { label: "Type", key: "type" }, { label: "Name", key: "name" }, { label: "Detail", key: "detail" }
    ], diffRows);
    renderTable("malwareTable", [
      { label: "Severity", render: r => badge(r.severity) }, { label: "Type", key: "type" }, { label: "Name", key: "name" },
      { label: "Signals", render: r => value(r.riskSignals || []) }, { label: "Detail", key: "detail" }
    ], data.threatIndicators || data.malwareIndicators || []);
    renderTable("correlationTable", [
      { label: "Severity", render: r => badge(r.severity) }, { label: "Process", key: "process" }, { label: "PID", key: "pid" },
      { label: "Application", key: "application" }, { label: "Resource", key: "resource" }, { label: "Startup", key: "loadsAtStartup" },
      { label: "Signature", key: "signatureStatus" }, { label: "Explanation", key: "explanation" }
    ], data.performanceCorrelations || []);
  }

  function renderFilteredPorts() {
    const term = ($("portSearch").value || "").toLowerCase();
    const severity = $("portSeverity").value;
    const rows = (data.ports || []).filter(p => {
      const haystack = `${p.protocol} ${p.localAddress} ${p.port} ${p.process} ${p.service}`.toLowerCase();
      return (!term || haystack.includes(term)) && (!severity || p.severity === severity);
    });
    renderTable("portsTable", [
      { label: "Severity", render: r => badge(r.severity) }, { label: "Protocol", key: "protocol" }, { label: "Address", key: "localAddress" },
      { label: "Port", key: "port" }, { label: "Exposure", key: "exposure" }, { label: "Process", key: "process" }, { label: "PID", key: "pid" }, { label: "Service", key: "service" }
    ], rows);
  }

  function renderRecommendations() {
    const term = ($("recSearch").value || "").toLowerCase();
    const severity = $("recSeverity").value;
    const rows = (data.recommendations || []).filter(r => {
      const haystack = `${r.issue} ${r.description} ${r.impact} ${r.recommendation}`.toLowerCase();
      return (!term || haystack.includes(term)) && (!severity || r.severity === severity);
    });
    $("recommendationList").innerHTML = rows.length ? rows.map(r => `
      <article class="recommendation" style="border-left-color:${sevColor[r.severity] || sevColor.INFO}">
        ${badge(r.severity)}
        <h3>${value(r.issue)}</h3>
        <p><strong>Description:</strong> ${value(r.description)}</p>
        <p><strong>Impact:</strong> ${value(r.impact)}</p>
        <p><strong>Recommendation:</strong> ${value(r.recommendation)}</p>
        ${r.fix ? `<code class="fix">${value(r.fix)}</code>` : ""}
      </article>
    `).join("") : "<p class='muted'>No recommendations match the active filter.</p>";
  }

  function renderCharts() {
    const risk = data.risk?.overall || 0;
    chart("riskChart", "doughnut", ["Risk", "Remaining"], [risk, 100 - risk], [sevColor[data.risk?.overallSeverity] || sevColor.SAFE, "#25313d"]);
    chart("cpuChart", "bar", ["CPU"], [data.cpu?.usagePercent || 0], [sevColor.INFO]);
    chart("ramChart", "bar", ["RAM"], [data.ram?.usedPercent || 0], [sevColor.WARNING]);
    const diskRows = data.disk?.volumes || [];
    chart("diskChart", "bar", diskRows.map(d => d.drive), diskRows.map(d => 100 - (d.freePercent || 0)), diskRows.map(() => sevColor.HIGH));
    const dist = data.risk?.severityDistribution || {};
    chart("severityChart", "doughnut", ["Safe", "Warning", "High", "Critical"], [dist.SAFE || 0, dist.WARNING || 0, dist.HIGH || 0, dist.CRITICAL || 0], [sevColor.SAFE, sevColor.WARNING, sevColor.HIGH, sevColor.CRITICAL]);
  }

  function renderTimeline() {
    const el = $("persistenceTimeline");
    if (!el) return;
    el.innerHTML = (data.persistenceTimeline || []).map(step => `
      <div class="timeline-step">
        <span>${value(step.phase)}</span>
        <strong>${value(step.count, "0")}</strong>
        <p>${value(step.description)}</p>
      </div>
    `).join("");
  }

  function renderLogs() {
    $("logView").textContent = (data.logs || []).map(l => `[${l.timestamp}] [${l.level}] ${l.message}`).join("\n") || "No logs embedded.";
  }

  renderOverview();
  renderStaticSections();
  renderTables();
  renderFilteredPorts();
  renderRecommendations();
  renderCharts();
  renderTimeline();
  renderLogs();
  ["portSearch", "portSeverity"].forEach(id => $(id).addEventListener("input", renderFilteredPorts));
  ["recSearch", "recSeverity"].forEach(id => $(id).addEventListener("input", renderRecommendations));
})();
