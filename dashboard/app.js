const API_BASE = window.VAJRA_API_BASE || "http://127.0.0.1:8000";
const state = { flows: [], alerts: [], selectedFlow: null, selectedAlert: null };

const $ = (selector) => document.querySelector(selector);
const formatNumber = (value) => typeof value === "number" ? value.toLocaleString() : "--";
const shortId = (value) => value ? `${value.slice(0, 12)}...` : "--";
const fetchJson = async (path) => {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
};

function setStatus(selector, label, status = "") {
  const node = $(selector); node.className = `status-chip ${status}`; node.querySelector("span").textContent = label;
}

function renderTraffic(data) {
  document.querySelector('[data-metric="packet_count"]').textContent = formatNumber(data.packet_count);
  document.querySelector('[data-metric="byte_count"]').textContent = formatNumber(data.byte_count);
  $("#last-seen").textContent = `LAST SEEN // ${data.last_seen || "NONE"}`;
  const protocols = data.protocol_distribution || {};
  $("#protocol-count").textContent = formatNumber(Object.keys(protocols).length);
  const total = Object.values(protocols).reduce((sum, value) => sum + value, 0);
  $("#protocol-bars").innerHTML = total ? Object.entries(protocols).map(([name, count]) => `
    <div class="bar-row"><span>${name}</span><div class="bar-track"><div class="bar-fill" style="width:${(count / total) * 100}%"></div></div><span>${formatNumber(count)} pkts</span></div>`).join("") : '<div class="empty-state">No observed traffic</div>';
}

function renderFlows(data) {
  state.flows = data.flows || [];
  $("#active-flow-count").textContent = formatNumber(data.active_flow_count);
  $("#flow-count-label").textContent = `${formatNumber(data.active_flow_count)} FLOWS`;
  const body = $("#flows-body");
  body.innerHTML = state.flows.length ? state.flows.map((flow, index) => `
    <tr data-flow-index="${index}"><td class="flow-id">${shortId(flow.flow_id)}</td><td class="direction">${flow.source_ip}:${flow.source_port ?? "-"} → ${flow.destination_ip}:${flow.destination_port ?? "-"}</td><td>${flow.protocol}</td><td>${formatNumber(flow.packet_count)}</td><td>${formatNumber(flow.byte_count)}</td><td>${flow.duration_seconds}s</td></tr>`).join("") : '<tr><td colspan="6"><div class="empty-state">No observed traffic</div></td></tr>';
  body.querySelectorAll("[data-flow-index]").forEach(row => row.addEventListener("click", () => selectFlow(state.flows[Number(row.dataset.flowIndex)], row)));
}

function selectFlow(flow, row) {
  document.querySelectorAll("#flows-body tr").forEach(node => node.classList.remove("selected")); row?.classList.add("selected"); state.selectedFlow = flow;
  $("#flow-detail").innerHTML = `<div class="detail-stack">${Object.entries({ "FLOW ID": flow.flow_id, "DIRECTION": `${flow.source_ip}:${flow.source_port ?? "-"} → ${flow.destination_ip}:${flow.destination_port ?? "-"}`, PROTOCOL: flow.protocol, FIRST_SEEN: flow.first_seen, LAST_SEEN: flow.last_seen, DURATION: `${flow.duration_seconds}s`, PACKETS: formatNumber(flow.packet_count), BYTES: formatNumber(flow.byte_count) }).map(([key, value]) => `<div class="detail-line"><label>${key}</label><span>${value}</span></div>`).join("")}</div>`;
}

function severityClass(severity) { return `severity-${(severity || "low").toLowerCase()}`; }
function alertCountLabel(count) { return `${formatNumber(count)} ${count === 1 ? "ALERT" : "ALERTS"}`; }
function renderAlerts(alerts) {
  state.alerts = alerts || [];
  $("#alert-count-label").textContent = alertCountLabel(state.alerts.length);
  $("#alerts-list").innerHTML = state.alerts.length ? state.alerts.map((alert, index) => `<div class="alert-item" data-alert-index="${index}"><div class="alert-top"><span class="alert-class">${alert.threat_class}</span><span class="severity ${severityClass(alert.severity)}">${alert.severity}</span></div><div class="alert-sub">${alert.timestamp} // ${shortId(alert.flow_id)} // SCORE ${alert.score}</div></div>`).join("") : '<div class="empty-state">No alerts observed</div>';
  document.querySelectorAll("[data-alert-index]").forEach(item => item.addEventListener("click", () => selectAlert(state.alerts[Number(item.dataset.alertIndex)], item)));
  renderThreatAnalytics(state.alerts);
}

function renderThreatAnalytics(alerts) {
  const analytics = $("#threat-analytics");
  if (!alerts.length) {
    analytics.innerHTML = '<div class="empty-state">No alerts observed</div>';
    return;
  }
  const threatCounts = {};
  const severityCounts = {};
  alerts.forEach(alert => {
    threatCounts[alert.threat_class] = (threatCounts[alert.threat_class] || 0) + 1;
    severityCounts[alert.severity] = (severityCounts[alert.severity] || 0) + 1;
  });
  const renderCounts = (title, values, className) => `<div class="analytics-block"><div class="analytics-title">${title}</div>${Object.entries(values).map(([name, count]) => `<div class="analytics-row"><span>${name}</span><strong class="${className ? `severity ${severityClass(name)}` : ""}">${formatNumber(count)}</strong></div>`).join("")}</div>`;
  analytics.innerHTML = `${renderCounts("THREAT CLASSES", threatCounts, false)}${renderCounts("SEVERITY STATES", severityCounts, true)}`;
}

function selectAlert(alert, node) {
  document.querySelectorAll("[data-alert-index]").forEach(item => item.classList.remove("selected")); node?.classList.add("selected"); state.selectedAlert = alert;
  const rows = { ALERT_ID: alert.alert_id, THREAT_CLASS: alert.threat_class, SEVERITY: alert.severity, SCORE: `${alert.score} (${alert.score_method})`, SOURCE: alert.detector_source, METHOD: alert.detection_method, EXPLANATION: alert.explanation, ...alert.feature_values, ...alert.evidence };
  $("#alert-detail").innerHTML = `<div class="detail-stack"><div class="evidence-list">${Object.entries(rows).map(([key, value]) => `<div class="evidence-row"><span>${key}</span><span>${typeof value === "object" ? JSON.stringify(value) : value}</span></div>`).join("")}</div></div>`;
}

function appendStream(alert) {
  const stream = $("#stream-list");
  if (alert.alert_id && stream.querySelector(`[data-stream-alert-id="${alert.alert_id}"]`)) return;
  if (stream.querySelector(".empty-state")) stream.innerHTML = "";
  const item = document.createElement("div"); item.className = "stream-item"; if (alert.alert_id) item.dataset.streamAlertId = alert.alert_id; item.innerHTML = `<div class="alert-top"><span class="alert-class">${alert.threat_class}</span><span class="alert-time">${alert.timestamp}</span></div><div class="alert-sub">${alert.explanation}</div>`; stream.prepend(item);
  while (stream.children.length > 20) stream.lastElementChild.remove();
}

function renderHistoricalStream(alerts) {
  alerts.slice().reverse().forEach(appendStream);
}

async function refresh() {
  try {
    const [health, selfTest, traffic, flows, alerts, detectors] = await Promise.all([fetchJson("/health"), fetchJson("/self-test"), fetchJson("/traffic/stats"), fetchJson("/flows/active"), fetchJson("/alerts/recent"), fetchJson("/detectors/stats")]);
    setStatus("#api-status", "API ONLINE", "ok"); $("#health-value").textContent = health.status.toUpperCase(); $("#health-detail").textContent = `v${health.version} // SELF-TEST ${selfTest.status.toUpperCase()}`; $("#ml-value").textContent = detectors.ml_status.replaceAll("_", " ").toUpperCase();
    renderTraffic(traffic); renderFlows(flows); renderAlerts(alerts); renderHistoricalStream(alerts); renderDetectors(detectors); $("#updated-at").textContent = `UPDATED // ${new Date().toISOString()}`;
  } catch (error) { setStatus("#api-status", "API OFFLINE", "error"); $("#health-value").textContent = "UNAVAILABLE"; $("#health-detail").textContent = error.message; }
}

function renderDetectors(data) { const entries = Object.entries(data.detectors || {}); $("#detectors-list").innerHTML = entries.length ? entries.map(([name, stats]) => `<div class="detector-item"><span class="detector-name">${name}</span><span class="detector-values">EVAL ${stats.evaluations} / EMIT ${stats.alerts_emitted} / DROP ${stats.alerts_suppressed}</span></div>`).join("") : '<div class="empty-state">No detector data</div>'; }

function connectStream() {
  const stream = new EventSource(`${API_BASE}/alerts/stream`);
  stream.onopen = () => setStatus("#stream-status", "STREAM LIVE", "ok");
  stream.onmessage = (event) => { try { const alert = JSON.parse(event.data); appendStream(alert); state.alerts.unshift(alert); renderAlerts(state.alerts.slice(0, 100)); } catch { /* Ignore malformed stream frames. */ } };
  stream.onerror = () => { setStatus("#stream-status", "STREAM DISCONNECTED", "error"); stream.close(); setTimeout(connectStream, 3000); };
}

$("#refresh-button").addEventListener("click", refresh); refresh(); connectStream(); setInterval(refresh, 5000);