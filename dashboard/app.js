const API_BASE_URL = "https://sih25orneb.execute-api.eu-north-1.amazonaws.com";
const STATE_INTERVAL_MS = 1500;
const HEALTH_INTERVAL_MS = 4000;
const AGENTS = ["agent_a", "agent_b", "attacker"];
const $ = (selector) => document.querySelector(selector);
const endpoint = (path) => `${API_BASE_URL.replace(/\/$/, "")}${path}`;

async function request(path, options = {}) {
  const response = await fetch(endpoint(path), { headers: { "Content-Type": "application/json", ...(options.headers || {}) }, ...options });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || body.error || `${response.status}`);
  return body;
}
function showControl(value, failed = false) { const output = $("#control-result"); output.textContent = value; output.classList.toggle("failed", failed); }
function formatTime(timestamp) { return timestamp ? new Date(timestamp * 1000).toLocaleTimeString() : "—"; }

function renderFeed(records) {
  const feed = $("#feed"); feed.replaceChildren();
  const newestFirst = [...records].sort((a, b) => b.timestamp - a.timestamp);
  $("#feed-count").textContent = newestFirst.length;
  for (const record of newestFirst) {
    const row = document.createElement("tr"); row.className = "feed-row";
    row.innerHTML = `<td>${formatTime(record.timestamp)}</td><td>${record.issuer}</td><td>${record.action}</td><td>${record.reason_code === "ACCEPTED" ? "—" : record.reason_code}</td><td>${record.result}</td>`;
    const detail = document.createElement("tr"); detail.className = "raw-row"; detail.hidden = true;
    detail.innerHTML = `<td colspan="5"><pre>${JSON.stringify(record, null, 2)}</pre></td>`;
    row.addEventListener("click", () => { detail.hidden = !detail.hidden; }); feed.append(row, detail);
  }
}
function renderAgents(reputation, agentStatus) {
  const container = $("#agent-cards"); container.replaceChildren();
  for (const agent of AGENTS) {
    const data = reputation[agent] || {}; const card = document.createElement("article"); card.className = "agent-card";
    card.innerHTML = `<div class="agent-name">${agent}</div><dl><div><dt>SCORE</dt><dd>${data.score ?? "—"}</dd></div><div><dt>STATUS</dt><dd>${agentStatus[agent] ?? "unknown"}</dd></div><div><dt>REVIEW</dt><dd>${data.requires_review ? "YES" : "NO"}</dd></div></dl>`;
    container.append(card);
  }
}
async function pollHealth() {
  try { const health = await request("/health"); $("#health-dot").classList.toggle("healthy", health.status === "healthy"); $("#health-status").textContent = health.status; $("#latency").textContent = `${Math.round(health.latency_ms)} ms`; $("#region").textContent = health.region; $("#environment").textContent = health.environment; }
  catch { $("#health-dot").classList.remove("healthy"); $("#health-status").textContent = "offline"; }
}
async function pollState() { try { const state = await request("/dashboard/state"); renderFeed(state.audit_feed || []); renderAgents(state.reputation || {}, state.agent_status || {}); } catch (error) { showControl(error.message, true); } }

$("#send-valid").addEventListener("click", async () => { try { const result = await request("/demo/send-valid", { method: "POST" }); showControl(result.reason_code); pollState(); } catch (error) { showControl(error.message, true); } });
$("#run-attacks").addEventListener("click", async () => { try { const selected = $("#attack-select").value; const body = selected === "all" ? {} : { attacks: [selected] }; const result = await request("/redteam/run", { method: "POST", body: JSON.stringify(body) }); const passed = result.results.filter((item) => item.passed).length; showControl(`${passed}/${result.results.length}`); pollState(); } catch (error) { showControl(error.message, true); } });
$("#revoke-agent").addEventListener("click", async () => { try { const result = await request("/agents/agent_a/revoke", { method: "POST", body: JSON.stringify({ reason: "dashboard" }) }); showControl(result.status); pollState(); } catch (error) { showControl(error.message, true); } });
$("#fire-concurrent").addEventListener("click", async () => { const requests = Array.from({ length: 20 }, (_, index) => index >= 18 ? request("/redteam/run", { method: "POST", body: JSON.stringify({ attacks: ["attack_tampered_action"] }) }) : request("/demo/send-valid", { method: "POST" })); const results = await Promise.allSettled(requests); showControl(`${results.filter((result) => result.status === "fulfilled").length}/20`); pollState(); });
pollHealth(); pollState(); setInterval(pollHealth, HEALTH_INTERVAL_MS); setInterval(pollState, STATE_INTERVAL_MS);
