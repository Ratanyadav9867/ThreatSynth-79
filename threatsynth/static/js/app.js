/**
 * ThreatSynth 79 Frontend Application Logic
 * Manages Real-Time Triage, RBAC Identity Switching, SHAP Explainability Charts & Audit Stream.
 */

// Application State
let currentRole = "soc_analyst";
let currentToken = "";
let currentAlerts = [];
let selectedAlertId = null;
let currentFilter = "";
let shapChartInstance = null;

// User Identity Profiles
const USER_PROFILES = {
  soc_analyst: {
    username: "soc_analyst",
    role: "soc_analyst",
    displayName: "Alice Chen, CISSP",
    badgeTitle: "SOC ANALYST (L2)",
    statusText: "Authorized: Full Forensic Telemetry, SHAP Weights & AI Playbooks",
    color: "cyan"
  },
  admin: {
    username: "admin",
    role: "admin",
    displayName: "Commander Sarah Vance",
    badgeTitle: "SOC ADMINISTRATOR",
    statusText: "Full Authority: Ingestion, Model Retraining, Policy & Audit Export",
    color: "indigo"
  },
  tier1_viewer: {
    username: "tier1_viewer",
    role: "tier1_viewer",
    displayName: "Bob Martinez (Tier 1)",
    badgeTitle: "TIER 1 SUPPORT (REDACTED)",
    statusText: "Limited Read Access: Sensitive Threat Payloads & Forensic Summaries Redacted",
    color: "amber"
  },
  unauthorized_guest: {
    username: "unauthorized_guest",
    role: "unauthorized_guest",
    displayName: "Charlie Guest (External)",
    badgeTitle: "UNAUTHORIZED GUEST",
    statusText: "Access Restricted: Blocked with 403 Forbidden on Sensitive Endpoints",
    color: "rose"
  }
};

// Initialize Application
document.addEventListener("DOMContentLoaded", async () => {
  await switchUserRole("soc_analyst");
  await refreshDashboard();
  loadModelMetrics();

  // Auto-refresh audit trail and feed every 15 seconds
  setInterval(() => {
    loadAuditLogs();
    loadCorrelations();
  }, 15000);
});

/**
 * Switch Active User Persona / Identity to test RBAC in Real Time
 */
async function switchUserRole(role) {
  currentRole = role;
  const profile = USER_PROFILES[role] || USER_PROFILES["unauthorized_guest"];

  // Authenticate against Mock IdP / OAuth2 Stub
  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: profile.username })
    });
    const data = await res.json();
    currentToken = data.access_token;
  } catch (e) {
    console.error("Auth error:", e);
    currentToken = role; // Fallback
  }

  // Update UI Header Buttons
  document.querySelectorAll(".role-btn").forEach(btn => {
    btn.classList.remove("active", "bg-cyan-600", "bg-indigo-600", "bg-amber-600", "bg-rose-600", "text-white");
    btn.classList.add("text-slate-400");
  });

  const activeBtn = document.getElementById(`btnRole-${role}`);
  if (activeBtn) {
    activeBtn.classList.remove("text-slate-400");
    if (role === "soc_analyst") activeBtn.classList.add("bg-cyan-600", "text-white");
    else if (role === "admin") activeBtn.classList.add("bg-indigo-600", "text-white");
    else if (role === "tier1_viewer") activeBtn.classList.add("bg-amber-600", "text-white");
    else activeBtn.classList.add("bg-rose-600", "text-white");
    activeBtn.classList.add("active");
  }

  // Update Status Banner
  document.getElementById("currentRoleBadge").textContent = profile.badgeTitle;
  document.getElementById("currentRoleBadge").className = `text-xs font-bold font-mono uppercase text-${profile.color}-400`;
  document.getElementById("currentRoleStatus").textContent = profile.statusText;

  // Refresh Feed and Re-inspect Current Alert under new RBAC permissions
  await loadAlerts();
  await loadAuditLogs();
  await loadCorrelations();

  if (selectedAlertId) {
    inspectAlert(selectedAlertId);
  }
}

/**
 * Fetch and Render Alert Stream
 */
async function loadAlerts() {
  const container = document.getElementById("alertsListContainer");
  const startTime = performance.now();

  try {
    const url = currentFilter ? `/api/alerts?risk=${currentFilter}` : `/api/alerts`;
    const res = await fetch(url, {
      headers: { "Authorization": `Bearer ${currentToken}` }
    });
    const data = await res.json();
    currentAlerts = data.alerts || [];

    const latency = Math.round(performance.now() - startTime);
    document.getElementById("latencyIndicator").textContent = `${latency}ms (Live)`;

    updateKPIs(currentAlerts);
    renderAlertCards(currentAlerts);
  } catch (e) {
    container.innerHTML = `<div class="p-6 text-center text-rose-400 font-mono">Error fetching alerts: ${e.message}</div>`;
  }
}

/**
 * Update Top KPI Counters
 */
function updateKPIs(alerts) {
  document.getElementById("statTotal").textContent = alerts.length;
  document.getElementById("statHigh").textContent = alerts.filter(a => a.risk_level === "High").length;
  document.getElementById("statMedium").textContent = alerts.filter(a => a.risk_level === "Medium").length;
  document.getElementById("statLow").textContent = alerts.filter(a => a.risk_level === "Low").length;
}

/**
 * Render Feed Cards in Left Column
 */
function renderAlertCards(alerts) {
  const container = document.getElementById("alertsListContainer");
  if (!alerts || alerts.length === 0) {
    container.innerHTML = `<div class="p-10 text-center text-slate-500 font-mono">No alerts matching filter '${currentFilter || "All"}'.</div>`;
    return;
  }

  container.innerHTML = alerts.map(alert => {
    const isHigh = alert.risk_level === "High";
    const isMed = alert.risk_level === "Medium";
    const isLow = alert.risk_level === "Low";

    const badgeColor = isHigh ? "bg-rose-950 text-rose-400 border-rose-800" :
                       isMed ? "bg-amber-950 text-amber-400 border-amber-800" :
                       "bg-emerald-950 text-emerald-400 border-emerald-800";

    const pulseClass = isHigh ? "critical-pulse border-rose-900/80" : "border-slate-800/90";
    const activeClass = selectedAlertId === alert.alert_id ? "active ring-1 ring-cyan-400" : "";
    const isCorrelated = alert.correlation && alert.correlation.has_correlation;

    const timeStr = alert.timestamp ? alert.timestamp.substring(11, 19) : "12:00:00";
    const anomaly = alert.anomaly_score ? alert.anomaly_score.toFixed(2) : "0.00";
    const confidence = alert.confidence ? Math.round(alert.confidence * 100) : 95;

    return `
      <div onclick="inspectAlert('${alert.alert_id}')" 
           class="alert-card p-4 rounded-xl bg-slate-900/90 border ${pulseClass} ${activeClass} cursor-pointer space-y-2.5">
        
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 text-[10px] font-bold font-mono uppercase rounded border ${badgeColor}">
              ${alert.risk_level} RISK
            </span>
            ${isCorrelated ? `<span class="px-1.5 py-0.5 text-[9px] font-mono rounded bg-indigo-950 text-indigo-300 border border-indigo-800 flex items-center gap-1"><i data-lucide="git-merge" class="w-3 h-3"></i> CHAIN</span>` : ''}
            <span class="text-xs font-mono text-slate-400">${alert.alert_id}</span>
          </div>
          <span class="text-[11px] font-mono text-slate-500">${timeStr} UTC</span>
        </div>

        <div>
          <h4 class="text-sm font-semibold text-white tracking-tight">${alert.alert_name || alert.title || 'Security Anomaly Event'}</h4>
          <p class="text-xs text-slate-400 font-mono mt-0.5 truncate">${alert.resource || alert.endpoint || 'API Gateway'} &bull; User: <span class="text-cyan-300">${alert.username || 'unknown'}</span></p>
        </div>

        <div class="flex items-center justify-between pt-1 border-t border-slate-800/80 text-[11px] font-mono">
          <div class="flex items-center gap-3">
            <span class="text-slate-400">Anomaly Index: <b class="${isHigh ? 'text-rose-400' : 'text-slate-300'}">${anomaly}</b></span>
            <span class="text-slate-400">ML Conf: <b class="text-slate-300">${confidence}%</b></span>
          </div>
          <span class="text-cyan-400 flex items-center gap-1 hover:underline text-[11px]">
            Inspect <i data-lucide="chevron-right" class="w-3 h-3"></i>
          </span>
        </div>

      </div>
    `;
  }).join("");

  lucide.createIcons();
}

/**
 * Deep-Dive Alert Inspection with Strict RBAC Enforcement & SHAP Chart Rendering
 */
async function inspectAlert(alertId) {
  selectedAlertId = alertId;
  renderAlertCards(currentAlerts);

  const container = document.getElementById("inspectorContent");
  const accessTag = document.getElementById("inspectorAccessTag");

  container.innerHTML = `
    <div class="text-center py-10 text-slate-400 font-mono">
      <i data-lucide="loader" class="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-500"></i>
      Authenticating identity & loading forensic intelligence...
    </div>
  `;
  lucide.createIcons();

  try {
    const res = await fetch(`/api/alerts/${alertId}`, {
      headers: { "Authorization": `Bearer ${currentToken}` }
    });

    // RBAC RESTRICTION CHECK: 403 Forbidden
    if (res.status === 403) {
      accessTag.textContent = "ACCESS RESTRICTED (403)";
      accessTag.className = "px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-rose-950 text-rose-400 border border-rose-800";

      container.innerHTML = `
        <div class="p-6 rounded-xl bg-rose-950/40 border border-rose-800 space-y-3 text-center">
          <div class="h-12 w-12 rounded-full bg-rose-900/60 border border-rose-500 flex items-center justify-center mx-auto text-rose-400">
            <i data-lucide="shield-x" class="w-6 h-6"></i>
          </div>
          <h4 class="text-sm font-bold font-mono text-rose-300 uppercase">403 Forbidden: Unauthorized Threat Access</h4>
          <p class="text-xs text-slate-300 font-mono leading-relaxed">
            Your current identity role (<b class="text-rose-400">${currentRole}</b>) lacks the security clearance required to inspect sensitive forensic threat intelligence, SHAP decision weights, and raw attack payloads.
          </p>
          <div class="text-[11px] text-slate-400 font-mono bg-slate-950 p-2.5 rounded border border-slate-800 text-left">
            <div>&bull; <b>Security Policy:</b> RFC 7519 Identity Access Control</div>
            <div>&bull; <b>Required Role:</b> <span class="text-cyan-400">SOC Analyst</span> or <span class="text-indigo-400">Admin</span></div>
            <div>&bull; <b>Audit Action:</b> Real-time security rejection logged in tamper-evident ledger.</div>
          </div>
          <button onclick="switchUserRole('soc_analyst')" class="px-3 py-1.5 text-xs font-mono font-bold bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition shadow">
            Switch to Authorized SOC Analyst Persona
          </button>
        </div>
      `;
      lucide.createIcons();
      loadAuditLogs();
      return;
    }

    const alert = await res.json();
    const isRedacted = alert.access_level === "REDACTED_TIER1";

    accessTag.textContent = isRedacted ? "TIER 1 (REDACTED VIEW)" : "AUTHORIZED FORENSICS";
    accessTag.className = isRedacted ? 
      "px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-amber-950 text-amber-300 border border-amber-800" :
      "px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-cyan-950 text-cyan-300 border border-cyan-800";

    const isHigh = alert.risk_level === "High";
    const isMed = alert.risk_level === "Medium";
    const riskBadge = isHigh ? "bg-rose-950 text-rose-400 border-rose-800" :
                      isMed ? "bg-amber-950 text-amber-400 border-amber-800" :
                      "bg-emerald-950 text-emerald-400 border-emerald-800";

    const genai = alert.genai_brief || {};
    const mitre = genai.mitre_attack || {};
    const explain = alert.explainability || {};
    const topDrivers = explain.top_risk_drivers || [];
    const playbook = genai.remediation_playbook || [];

    container.innerHTML = `
      <div class="space-y-4 text-xs font-mono">
        
        <!-- Header Info -->
        <div class="flex items-start justify-between gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800">
          <div>
            <div class="text-[11px] text-slate-500">${alert.alert_id} &bull; ${alert.timestamp}</div>
            <h4 class="text-sm font-bold text-white font-sans mt-0.5">${alert.alert_name || 'Security Event'}</h4>
            <div class="text-slate-400 mt-1">Source IP: <span class="text-cyan-400 font-mono">${alert.source_ip || 'N/A'}</span> (${alert.source_country || 'US'})</div>
          </div>
          <span class="px-2.5 py-1 text-xs font-bold uppercase rounded border ${riskBadge}">
            ${alert.risk_level} Risk
          </span>
        </div>

        <!-- MITRE ATT&CK & Priority Pill Bar -->
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-2 py-1 rounded bg-slate-950 text-slate-300 border border-slate-800 flex items-center gap-1.5">
            <i data-lucide="target" class="w-3.5 h-3.5 text-rose-400"></i>
            MITRE ${mitre.technique_id || 'N/A'}: ${mitre.technique_name || 'Baseline'}
          </span>
          <span class="px-2 py-1 rounded bg-slate-950 text-slate-300 border border-slate-800">
            Kill Chain: <b class="text-cyan-400">${mitre.kill_chain_stage || 'N/A'}</b>
          </span>
        </div>

        <!-- Gen-AI Incident Briefing -->
        <div class="p-3.5 rounded-lg bg-cyan-950/30 border border-cyan-800/80 space-y-1.5">
          <div class="flex items-center gap-1.5 text-cyan-300 font-bold">
            <i data-lucide="sparkles" class="w-4 h-4"></i>
            <span>Gen-AI Threat Synthesis Briefing</span>
          </div>
          <p class="text-slate-300 font-sans text-xs leading-relaxed">
            ${isRedacted ? `<span class="text-amber-400 font-mono">[REDACTED - REQUIRE SOC ANALYST ROLE TO VIEW RISK EXPLANATIONS]</span>` : (genai.executive_summary || explain.explanation_summary || 'Analysis baseline established.')}
          </p>
        </div>

        <!-- SHAP-Style Explainability Bar Chart -->
        ${!isRedacted ? `
          <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-2">
            <div class="flex items-center justify-between text-[11px]">
              <span class="font-bold text-slate-300 uppercase flex items-center gap-1">
                <i data-lucide="bar-chart-2" class="w-3.5 h-3.5 text-cyan-400"></i>
                SHAP Local Feature Attribution Weights
              </span>
              <span class="text-slate-500">Tree Importance + Delta</span>
            </div>
            <div class="h-36 w-full">
              <canvas id="shapChartCanvas"></canvas>
            </div>
          </div>
        ` : `
          <div class="p-3 rounded bg-amber-950/20 border border-amber-800/60 text-amber-300 text-[11px]">
            <i data-lucide="lock" class="w-3.5 h-3.5 inline mr-1"></i>
            SHAP Decision Weights & Factor Breakdown are redacted for Tier 1 role.
          </div>
        `}

        <!-- Top Decision Drivers List -->
        ${!isRedacted && topDrivers.length > 0 ? `
          <div class="space-y-1.5">
            <div class="text-[11px] font-bold text-slate-400 uppercase">Primary Risk Drivers:</div>
            <div class="space-y-1">
              ${topDrivers.map(d => `
                <div class="p-2 rounded bg-slate-950 border border-slate-800 flex items-start gap-2">
                  <span class="w-1.5 h-1.5 rounded-full bg-rose-500 mt-1.5 flex-shrink-0"></span>
                  <div>
                    <div class="font-semibold text-slate-200">${d.display_name} <span class="text-slate-500">(Val: ${d.value})</span></div>
                    <div class="text-[11px] text-slate-400 font-sans">${d.explanation}</div>
                  </div>
                </div>
              `).join("")}
            </div>
          </div>
        ` : ''}

        <!-- Forensic Payload (Redacted for non-analysts) -->
        <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
          <div class="flex items-center justify-between text-[11px] text-slate-400">
            <span>RAW FORENSIC PAYLOAD TELEMETRY</span>
            ${isRedacted ? `<span class="text-amber-400 text-[10px] uppercase font-bold">REDACTED</span>` : `<span class="text-cyan-400 text-[10px] uppercase font-bold">UNMASKED</span>`}
          </div>
          <pre class="p-2 bg-black/60 rounded text-[11px] text-cyan-300 overflow-x-auto font-mono whitespace-pre-wrap">${alert.sensitive_payload || alert.payload || 'No payload data.'}</pre>
        </div>

        <!-- SOC Incident Response Playbook Checklist -->
        ${!isRedacted && playbook.length > 0 ? `
          <div class="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
            <div class="flex items-center gap-1.5 text-emerald-400 font-bold text-[11px] uppercase">
              <i data-lucide="check-square" class="w-3.5 h-3.5"></i>
              <span>Recommended SOC Remediation Checklist</span>
            </div>
            <div class="space-y-1.5">
              ${playbook.map((step, idx) => `
                <label class="flex items-start gap-2 p-1.5 rounded hover:bg-slate-900 cursor-pointer">
                  <input type="checkbox" class="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-600 focus:ring-0">
                  <span class="text-[11px] text-slate-300 font-sans leading-tight">${step}</span>
                </label>
              `).join("")}
            </div>
          </div>
        ` : ''}

      </div>
    `;

    lucide.createIcons();

    // Render SHAP chart if allowed
    if (!isRedacted && explain.all_factors) {
      renderShapChart(explain.all_factors);
    }

  } catch (e) {
    container.innerHTML = `<div class="p-4 text-rose-400 font-mono">Error inspecting alert: ${e.message}</div>`;
  }
}

/**
 * Render Chart.js Bar Chart for SHAP Local Contributions
 */
function renderShapChart(factors) {
  const canvas = document.getElementById("shapChartCanvas");
  if (!canvas) return;

  if (shapChartInstance) {
    shapChartInstance.destroy();
  }

  const top6 = factors.slice(0, 6);
  const labels = top6.map(f => f.display_name);
  const dataValues = top6.map(f => f.contribution_score);
  const bgColors = dataValues.map(v => v >= 0 ? "rgba(244, 63, 94, 0.85)" : "rgba(16, 185, 129, 0.85)");

  shapChartInstance = new Chart(canvas, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Feature Contribution to Risk",
        data: dataValues,
        backgroundColor: bgColors,
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => `Contribution: ${ctx.parsed.x > 0 ? '+' : ''}${ctx.parsed.x.toFixed(4)}`
          }
        }
      },
      scales: {
        x: {
          grid: { color: "#1e293b" },
          ticks: { color: "#94a3b8", font: { size: 9, family: "JetBrains Mono" } }
        },
        y: {
          grid: { display: false },
          ticks: { color: "#cbd5e1", font: { size: 9, family: "JetBrains Mono" } }
        }
      }
    }
  });
}

/**
 * Filter alerts by risk level
 */
function filterByRisk(risk) {
  currentFilter = risk;
  
  document.querySelectorAll("[id^='filter-']").forEach(btn => {
    btn.className = "px-2 py-1 rounded font-medium text-slate-400 hover:text-white";
  });
  
  const activeId = risk === "" ? "filter-all" : `filter-${risk.toLowerCase().substring(0, 4)}`;
  const activeBtn = document.getElementById(activeId);
  if (activeBtn) {
    activeBtn.className = "px-2.5 py-1 rounded font-medium bg-slate-800 text-cyan-300";
  }

  loadAlerts();
}

/**
 * Inject Sample Alerts via one-click buttons
 */
async function injectSampleAlert(sampleFileName) {
  try {
    const res = await fetch("/api/samples");
    const samples = await res.json();
    const target = samples.find(s => s.file_name === sampleFileName);

    if (!target) {
      alert(`Sample '${sampleFileName}' not found.`);
      return;
    }

    const ingestRes = await fetch("/api/alerts/ingest", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${currentToken}`
      },
      body: JSON.stringify(target.data)
    });

    const result = await ingestRes.json();
    await loadAlerts();
    await loadAuditLogs();
    await loadCorrelations();

    if (result.alerts && result.alerts.length > 0) {
      inspectAlert(result.alerts[0].alert_id);
    }
  } catch (e) {
    alert(`Failed to inject sample alert: ${e.message}`);
  }
}

/**
 * Multi-Alert Correlation Cards
 */
async function loadCorrelations() {
  const container = document.getElementById("correlationCardsGrid");
  const badge = document.getElementById("corrCountBadge");

  try {
    const res = await fetch("/api/rules/correlated", {
      headers: { "Authorization": `Bearer ${currentToken}` }
    });
    const data = await res.json();

    badge.textContent = `${data.correlated_incidents_count} Correlated Chains`;

    if (data.correlated_alerts.length === 0) {
      container.innerHTML = `<div class="col-span-full text-center py-6 text-slate-500 font-mono text-xs">No multi-event attack chains currently active. Ingest sample scenarios to trigger correlation rules.</div>`;
      return;
    }

    container.innerHTML = data.correlated_alerts.slice(0, 4).map(alert => {
      const corr = alert.correlation || {};
      const rules = corr.matched_rules || [];
      const primaryRule = rules[0] || { rule_name: "Correlated Threat Pattern", severity: "HIGH" };

      return `
        <div class="p-3.5 rounded-xl bg-slate-950 border border-indigo-900/60 space-y-2">
          <div class="flex items-center justify-between">
            <span class="px-2 py-0.5 text-[9px] font-mono font-bold rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
              ${primaryRule.rule_id || 'CHAIN'}
            </span>
            <span class="text-[10px] font-mono text-rose-400 font-bold">${primaryRule.severity}</span>
          </div>
          <h5 class="text-xs font-semibold text-white truncate">${primaryRule.rule_name}</h5>
          <p class="text-[11px] text-slate-400 font-sans line-clamp-2">${primaryRule.description || alert.alert_name}</p>
          <button onclick="inspectAlert('${alert.alert_id}')" class="w-full text-center py-1 text-[10px] font-mono text-cyan-400 bg-cyan-950/40 hover:bg-cyan-900/40 rounded border border-cyan-800">
            View Correlated Forensics
          </button>
        </div>
      `;
    }).join("");

  } catch (e) {
    console.error("Correlation error:", e);
  }
}

/**
 * Load Tamper-Evident Audit Trail Stream
 */
async function loadAuditLogs() {
  const tbody = document.getElementById("auditTableBody");

  try {
    const res = await fetch("/api/audit/logs?limit=8");
    const data = await res.json();
    const logs = data.logs || [];

    tbody.innerHTML = logs.map(entry => {
      const isOk = entry.status_code >= 200 && entry.status_code < 400;
      const isDenied = entry.status_code === 403;
      const statusColor = isOk ? "text-emerald-400" : isDenied ? "text-rose-400 font-bold" : "text-amber-400";
      const timeStr = entry.timestamp ? entry.timestamp.substring(11, 19) : "12:00:00";
      const shortHash = entry.hash ? entry.hash.substring(0, 10) + "..." : "sha256";

      return `
        <tr class="hover:bg-slate-900/50">
          <td class="p-2.5 text-slate-400">${timeStr} UTC</td>
          <td class="p-2.5 font-medium text-white">${entry.username} <span class="text-slate-500">(${entry.role})</span></td>
          <td class="p-2.5 text-cyan-300 truncate max-w-xs">${entry.action}</td>
          <td class="p-2.5 ${statusColor}">${entry.status_code}</td>
          <td class="p-2.5"><span class="px-1.5 py-0.5 rounded text-[10px] ${isDenied ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-slate-900 text-slate-300'}">${entry.outcome}</span></td>
          <td class="p-2.5 text-slate-500 font-mono">${shortHash}</td>
        </tr>
      `;
    }).join("");

  } catch (e) {
    console.error("Audit load error:", e);
  }
}

/**
 * Verify SHA-256 Cryptographic Chain
 */
async function verifyAuditChain() {
  try {
    const res = await fetch("/api/audit/verify");
    const result = await res.json();

    if (result.valid) {
      alert(`✔ Cryptographic Audit Trail Verified!\nTotal Events: ${result.total_events}\nIntegrity Status: SECURE_VERIFIED\nLatest Hash: ${result.latest_hash}`);
    } else {
      alert(`✖ Tampering Detected in Audit Trail!\nDetails: ${JSON.stringify(result)}`);
    }
  } catch (e) {
    alert(`Verification error: ${e.message}`);
  }
}

/**
 * Trigger ML Retraining via API (Admin only)
 */
async function triggerRetrain() {
  const icon = document.getElementById("retrainIcon");
  icon.classList.add("animate-spin");

  try {
    const res = await fetch("/api/model/retrain?samples_count=600", {
      method: "POST",
      headers: { "Authorization": `Bearer ${currentToken}` }
    });

    if (res.status === 403) {
      alert("✖ 403 Forbidden: Only Administrator role can trigger model retraining.");
      icon.classList.remove("animate-spin");
      loadAuditLogs();
      return;
    }

    const data = await res.json();
    alert(`✔ Model Retrained Successfully via API!\nSamples Trained: 600\nAccuracy: ${(data.metrics.accuracy * 100).toFixed(2)}%\nMacro F1: ${data.metrics.f1_macro.toFixed(4)}\nDuration: ${data.retrain_duration_ms}ms`);

    loadModelMetrics();
    loadAuditLogs();
  } catch (e) {
    alert(`Retrain failed: ${e.message}`);
  } finally {
    icon.classList.remove("animate-spin");
  }
}

/**
 * Load Model Evaluation Metrics
 */
async function loadModelMetrics() {
  try {
    const res = await fetch("/api/model/metrics");
    const data = await res.json();

    if (data.metrics && data.metrics.accuracy) {
      document.getElementById("metricAcc").textContent = `${(data.metrics.accuracy * 100).toFixed(1)}%`;
      document.getElementById("metricF1").textContent = data.metrics.f1_macro.toFixed(3);
    }
  } catch (e) {
    console.error("Metrics load error:", e);
  }
}

/**
 * Download PDF Incident Dossier
 */
function downloadPdfReport() {
  if (currentRole === "unauthorized_guest" || currentRole === "tier1_viewer") {
    alert(`Access Restricted: Role '${currentRole}' cannot export confidential PDF Incident Dossiers. Please switch to SOC Analyst or Admin.`);
    return;
  }
  window.open(`/api/reports/pdf?token=${currentToken}`, "_blank");
}

/**
 * Upload Modal & JSON Ingestion Handlers
 */
function openUploadModal() {
  document.getElementById("uploadModal").classList.remove("hidden");
}

function closeUploadModal() {
  document.getElementById("uploadModal").classList.add("hidden");
}

async function handleFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch("/api/alerts/ingest", {
      method: "POST",
      headers: { "Authorization": `Bearer ${currentToken}` },
      body: formData
    });
    const data = await res.json();
    closeUploadModal();
    await loadAlerts();
    await loadAuditLogs();
    if (data.alerts && data.alerts.length > 0) {
      inspectAlert(data.alerts[0].alert_id);
    }
  } catch (e) {
    alert(`File ingestion failed: ${e.message}`);
  }
}

async function submitRawJson() {
  const text = document.getElementById("rawJsonInput").value.trim();
  if (!text) return;

  try {
    const parsed = JSON.parse(text);
    const res = await fetch("/api/alerts/ingest", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${currentToken}`
      },
      body: JSON.stringify(parsed)
    });
    const data = await res.json();
    closeUploadModal();
    await loadAlerts();
    await loadAuditLogs();
    if (data.alerts && data.alerts.length > 0) {
      inspectAlert(data.alerts[0].alert_id);
    }
  } catch (e) {
    alert(`Invalid JSON or ingestion error: ${e.message}`);
  }
}

async function refreshDashboard() {
  await loadAlerts();
  await loadAuditLogs();
  await loadCorrelations();
}
