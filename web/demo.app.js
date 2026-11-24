/* mini-SIEM — démo simple : déposer un journal, voir les alertes.
 * Script externe (CSP script-src 'self') : aucun gestionnaire dans le HTML,
 * toute donnée affichée est échappée, guillemets compris.
 */
(function () {
  "use strict";
  const M = window.MiniSIEM;
  const SEV = M.SEVERITY_ORDER;
  const SEVS = ["critical", "high", "medium", "low"];
  const RULES = window.MINISIEM_RULES;
  const CTI = M.ctiIndex(window.MINISIEM_CTI);
  const ESC = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"};
  const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ESC[c]);
  const sev = s => (SEVS.indexOf(s) >= 0 ? s : "low");
  const num = n => (isFinite(Number(n)) ? Number(n) : 0);
  const $ = id => document.getElementById(id);

  function analyze(text) {
    const events = M.parseText(text, 2026);
    let alerts = M.runRules(RULES, events);
    alerts = alerts.concat(M.ctiDetectContacts(CTI, events, alerts));
    M.ctiEnrich(alerts, CTI);
    M.enrich(alerts);
    const rank = s => (s in SEV ? SEV[s] : 9);
    alerts.sort((a, b) => (rank(a.severity) - rank(b.severity)) || (a.first_seen - b.first_seen));
    render(events, alerts);
  }

  function kpi(n, label, cls) {
    return `<div class="kpi"><div class="n${cls ? " " + cls : ""}">${num(n)}</div><div class="l">${esc(label)}</div></div>`;
  }

  function render(events, alerts) {
    $("results").classList.remove("hidden");
    const counts = {critical: 0, high: 0, medium: 0, low: 0};
    alerts.forEach(a => counts[sev(a.severity)]++);
    $("kpis").innerHTML = kpi(events.length, "Événements") + kpi(alerts.length, "Alertes") +
      SEVS.map(s => kpi(counts[s], s, "c-" + s)).join("");

    const techs = {};
    alerts.forEach(a => { techs[a.attack] = (techs[a.attack] || 0) + 1; });
    $("chips").innerHTML = Object.keys(techs).length
      ? Object.entries(techs).map(([t, n]) => `<span class="chip"><span class="att">${esc(t)}</span> ×${num(n)}</span>`).join("")
      : '<span class="chip">aucune</span>';

    $("rows").innerHTML = alerts.map(a => `
      <tr>
        <td><span class="sev ${sev(a.severity)}">${sev(a.severity)}</span></td>
        <td>${esc(a.title)}${a.threat ? `<br><span class="cti">⚠ connu — ${esc(a.threat.source)} (${esc(a.threat.category)}, ${num(a.threat.confidence)}%)</span>` : ""}
          <details><summary>${num(a.count)} preuve(s)</summary>
          <pre>${esc((a.evidence || []).join("\n"))}</pre></details></td>
        <td>${a.source_ip ? `<code>${esc(a.source_ip)}</code>` : "-"}${a.country ? `<br><span class="geo">${esc(a.country)}${a.city ? " · " + esc(a.city) : ""}</span>` : ""}</td>
        <td>${esc(a.user) || "-"}</td>
        <td>${num(a.count)}</td>
        <td><span class="att">${esc(a.attack)}</span></td>
      </tr>`).join("") || '<tr><td colspan="6" class="none">Aucune alerte détectée.</td></tr>';
    $("results").scrollIntoView({behavior: "smooth", block: "start"});
  }

  function readFile(f) { const r = new FileReader(); r.onload = () => analyze(String(r.result)); r.readAsText(f); }

  document.addEventListener("click", e => {
    const t = e.target.closest("[data-action]");
    if (!t) return;
    if (t.dataset.action === "pick-file") $("file").click();
    else if (t.dataset.action === "sample" && window.MINISIEM_SAMPLES[t.dataset.sample])
      analyze(window.MINISIEM_SAMPLES[t.dataset.sample]);
  });
  const drop = $("drop");
  ["dragover", "dragenter"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", e => { const f = e.dataTransfer.files[0]; if (f) readFile(f); });
  $("file").addEventListener("change", e => { const f = e.target.files[0]; if (f) readFile(f); });
})();
