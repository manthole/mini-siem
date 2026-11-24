/* mini-SIEM — console SOC (logique front).
 * S'appuie sur le moteur partagé window.MiniSIEM. Tout est côté client.
 *
 * Sécurité : la page est servie sous une CSP stricte (script-src 'self',
 * style-src 'self'). Aucun gestionnaire d'événement ni style dans le HTML :
 * les clics passent par des attributs data-action et un écouteur unique.
 * Toute donnée affichée (journaux chargés, règles et statuts relus depuis
 * localStorage) est échappée, guillemets compris, avant d'entrer dans le DOM.
 */
(function () {
  "use strict";
  const M = window.MiniSIEM;
  const DEFAULT_RULES = window.MINISIEM_RULES;
  const CTI = M.ctiIndex(window.MINISIEM_CTI);
  const SEV = M.SEVERITY_ORDER;
  const SEVS = ["critical", "high", "medium", "low"];
  const IR_KEY = "minisiem_ir_v1", RULES_KEY = "minisiem_rules_v1";

  const STATUS = {
    nouveau:     {label: "Nouveau",      cls: ""},
    encours:     {label: "En cours",     cls: "encours"},
    contenu:     {label: "Contenu",      cls: "contenu"},
    resolu:      {label: "Résolu",       cls: "resolu"},
    fauxpositif: {label: "Faux positif", cls: "fauxpositif"},
  };
  const ACTIONS = {
    block_ip: "Bloquer l'IP source au pare-feu",
    reset_creds: "Réinitialiser les identifiants du compte",
    isolate_host: "Isoler l'hôte affecté",
    collect_evidence: "Collecter les preuves (logs, mémoire)",
    notify: "Notifier l'équipe / ouvrir un ticket",
  };
  const SAMPLE_NAMES = {auth: "Exemple SSH", web: "Exemple web", fw: "Exemple pare-feu",
                        win: "Exemple Windows", sysmon: "Exemple Sysmon"};

  const store = {
    get(k, def) { try { return JSON.parse(localStorage.getItem(k)) || def; } catch (e) { return def; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} },
  };

  const state = {
    events: [], alerts: [], srcLabel: "",
    rules: validRules(store.get(RULES_KEY, null)) || clone(DEFAULT_RULES),
    ir: store.get(IR_KEY, {}),
    currentRuleId: null,
  };
  if (!state.ir || typeof state.ir !== "object" || Array.isArray(state.ir)) state.ir = {};

  const els = {};
  ["file", "srcInfo", "kpis", "rows", "search", "filters", "openOnly", "ruleList", "ruleCount",
   "editor", "editHint", "editTitle", "e_id", "e_title", "e_type", "e_level",
   "e_attack", "e_tactic", "e_params", "e_err", "e_effect", "drawer"]
    .forEach(id => els[id] = document.getElementById(id));

  // --- Utilitaires --------------------------------------------------------
  function clone(o) { return JSON.parse(JSON.stringify(o)); }
  function validRules(r) {
    return Array.isArray(r) && r.every(x => x && typeof x === "object" && typeof x.id === "string") ? r : null;
  }
  const ESC = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"};
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, c => ESC[c]); }
  function sev(s) { return SEVS.indexOf(s) >= 0 ? s : "low"; }
  function num(n) { n = Number(n); return isFinite(n) ? n : 0; }
  function fp(a) { return [a.rule_id, a.source_ip || "", a.user || "", +new Date(a.first_seen)].join("|"); }
  function irOf(a) {
    const r = state.ir[fp(a)];
    const rec = r && typeof r === "object" ? r : {};
    return {status: STATUS[rec.status] ? rec.status : "nouveau",
            assignee: rec.assignee || "", notes: rec.notes || "",
            actions: rec.actions && typeof rec.actions === "object" ? rec.actions : {}};
  }
  function setIr(a, rec) { state.ir[fp(a)] = rec; store.set(IR_KEY, state.ir); }
  function fmt(d) { const x = new Date(d); return isNaN(x) ? "-" : x.toLocaleString("fr-FR"); }
  function base(p) { return p ? String(p).split(/[\\/]/).pop() : ""; }
  function clip(s, n) { s = String(s || ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

  function download(name, text, type) {
    const b = new Blob([text], {type: type || "application/json"});
    const u = URL.createObjectURL(b), a = document.createElement("a");
    a.href = u; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(u), 500);
  }

  // Résumé lisible d'un événement, selon sa source (colonne « Détail »)
  function detailOf(e) {
    switch (e.event_type) {
      case "process_creation": return e.command_line || base(e.process);
      case "network_connection": return `${base(e.process)} → ${e.dest_ip || "?"}:${e.dest_port || "?"}`;
      case "process_access": return `${base(e.process)} → ${base(e.target)} (${e.granted_access || "?"})`;
      case "file_event": case "registry_set": case "dns_query": return `${base(e.process)} → ${e.target || ""}`;
      case "web_request": return `${e.method || ""} ${e.url || ""} → ${e.status || ""}`;
      case "fw_block": return `${e.proto || ""} port ${e.dest_port || "?"}`;
      default: return e.event_id ? `EventID ${e.event_id}${e.detail ? " · " + e.detail : ""}` : "";
    }
  }

  // --- Détection ----------------------------------------------------------
  function detect() {
    const ev = state.events;
    let alerts = M.runRules(state.rules, ev);
    alerts = alerts.concat(M.ctiDetectContacts(CTI, ev, alerts));
    M.ctiEnrich(alerts, CTI);
    M.enrich(alerts);
    const rank = s => (s in SEV ? SEV[s] : 9);
    alerts.sort((a, b) => (rank(a.severity) - rank(b.severity)) ||
                          (new Date(a.first_seen) - new Date(b.first_seen)));
    state.alerts = alerts;
    renderKPIs(); renderAlerts();
  }

  function renderKPIs() {
    const c = {critical: 0, high: 0, medium: 0, low: 0};
    state.alerts.forEach(a => c[sev(a.severity)]++);
    const open = state.alerts.filter(a => { const s = irOf(a).status; return s !== "resolu" && s !== "fauxpositif"; }).length;
    els.kpis.innerHTML =
      kpi(state.events.length, "Événements") + kpi(state.alerts.length, "Alertes") +
      kpi(open, "Non résolues") + SEVS.map(s => kpi(c[s], s, "c-" + s)).join("");
  }
  function kpi(n, l, cls) {
    return `<div class="kpi"><div class="n${cls ? " " + cls : ""}">${num(n)}</div><div class="l">${esc(l)}</div></div>`;
  }

  function emptyRow(text) { return `<tr><td colspan="7" class="meta empty">${esc(text)}</td></tr>`; }

  function renderAlerts() {
    const q = (els.search.value || "").toLowerCase();
    const sevs = Array.from(document.querySelectorAll(".sevf:checked")).map(c => c.value);
    const openOnly = els.openOnly.checked;
    if (!state.alerts.length) { els.rows.innerHTML = emptyRow("Charge une source pour lancer la détection."); return; }
    const rows = state.alerts.filter(a => {
      if (sevs.indexOf(sev(a.severity)) < 0) return false;
      if (openOnly) { const s = irOf(a).status; if (s === "resolu" || s === "fauxpositif") return false; }
      if (q) { const hay = [a.rule_id, a.title, a.source_ip, a.user, a.attack].join(" ").toLowerCase();
               if (hay.indexOf(q) < 0) return false; }
      return true;
    });
    els.rows.innerHTML = rows.length ? rows.map(a => {
      const st = STATUS[irOf(a).status], s = sev(a.severity);
      return `<tr data-action="open" data-idx="${state.alerts.indexOf(a)}" tabindex="0">
        <td><span class="sev ${s}">${s}</span></td>
        <td><span class="st ${st.cls}">${esc(st.label)}</span></td>
        <td>${esc(a.title)}${a.threat ? ` <span class="cti">connu</span>` : ""}</td>
        <td>${a.source_ip ? `<code>${esc(a.source_ip)}</code>` : "-"}${a.country ? `<br><span class="meta">${esc(a.country)}</span>` : ""}</td>
        <td>${esc(a.user) || "-"}</td><td>${num(a.count)}</td>
        <td><span class="att">${esc(a.attack)}</span></td></tr>`;
    }).join("") : emptyRow("Aucune alerte pour ces filtres.");
  }

  // --- Investigation + réponse à incident (drawer) ------------------------
  function openDrawer(idx) {
    const a = state.alerts[idx];
    if (!a) return;
    const rec = irOf(a), s = sev(a.severity);
    const rule = state.rules.find(r => r.id === a.rule_id);
    // Activité liée : mêmes IP ou compte
    const related = state.events.filter(e =>
      (a.source_ip && (e.source_ip === a.source_ip || e.dest_ip === a.source_ip)) ||
      (a.user && e.user === a.user))
      .sort((x, y) => new Date(x.timestamp) - new Date(y.timestamp));
    // Chaîne ATT&CK de l'entité
    const chain = state.alerts.filter(x =>
      (a.source_ip && x.source_ip === a.source_ip) || (a.user && x.user === a.user))
      .sort((x, y) => new Date(x.first_seen) - new Date(y.first_seen));
    const evidence = Array.isArray(a.evidence) ? a.evidence : [];

    els.drawer.innerHTML = `<div class="drawer-bg">
      <div class="drawer" role="dialog" aria-modal="true" aria-labelledby="drawerTitle">
        <button class="close" data-action="close-drawer" aria-label="Fermer">&times;</button>
        <h2 id="drawerTitle">${esc(a.title)}</h2>
        <div class="row"><span class="sev ${s}">${s}</span>
          <span class="att">${esc(a.attack)}</span><span class="meta">${esc(a.tactic)}</span></div>
        <p class="meta">${esc(a.description || "")}</p>
        <div class="row meta">
          <span>Source : ${a.source_ip ? `<code>${esc(a.source_ip)}</code>` : "-"}
            ${a.country ? `· ${esc(a.country)}${a.city ? " (" + esc(a.city) + ")" : ""}` : ""}</span>
          <span>Compte : ${esc(a.user) || "-"}</span>
          <span>${num(a.count)} occurrence(s)</span>
          <span>${esc(fmt(a.first_seen))} → ${esc(fmt(a.last_seen))}</span>
        </div>
        ${a.threat ? `<p><span class="cti">⚠ Renseignement : connu de ${esc(a.threat.source)}
          — ${esc(a.threat.category)}, confiance ${num(a.threat.confidence)}%</span></p>` : ""}

        <h3>Réponse à incident</h3>
        <div class="row">
          <select id="ir_status" aria-label="Statut">${Object.keys(STATUS).map(k =>
            `<option value="${k}"${rec.status === k ? " selected" : ""}>${esc(STATUS[k].label)}</option>`).join("")}</select>
          <input id="ir_assignee" class="grow" placeholder="Assigné à" aria-label="Assigné à" value="${esc(rec.assignee)}">
        </div>
        <div class="acts">${Object.keys(ACTIONS).map(k =>
          `<label class="chk"><input type="checkbox" id="ir_act_${k}"${rec.actions[k] ? " checked" : ""}> ${esc(ACTIONS[k])}</label>`).join("")}</div>
        <textarea id="ir_notes" rows="3" placeholder="Notes d'investigation..." aria-label="Notes">${esc(rec.notes)}</textarea>
        <div class="row mt8"><button class="primary" data-action="save-ir" data-idx="${num(idx)}">Enregistrer</button>
          <span class="meta" id="ir_saved"></span></div>

        <h3>Chaîne ATT&amp;CK de l'entité (${chain.length} alerte(s))</h3>
        <div class="tablewrap"><table><tbody>${chain.map(x =>
          `<tr class="static"><td><span class="sev ${sev(x.severity)}">${sev(x.severity)}</span></td>
            <td>${esc(x.title)}</td><td><span class="att">${esc(x.attack)}</span></td>
            <td class="meta">${esc(x.tactic)}</td></tr>`).join("")}</tbody></table></div>

        <h3>Activité liée (${related.length} événement(s))</h3>
        <div class="tablewrap"><table><thead><tr><th>Heure</th><th>Source</th><th>Type</th><th>Détail</th></tr></thead>
          <tbody>${related.slice(0, 60).map(e =>
            `<tr class="static"><td class="meta">${esc(fmt(e.timestamp))}</td>
              <td class="meta">${esc(e.source)}</td><td>${esc(e.event_type)}<br><span class="meta">${esc(e.outcome)}</span></td>
              <td class="det">${esc(clip(detailOf(e), 160))}</td></tr>`).join("")}</tbody></table></div>
        ${related.length > 60 ? `<p class="meta">… ${related.length - 60} de plus</p>` : ""}

        <h3>Preuves (${evidence.length})</h3>
        <pre>${esc(evidence.join("\n"))}</pre>

        <h3>Règle déclenchée</h3>
        <pre>${esc(JSON.stringify(rule || {id: a.rule_id, note: "règle interne (CTI)"}, null, 2))}</pre>
      </div></div>`;
    const close = els.drawer.querySelector(".close");
    if (close) close.focus();
  }
  function closeDrawer() { els.drawer.innerHTML = ""; }

  function saveIr(idx) {
    const a = state.alerts[idx];
    if (!a) return;
    const actions = {};
    Object.keys(ACTIONS).forEach(k => { const el = document.getElementById("ir_act_" + k); if (el && el.checked) actions[k] = true; });
    setIr(a, {status: document.getElementById("ir_status").value,
              assignee: document.getElementById("ir_assignee").value,
              notes: document.getElementById("ir_notes").value, actions: actions});
    document.getElementById("ir_saved").textContent = "Enregistré ✓";
    renderKPIs(); renderAlerts();
  }

  function exportIncident() {
    if (!state.alerts.length) { window.alert("Charge d'abord une source."); return; }
    const data = state.alerts.map(a => {
      const rec = irOf(a);
      return {rule_id: a.rule_id, title: a.title, severity: a.severity, attack: a.attack,
              tactic: a.tactic, source_ip: a.source_ip, user: a.user, count: a.count,
              first_seen: a.first_seen, last_seen: a.last_seen, country: a.country || null,
              threat: a.threat || null, status: rec.status, assignee: rec.assignee,
              actions: Object.keys(rec.actions), notes: rec.notes};
    });
    download("rapport_incident.json", JSON.stringify(
      {generated_at: new Date().toISOString(), source: state.srcLabel,
       total: data.length, alerts: data}, null, 2));
  }

  // --- Éditeur de règles --------------------------------------------------
  const META_FIELDS = ["id", "title", "type", "level", "attack", "tactic", "_file", "description"];
  function paramsOf(rule) {
    const p = {}; Object.keys(rule).forEach(k => { if (META_FIELDS.indexOf(k) < 0) p[k] = rule[k]; });
    return p;
  }

  function renderRuleList() {
    els.ruleCount.textContent = state.rules.length;
    els.ruleList.innerHTML = state.rules.map(r =>
      `<div class="rulecard${r.id === state.currentRuleId ? " sel" : ""}" data-action="select-rule" data-rule="${esc(r.id)}" tabindex="0">
        <div class="row m0 between">
          <b>${esc(r.id)}</b><span class="sev ${sev(r.level)}">${sev(r.level)}</span></div>
        <div class="meta">${esc(r.title)} · <span class="att">${esc(r.attack || "-")}</span> · ${esc(r.type)}</div>
      </div>`).join("");
  }

  function selectRule(id) {
    const r = state.rules.find(x => x.id === id);
    if (!r) return;
    state.currentRuleId = id;
    els.editor.classList.remove("hidden"); els.editHint.classList.add("hidden");
    els.editTitle.textContent = "Éditeur — " + id;
    els.e_id.value = r.id; els.e_title.value = r.title || ""; els.e_type.value = r.type || "match";
    els.e_level.value = sev(r.level || "medium"); els.e_attack.value = r.attack || ""; els.e_tactic.value = r.tactic || "";
    const params = paramsOf(r);
    if (r.description) params.description = r.description;
    els.e_params.value = JSON.stringify(params, null, 2);
    els.e_err.classList.add("hidden"); els.e_effect.textContent = "";
    renderRuleList();
  }

  function newRule() {
    const id = "NOUVELLE_REGLE_" + (state.rules.length + 1);
    state.rules.push({id: id, title: "Nouvelle règle", type: "match", level: "medium",
      attack: "", tactic: "", selection: {event_type: "ssh_login", outcome: "failure"}});
    persistRules(); selectRule(id); renderRuleList();
  }

  function showErr(msg) { els.e_err.textContent = msg; els.e_err.classList.remove("hidden"); }

  function saveRule() {
    let params;
    try { params = JSON.parse(els.e_params.value || "{}"); }
    catch (e) { showErr("JSON invalide : " + e.message); return; }
    if (!params || typeof params !== "object" || Array.isArray(params)) { showErr("Les paramètres doivent être un objet JSON."); return; }
    if (!els.e_id.value.trim()) { showErr("L'id est obligatoire."); return; }
    els.e_err.classList.add("hidden");
    const idx = state.rules.findIndex(r => r.id === state.currentRuleId);
    const rule = Object.assign({}, params, {id: els.e_id.value.trim(), title: els.e_title.value,
      type: els.e_type.value, level: els.e_level.value,
      attack: els.e_attack.value, tactic: els.e_tactic.value});
    if (idx >= 0) state.rules[idx] = rule; else state.rules.push(rule);
    state.currentRuleId = rule.id;
    persistRules();
    const before = state.alerts.length;
    try { detect(); }
    catch (e) { showErr("Règle inutilisable : " + e.message); return; }
    els.e_effect.textContent = `Règles enregistrées. Détection relancée : ${state.alerts.length} alerte(s) (était ${before}).`;
    renderRuleList();
  }

  function deleteRule() {
    state.rules = state.rules.filter(r => r.id !== state.currentRuleId);
    state.currentRuleId = null; persistRules();
    els.editor.classList.add("hidden"); els.editHint.classList.remove("hidden");
    detect(); renderRuleList();
  }

  function resetRules() {
    if (!window.confirm("Réinitialiser toutes les règles aux valeurs par défaut ?")) return;
    state.rules = clone(DEFAULT_RULES); try { localStorage.removeItem(RULES_KEY); } catch (e) {}
    state.currentRuleId = null; els.editor.classList.add("hidden"); els.editHint.classList.remove("hidden");
    detect(); renderRuleList();
  }

  function persistRules() { store.set(RULES_KEY, state.rules); }
  function exportRules() { download("rules.json", JSON.stringify(state.rules, null, 2)); }

  // --- Chargement des sources --------------------------------------------
  function analyzeText(text, label) {
    state.events = M.parseText(text, 2026);
    state.srcLabel = label;
    els.srcInfo.textContent = `${label} — ${state.events.length} événements`;
    detect();
  }
  function loadSample(key) {
    if (!SAMPLE_NAMES[key]) return;
    analyzeText(window.MINISIEM_SAMPLES[key], SAMPLE_NAMES[key]);
  }
  function loadAll() {
    const s = window.MINISIEM_SAMPLES;
    analyzeText(Object.keys(SAMPLE_NAMES).map(k => s[k]).join("\n"), "Toutes les sources");
  }

  // --- Navigation ---------------------------------------------------------
  function tab(name) {
    document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
    document.getElementById("tab-detect").classList.toggle("hidden", name !== "detect");
    document.getElementById("tab-rules").classList.toggle("hidden", name !== "rules");
    if (name === "rules") renderRuleList();
  }

  // --- Événements : un écouteur délégué, aucun onclick dans le HTML -------
  const HANDLERS = {
    "pick-file": () => els.file.click(),
    "sample": t => loadSample(t.dataset.sample),
    "load-all": loadAll,
    "tab": t => tab(t.dataset.tab),
    "export-incident": exportIncident,
    "open": t => openDrawer(+t.dataset.idx),
    "close-drawer": closeDrawer,
    "save-ir": t => saveIr(+t.dataset.idx),
    "new-rule": newRule,
    "reset-rules": resetRules,
    "export-rules": exportRules,
    "select-rule": t => selectRule(t.dataset.rule),
    "save-rule": saveRule,
    "delete-rule": deleteRule,
  };

  document.addEventListener("click", e => {
    if (e.target.classList && e.target.classList.contains("drawer-bg")) { closeDrawer(); return; }
    const t = e.target.closest("[data-action]");
    if (t && HANDLERS[t.dataset.action]) HANDLERS[t.dataset.action](t);
  });
  document.addEventListener("keydown", e => {
    if (e.key === "Escape" && els.drawer.firstChild) { closeDrawer(); return; }
    if (e.key !== "Enter" && e.key !== " ") return;
    const t = e.target.closest && e.target.closest("tr[data-action], .rulecard[data-action]");
    if (t) { e.preventDefault(); HANDLERS[t.dataset.action](t); }
  });
  els.search.addEventListener("input", renderAlerts);
  els.filters.addEventListener("change", renderAlerts);
  els.file.addEventListener("change", e => {
    const f = e.target.files[0]; if (!f) return;
    const r = new FileReader(); r.onload = () => analyzeText(String(r.result), f.name); r.readAsText(f);
  });

  renderRuleList();
})();
