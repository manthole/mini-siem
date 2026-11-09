/* mini-SIEM — console SOC (logique front).
 * S'appuie sur le moteur partagé window.MiniSIEM. Tout est côté client.
 */
(function () {
  "use strict";
  const M = window.MiniSIEM;
  const DEFAULT_RULES = window.MINISIEM_RULES;
  const CTI = M.ctiIndex(window.MINISIEM_CTI);
  const SEV = M.SEVERITY_ORDER;
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

  const store = {
    get(k, def) { try { return JSON.parse(localStorage.getItem(k)) || def; } catch (e) { return def; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} },
  };

  const state = {
    events: [], alerts: [], srcLabel: "",
    rules: store.get(RULES_KEY, null) || clone(DEFAULT_RULES),
    ir: store.get(IR_KEY, {}),
    currentRuleId: null,
  };

  const els = {};
  ["file", "srcInfo", "kpis", "rows", "search", "openOnly", "ruleList", "ruleCount",
   "editor", "editHint", "editTitle", "e_id", "e_title", "e_type", "e_level",
   "e_attack", "e_tactic", "e_params", "e_err", "e_effect", "drawer"]
    .forEach(id => els[id] = document.getElementById(id));
  window.els = els;

  function clone(o) { return JSON.parse(JSON.stringify(o)); }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c])); }
  function fp(a) { return [a.rule_id, a.source_ip || "", a.user || "", +new Date(a.first_seen)].join("|"); }
  function irOf(a) { return state.ir[fp(a)] || {status: "nouveau", assignee: "", notes: "", actions: {}}; }
  function setIr(a, rec) { state.ir[fp(a)] = rec; store.set(IR_KEY, state.ir); }
  function fmt(d) { return new Date(d).toLocaleString("fr-FR"); }

  function download(name, text, type) {
    const b = new Blob([text], {type: type || "application/json"});
    const u = URL.createObjectURL(b), a = document.createElement("a");
    a.href = u; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(u), 500);
  }

  // --- Détection ----------------------------------------------------------
  function detect() {
    const ev = state.events;
    let alerts = M.runRules(state.rules, ev);
    alerts = alerts.concat(M.ctiDetectContacts(CTI, ev, alerts));
    M.ctiEnrich(alerts, CTI);
    M.enrich(alerts);
    alerts.sort((a, b) => (SEV[a.severity] - SEV[b.severity]) || (new Date(a.first_seen) - new Date(b.first_seen)));
    state.alerts = alerts;
    renderKPIs(); renderAlerts();
  }

  function renderKPIs() {
    const c = {critical: 0, high: 0, medium: 0, low: 0};
    state.alerts.forEach(a => c[a.severity]++);
    const open = state.alerts.filter(a => { const s = irOf(a).status; return s !== "resolu" && s !== "fauxpositif"; }).length;
    els.kpis.innerHTML =
      kpi(state.events.length, "Événements") + kpi(state.alerts.length, "Alertes") +
      kpi(open, "Non résolues") +
      ["critical","high","medium","low"].map(s => kpi(c[s], s, `var(--${s})`)).join("");
  }
  function kpi(n, l, col) {
    return `<div class="kpi"><div class="n"${col?` style="color:${col}"`:""}>${n}</div><div class="l">${l}</div></div>`;
  }

  function renderAlerts() {
    const q = (els.search.value || "").toLowerCase();
    const sevs = Array.from(document.querySelectorAll(".sevf:checked")).map(c => c.value);
    const openOnly = els.openOnly.checked;
    const rows = state.alerts.filter(a => {
      if (sevs.indexOf(a.severity) < 0) return false;
      if (openOnly) { const s = irOf(a).status; if (s === "resolu" || s === "fauxpositif") return false; }
      if (q) { const hay = [a.rule_id, a.title, a.source_ip, a.user, a.attack].join(" ").toLowerCase();
               if (hay.indexOf(q) < 0) return false; }
      return true;
    });
    if (!state.alerts.length) { els.rows.innerHTML = `<tr><td colspan="7" class="meta" style="padding:20px">Charge une source pour lancer la détection.</td></tr>`; return; }
    els.rows.innerHTML = rows.length ? rows.map((a, i) => {
      const rec = irOf(a), st = STATUS[rec.status];
      return `<tr onclick="App.open(${state.alerts.indexOf(a)})">
        <td><span class="sev ${a.severity}">${a.severity}</span></td>
        <td><span class="st ${st.cls}">${st.label}</span></td>
        <td>${esc(a.title)}${a.threat?` <span class="cti">connu</span>`:""}</td>
        <td>${a.source_ip?`<code>${esc(a.source_ip)}</code>`:"-"}${a.country?`<br><span class="meta">${esc(a.country)}</span>`:""}</td>
        <td>${esc(a.user)||"-"}</td><td>${a.count}</td>
        <td><span class="att">${esc(a.attack)}</span></td></tr>`;
    }).join("") : `<tr><td colspan="7" class="meta" style="padding:20px">Aucune alerte pour ces filtres.</td></tr>`;
  }

  // --- Investigation + réponse à incident (drawer) ------------------------
  function openDrawer(idx) {
    const a = state.alerts[idx];
    const rec = irOf(a);
    const rule = state.rules.find(r => r.id === a.rule_id);
    // Activité liée : mêmes IP ou compte
    const related = state.events.filter(e =>
      (a.source_ip && e.source_ip === a.source_ip) || (a.user && e.user === a.user))
      .sort((x, y) => new Date(x.timestamp) - new Date(y.timestamp));
    // Chaîne ATT&CK de l'entité
    const chain = state.alerts.filter(x =>
      (a.source_ip && x.source_ip === a.source_ip) || (a.user && x.user === a.user))
      .sort((x, y) => new Date(x.first_seen) - new Date(y.first_seen));

    els.drawer.innerHTML = `<div class="drawer-bg" onclick="if(event.target===this)App.closeDrawer()">
      <div class="drawer">
        <span class="close" onclick="App.closeDrawer()">&times;</span>
        <h2>${esc(a.title)}</h2>
        <div class="row"><span class="sev ${a.severity}">${a.severity}</span>
          <span class="att">${esc(a.attack)}</span><span class="meta">${esc(a.tactic)}</span></div>
        <p class="meta">${esc(a.description||"")}</p>
        <div class="row meta">
          <span>Source : ${a.source_ip?`<code>${esc(a.source_ip)}</code>`:"-"}
            ${a.country?`· ${esc(a.country)}${a.city?" ("+esc(a.city)+")":""}`:""}</span>
          <span>Compte : ${esc(a.user)||"-"}</span>
          <span>${a.count} occurrence(s)</span>
          <span>${fmt(a.first_seen)} → ${fmt(a.last_seen)}</span>
        </div>
        ${a.threat?`<p><span class="cti">⚠ Renseignement : connu de ${esc(a.threat.source)}
          — ${esc(a.threat.category)}, confiance ${a.threat.confidence}%</span></p>`:""}

        <h3>Réponse à incident</h3>
        <div class="row">
          <select id="ir_status">${Object.keys(STATUS).map(k =>
            `<option value="${k}"${rec.status===k?" selected":""}>${STATUS[k].label}</option>`).join("")}</select>
          <input id="ir_assignee" placeholder="Assigné à" value="${esc(rec.assignee)}" style="flex:1">
        </div>
        <div style="margin:6px 0">${Object.keys(ACTIONS).map(k =>
          `<label class="chk"><input type="checkbox" id="ir_act_${k}"${rec.actions&&rec.actions[k]?" checked":""}> ${ACTIONS[k]}</label>`).join("")}</div>
        <textarea id="ir_notes" rows="3" placeholder="Notes d'investigation...">${esc(rec.notes)}</textarea>
        <div class="row" style="margin-top:8px"><button class="primary" onclick="App.saveIr(${idx})">Enregistrer</button>
          <span class="meta" id="ir_saved"></span></div>

        <h3>Chaîne ATT&amp;CK de l'entité (${chain.length} alerte(s))</h3>
        <table><tbody>${chain.map(x =>
          `<tr><td><span class="sev ${x.severity}">${x.severity}</span></td>
            <td>${esc(x.title)}</td><td><span class="att">${esc(x.attack)}</span></td>
            <td class="meta">${esc(x.tactic)}</td></tr>`).join("")}</tbody></table>

        <h3>Activité liée (${related.length} événement(s))</h3>
        <table><thead><tr><th>Heure</th><th>Source</th><th>Type</th><th>Issue</th></tr></thead>
          <tbody>${related.slice(0, 60).map(e =>
            `<tr style="cursor:default"><td class="meta">${fmt(e.timestamp)}</td>
              <td class="meta">${esc(e.source)}</td><td>${esc(e.event_type)}</td>
              <td>${esc(e.outcome)}</td></tr>`).join("")}</tbody></table>
        ${related.length>60?`<p class="meta">… ${related.length-60} de plus</p>`:""}

        <h3>Preuves (${a.evidence.length})</h3>
        <pre>${esc(a.evidence.join("\n"))}</pre>

        <h3>Règle déclenchée</h3>
        <pre>${esc(JSON.stringify(rule||{id:a.rule_id,note:"règle interne (CTI)"}, null, 2))}</pre>
      </div></div>`;
  }
  function closeDrawer() { els.drawer.innerHTML = ""; }

  function saveIr(idx) {
    const a = state.alerts[idx];
    const actions = {};
    Object.keys(ACTIONS).forEach(k => { const el = document.getElementById("ir_act_" + k); if (el && el.checked) actions[k] = true; });
    setIr(a, {status: document.getElementById("ir_status").value,
              assignee: document.getElementById("ir_assignee").value,
              notes: document.getElementById("ir_notes").value, actions: actions});
    document.getElementById("ir_saved").textContent = "Enregistré ✓";
    renderKPIs(); renderAlerts();
  }

  function exportIncident() {
    if (!state.alerts.length) { alert("Charge d'abord une source."); return; }
    const data = state.alerts.map(a => {
      const rec = irOf(a);
      return {rule_id: a.rule_id, title: a.title, severity: a.severity, attack: a.attack,
              tactic: a.tactic, source_ip: a.source_ip, user: a.user, count: a.count,
              first_seen: a.first_seen, last_seen: a.last_seen, country: a.country || null,
              threat: a.threat || null, status: rec.status, assignee: rec.assignee,
              actions: Object.keys(rec.actions || {}), notes: rec.notes};
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
      `<div class="rulecard ${r.id===state.currentRuleId?"sel":""}" onclick="App.selectRule('${r.id}')">
        <div class="row" style="margin:0; justify-content:space-between">
          <b>${esc(r.id)}</b><span class="sev ${r.level}">${r.level}</span></div>
        <div class="meta">${esc(r.title)} · <span class="att">${esc(r.attack||"-")}</span> · ${esc(r.type)}</div>
      </div>`).join("");
  }

  function selectRule(id) {
    const r = state.rules.find(x => x.id === id);
    if (!r) return;
    state.currentRuleId = id;
    els.editor.classList.remove("hidden"); els.editHint.classList.add("hidden");
    els.editTitle.textContent = "Éditeur — " + id;
    els.e_id.value = r.id; els.e_title.value = r.title || ""; els.e_type.value = r.type || "match";
    els.e_level.value = r.level || "medium"; els.e_attack.value = r.attack || ""; els.e_tactic.value = r.tactic || "";
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

  function saveRule() {
    let params;
    try { params = JSON.parse(els.e_params.value || "{}"); }
    catch (e) { els.e_err.textContent = "JSON invalide : " + e.message; els.e_err.classList.remove("hidden"); return; }
    if (!els.e_id.value.trim()) { els.e_err.textContent = "L'id est obligatoire."; els.e_err.classList.remove("hidden"); return; }
    els.e_err.classList.add("hidden");
    const idx = state.rules.findIndex(r => r.id === state.currentRuleId);
    const rule = Object.assign({id: els.e_id.value.trim(), title: els.e_title.value,
      type: els.e_type.value, level: els.e_level.value,
      attack: els.e_attack.value, tactic: els.e_tactic.value}, params);
    if (idx >= 0) state.rules[idx] = rule; else state.rules.push(rule);
    state.currentRuleId = rule.id;
    persistRules();
    const before = state.alerts.length;
    detect();
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
    if (!confirm("Réinitialiser toutes les règles aux valeurs par défaut ?")) return;
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
    const names = {auth: "Exemple SSH", web: "Exemple web", win: "Exemple Windows"};
    analyzeText(window.MINISIEM_SAMPLES[key], names[key]);
  }
  function loadAll() {
    const s = window.MINISIEM_SAMPLES;
    analyzeText([s.auth, s.web, s.win].join("\n"), "Toutes les sources");
  }

  // --- Navigation ---------------------------------------------------------
  function tab(name) {
    document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
    document.getElementById("tab-detect").classList.toggle("hidden", name !== "detect");
    document.getElementById("tab-rules").classList.toggle("hidden", name !== "rules");
    if (name === "rules") renderRuleList();
  }

  els.file.addEventListener("change", e => {
    const f = e.target.files[0]; if (!f) return;
    const r = new FileReader(); r.onload = () => analyzeText(r.result, f.name); r.readAsText(f);
  });

  window.App = {tab, loadSample, loadAll, renderAlerts, open: openDrawer, closeDrawer,
    saveIr, exportIncident, selectRule, newRule, saveRule, deleteRule, resetRules, exportRules};

  renderRuleList();
})();
