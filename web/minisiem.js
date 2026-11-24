/* mini-SIEM — moteur de détection porté en JavaScript.
 *
 * Même logique que la version Python (parsers + règles), pour tourner
 * entièrement dans le navigateur : aucune donnée n'est envoyée à un serveur.
 * Compatible navigateur (window.MiniSIEM) et Node (module.exports) pour les tests.
 */
(function (root) {
  "use strict";

  const MONTHS = {Jan:1,Feb:2,Mar:3,Apr:4,May:5,Jun:6,Jul:7,Aug:8,Sep:9,Oct:10,Nov:11,Dec:12};

  function mkDate(mon, day, time, year) {
    const [h, mi, s] = time.split(":").map(Number);
    return new Date(year, MONTHS[mon] - 1, +day, h, mi, s);
  }

  // --- Parsers ------------------------------------------------------------
  const RE_SYSLOG = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+)(?:\[(\d+)\])?:\s+(.*)$/;
  const RE_FAILED = /Failed password for (?:invalid user )?(\S+) from ([\d.:a-fA-F]+)/;
  const RE_ACCEPT = /Accepted \w+ for (\S+) from ([\d.:a-fA-F]+)/;
  const RE_INVALID = /Invalid user (\S+) from ([\d.:a-fA-F]+)/;
  const RE_SUDO_FAIL = /(\S+) : (?:command not allowed|user NOT in sudoers)/;
  const RE_SUDO = /(\S+) : .*COMMAND=(.*)$/;

  function parseAuth(line, year) {
    const m = RE_SYSLOG.exec(line);
    if (!m) return null;
    const [, mon, day, time, host, proc, , msg] = m;
    const ts = mkDate(mon, day, time, year);
    const base = {timestamp: ts, source: "auth.log", host: host, raw: line};
    if (proc === "sshd") {
      let f;
      if ((f = RE_FAILED.exec(msg))) return Object.assign({event_type:"ssh_login",outcome:"failure",user:f[1],source_ip:f[2]}, base);
      if ((f = RE_ACCEPT.exec(msg))) return Object.assign({event_type:"ssh_login",outcome:"success",user:f[1],source_ip:f[2]}, base);
      if ((f = RE_INVALID.exec(msg))) return Object.assign({event_type:"ssh_login",outcome:"failure",user:f[1],source_ip:f[2]}, base);
    }
    if (proc === "sudo") {
      let f;
      if ((f = RE_SUDO_FAIL.exec(msg))) return Object.assign({event_type:"sudo",outcome:"failure",user:f[1]}, base);
      if ((f = RE_SUDO.exec(msg))) return Object.assign({event_type:"sudo",outcome:"success",user:f[1]}, base);
    }
    return null;
  }

  const RE_APACHE = /^([\d.:a-fA-F]+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)\s+[^"]*"\s+(\d{3})\s+(\S+)(?:\s+"[^"]*"\s+"([^"]*)")?/;
  const APACHE_MON = MONTHS;
  function parseApache(line) {
    const m = RE_APACHE.exec(line);
    if (!m) return null;
    const tm = /^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})/.exec(m[2]);
    if (!tm) return null;
    const ts = new Date(+tm[3], APACHE_MON[tm[2]] - 1, +tm[1], +tm[4], +tm[5], +tm[6]);
    const status = +m[5];
    return {timestamp: ts, source: "access.log", event_type: "web_request",
            outcome: status >= 400 ? "failure" : "success", source_ip: m[1],
            method: m[3], url: m[4], status: status, user_agent: m[7] || "-", raw: line};
  }

  const RE_UFW_KV = /\b([A-Z]+)=(\S+)/g;
  function parseUfw(line, year) {
    if (line.indexOf("UFW BLOCK") < 0 && line.toLowerCase().indexOf("iptables") < 0) return null;
    const m = RE_SYSLOG.exec(line);
    if (!m) return null;
    const ts = mkDate(m[1], m[2], m[3], year);
    const kv = {}; let g;
    RE_UFW_KV.lastIndex = 0;
    while ((g = RE_UFW_KV.exec(m[7]))) kv[g[1]] = g[2];
    if (!kv.SRC) return null;
    return {timestamp: ts, source: "ufw.log", event_type: "fw_block", outcome: "blocked",
            host: m[4], source_ip: kv.SRC, proto: kv.PROTO,
            dest_port: kv.DPT ? +kv.DPT : null, raw: line};
  }

  const EVTX_MAP = {4625:["win_logon","failure"],4624:["win_logon","success"],
    4672:["win_special_priv","info"],4720:["win_account_created","info"],
    4732:["win_group_add","info"],1102:["win_log_cleared","info"]};
  // Sysmon : EventID -> catégorie de journal Sigma, reprise comme event_type
  const SYSMON_MAP = {1:"process_creation", 3:"network_connection", 10:"process_access",
    11:"file_event", 13:"registry_set", 22:"dns_query"};

  const XML_ENT = {amp:"&", lt:"<", gt:">", quot:'"', apos:"'"};
  function xmlText(s) {
    return s.replace(/&(#x[0-9a-fA-F]+|#\d+|amp|lt|gt|quot|apos);/g, (m, e) =>
      e[0] !== "#" ? XML_ENT[e] :
      String.fromCodePoint(e[1] === "x" ? parseInt(e.slice(2), 16) : +e.slice(1)));
  }
  function bareUser(u) { return u ? u.split("\\").pop() : null; }

  function sysmonEvent(eid, ts, host, data, raw) {
    const ev = {timestamp: ts, source: "sysmon", event_type: SYSMON_MAP[eid], outcome: "info",
                host: host, event_id: eid, raw: raw,
                user: bareUser(data.User || data.SourceUser)};
    if (eid === 1) {
      ev.process = data.Image; ev.parent_process = data.ParentImage;
      ev.command_line = data.CommandLine; ev.detail = data.IntegrityLevel;
    } else if (eid === 3) {
      ev.process = data.Image; ev.source_ip = data.SourceIp || null;
      ev.dest_ip = data.DestinationIp || null;
      ev.dest_port = /^\d+$/.test((data.DestinationPort || "").trim()) ? +data.DestinationPort : null;
      ev.proto = data.Protocol; ev.target = data.DestinationHostname || null;
    } else if (eid === 10) {
      ev.process = data.SourceImage; ev.target = data.TargetImage;
      ev.granted_access = (data.GrantedAccess || "").toLowerCase() || null;
    } else if (eid === 11) {
      ev.process = data.Image; ev.target = data.TargetFilename;
    } else if (eid === 13) {
      ev.process = data.Image; ev.target = data.TargetObject; ev.detail = data.Details;
    } else if (eid === 22) {
      ev.process = data.Image; ev.target = data.QueryName; ev.detail = data.QueryResults;
    }
    return ev;
  }

  function parseEvtxBlock(block) {
    const eidM = /<EventID\b[^>]*>\s*(\d+)\s*<\/EventID>/.exec(block);
    if (!eidM) return null;
    const eid = +eidM[1];
    const prov = (/<Provider\b[^>]*\bName=["']([^"']*)["']/.exec(block) || [, ""])[1];
    const chan = (/<Channel>([^<]*)<\/Channel>/.exec(block) || [, ""])[1];
    const sysmon = /sysmon/i.test(prov + " " + chan);
    if (!(sysmon ? SYSMON_MAP : EVTX_MAP)[eid]) return null;
    const tM = /<TimeCreated\b[^>]*\bSystemTime=["']([^"']+)["']/.exec(block);
    if (!tM) return null;
    const ts = new Date(tM[1].trim());
    if (isNaN(ts)) return null;
    const host = xmlText((/<Computer>([^<]*)<\/Computer>/.exec(block) || [,"-"])[1]) || "-";
    const data = {}; let d;
    const RE_DATA = /<Data Name=["']([^"']+)["']\s*>([^<]*)<\/Data>/g;
    while ((d = RE_DATA.exec(block))) data[d[1]] = xmlText(d[2]);
    const raw = block.split(/\s+/).filter(Boolean).join(" ");
    if (sysmon) return sysmonEvent(eid, ts, host, data, raw);
    const [etype, outcome] = EVTX_MAP[eid];
    let user = data.TargetUserName || data.SubjectUserName || null;
    let ip = data.IpAddress || null;
    if (ip === "-" || ip === "::1" || ip === "127.0.0.1" || ip === "") ip = null;
    let detail = null;
    if (eid === 4732) { detail = data.TargetUserName; user = data.MemberName || user; }
    else if (eid === 4625 || eid === 4624) detail = data.LogonType;
    return {timestamp: ts, source: "windows", event_type: etype, outcome: outcome,
            host: host, source_ip: ip, user: user, event_id: eid, detail: detail,
            raw: raw};
  }

  // Accepte un fichier XML Windows (Sécurité ou Sysmon), un journal texte, ou un
  // mélange des deux : les blocs <Event> sont extraits, le reste lu ligne à ligne.
  function parseText(text, year) {
    year = year || new Date().getFullYear();
    const events = [];
    const RE_BLOCK = /<Event\b[\s\S]*?<\/Event>/g;
    for (const b of text.match(RE_BLOCK) || []) { const e = parseEvtxBlock(b); if (e) events.push(e); }
    for (const line of text.replace(RE_BLOCK, "\n").split(/\r?\n/)) {
      if (!line.trim()) continue;
      const e = parseUfw(line, year) || parseAuth(line, year) || parseApache(line);
      if (e) events.push(e);
    }
    return events;
  }

  // --- Moteur de règles ---------------------------------------------------
  function asList(v) { return Array.isArray(v) ? v : [v]; }

  function matchField(value, expected) {
    if (expected && typeof expected === "object" && !Array.isArray(expected)) {
      for (const op of Object.keys(expected)) {
        const operand = expected[op];
        if (op === "contains") {
          const hay = String(value == null ? "" : value).toLowerCase();
          if (!asList(operand).some(o => hay.indexOf(String(o).toLowerCase()) >= 0)) return false;
        } else if (op === "endswith") {
          const hay = String(value == null ? "" : value).toLowerCase();
          if (value == null || !asList(operand).some(o => hay.endsWith(String(o).toLowerCase()))) return false;
        } else if (op === "regex") {
          if (value == null || !new RegExp(operand, "i").test(String(value))) return false;
        } else if (op === "in") {
          if (asList(operand).indexOf(value) < 0) return false;
        } else if (op === "gte") {
          if (value == null || value < operand) return false;
        } else if (op === "lte") {
          if (value == null || value > operand) return false;
        } else return false;
      }
      return true;
    }
    if (Array.isArray(expected)) return expected.indexOf(value) >= 0;
    return value === expected;
  }

  function matches(ev, cond) {
    for (const f of Object.keys(cond || {})) if (!matchField(ev[f], cond[f])) return false;
    return true;
  }

  // Sélection (ou precondition / trigger) moins le filtre d'exclusion de la règle
  function selected(ev, rule, key) {
    if (!matches(ev, rule[key || "selection"])) return false;
    return !(rule.filter && matches(ev, rule.filter));
  }

  function keyOf(ev, groupBy) { return groupBy.map(g => ev[g]).join("||"); }

  function alertFrom(rule, evs) {
    evs = evs.slice().sort((a, b) => a.timestamp - b.timestamp);
    const first = evs[0], last = evs[evs.length - 1];
    return {rule_id: rule.id, title: rule.title, severity: rule.level, attack: rule.attack,
            tactic: rule.tactic || "-", source_ip: first.source_ip || null,
            user: first.user || null, first_seen: first.timestamp, last_seen: last.timestamp,
            count: evs.length, description: rule.description || "",
            evidence: evs.slice(0, 8).map(e => e.raw)};
  }

  function runMatch(rule, events) {
    const gb = rule.group_by || ["source_ip", "user"];
    const buckets = {};
    for (const e of events) if (selected(e, rule))
      (buckets[keyOf(e, gb)] = buckets[keyOf(e, gb)] || []).push(e);
    return Object.values(buckets).map(g => alertFrom(rule, g));
  }

  function runThreshold(rule, events) {
    const gb = rule.group_by || ["source_ip"];
    const win = (rule.window_seconds || 300) * 1000;
    const thr = rule.count || 10, distinct = rule.distinct;
    const buckets = {};
    for (const e of events) if (selected(e, rule))
      (buckets[keyOf(e, gb)] = buckets[keyOf(e, gb)] || []).push(e);
    const reached = w => distinct
      ? new Set(w.map(e => e[distinct])).size >= thr : w.length >= thr;
    const alerts = [];
    for (const group of Object.values(buckets)) {
      group.sort((a, b) => a.timestamp - b.timestamp);
      let start = 0;
      for (let end = 0; end < group.length; end++) {
        while (group[end].timestamp - group[start].timestamp > win) start++;
        if (reached(group.slice(start, end + 1))) { alerts.push(alertFrom(rule, group.slice(start, end + 1))); break; }
      }
    }
    return alerts;
  }

  function runSequence(rule, events) {
    const gb = rule.group_by || ["source_ip"];
    const win = (rule.window_seconds || 600) * 1000;
    const minPre = rule.min_preconditions || 1;
    const pending = {}, alerts = [];
    const ordered = events.slice().sort((a, b) => a.timestamp - b.timestamp);
    for (const e of ordered) {
      const k = keyOf(e, gb);
      if (selected(e, rule, "precondition")) (pending[k] = pending[k] || []).push(e);
      else if (selected(e, rule, "trigger")) {
        const befores = (pending[k] || []).filter(p => e.timestamp - p.timestamp >= 0 && e.timestamp - p.timestamp <= win);
        if (befores.length >= minPre) { alerts.push(alertFrom(rule, befores.concat([e]))); pending[k] = []; }
      }
    }
    return alerts;
  }

  function runBaselineHour(rule, events) {
    const gb = rule.group_by || ["user"];
    const minSup = rule.min_support || 2;
    const byUser = {};
    for (const e of events) if (selected(e, rule))
      (byUser[keyOf(e, gb)] = byUser[keyOf(e, gb)] || []).push(e);
    const alerts = [];
    for (const group of Object.values(byUser)) {
      const hours = {};
      for (const e of group) { const h = e.timestamp.getHours(); hours[h] = (hours[h] || 0) + 1; }
      const usual = new Set(Object.keys(hours).filter(h => hours[h] >= minSup).map(Number));
      if (!usual.size) continue;
      const odd = group.filter(e => !usual.has(e.timestamp.getHours()));
      if (odd.length) alerts.push(alertFrom(rule, odd));
    }
    return alerts;
  }

  const RUNNERS = {match: runMatch, threshold: runThreshold,
                   sequence: runSequence, baseline_hour: runBaselineHour};

  function runRules(rules, events) {
    let alerts = [];
    for (const rule of rules) {
      const runner = RUNNERS[rule.type || "match"];
      if (runner) alerts = alerts.concat(runner(rule, events));
    }
    return alerts;
  }

  // --- Enrichissement GeoIP (table de démo) -------------------------------
  const GEO = {
    "203.0.113.66": {country:"Russie",city:"Moscou",lat:55.7558,lon:37.6173},
    "198.51.100.23": {country:"Chine",city:"Shanghai",lat:31.2304,lon:121.4737},
    "203.0.113.9":   {country:"Pays-Bas",city:"Amsterdam",lat:52.3676,lon:4.9041},
    "198.51.100.77": {country:"Brésil",city:"São Paulo",lat:-23.5505,lon:-46.6333},
    "203.0.113.200": {country:"Iran",city:"Téhéran",lat:35.6892,lon:51.3890}
  };
  function enrich(alerts) {
    for (const a of alerts) { const g = GEO[a.source_ip]; if (g) Object.assign(a, g); }
    return alerts;
  }

  const SEVERITY_ORDER = {critical:0, high:1, medium:2, low:3};

  // --- CTI : renseignement sur les menaces --------------------------------
  const CATEGORY_ATTACK = {c2:["T1071","Command and Control"],
    bruteforce:["T1110","Credential Access"], scanner:["T1595","Reconnaissance"],
    exploit:["T1190","Initial Access"], malware:["T1105","Command and Control"],
    tool:["T1595.002","Reconnaissance"]};
  function sevFromConf(c){ return c>=90?"critical":c>=75?"high":"medium"; }

  function ctiIndex(feed) {
    const ip = {};
    (feed && feed.indicators || []).forEach(i => { if (i.type === "ip") ip[i.value] = i; });
    return {name: (feed && feed.feed) || "aucun", ip: ip,
            indicators: (feed && feed.indicators) || []};
  }

  function ctiEnrich(alerts, cti) {
    let n = 0;
    for (const a of alerts) {
      const ind = cti.ip[a.source_ip];
      if (!ind) continue;
      a.threat = {feed: cti.name, source: ind.source || cti.name,
                  category: ind.category || "?", confidence: ind.confidence || 0};
      n++;
      if (["c2","exploit","malware"].indexOf(ind.category) >= 0 && (ind.confidence||0) >= 90)
        a.severity = "critical";
    }
    return n;
  }

  function ctiDetectContacts(cti, events, existing) {
    const already = new Set(existing.map(a => a.source_ip).filter(Boolean));
    const byIp = {};
    for (const e of events)                    // source puis destination (Sysmon 3)
      for (const ip of new Set([e.source_ip, e.dest_ip]))
        if (ip && cti.ip[ip] && !already.has(ip)) (byIp[ip] = byIp[ip] || []).push(e);
    const alerts = [];
    for (const ip of Object.keys(byIp)) {
      const evs = byIp[ip].sort((a,b)=>a.timestamp-b.timestamp);
      const ind = cti.ip[ip], conf = ind.confidence || 50;
      const [attack, tactic] = CATEGORY_ATTACK[ind.category] || ["T1071","Command and Control"];
      alerts.push({rule_id:"THREAT_INTEL_HIT",
        title:`Contact avec une IP malveillante connue (${ind.category||"?"})`,
        severity:sevFromConf(conf), attack:attack, tactic:tactic, source_ip:ip,
        user:evs[0].user||null, first_seen:evs[0].timestamp, last_seen:evs[evs.length-1].timestamp,
        count:evs.length, description:`IP référencée par ${ind.source||cti.name} (confiance ${conf}%).`,
        threat:{feed:cti.name, source:ind.source||cti.name, category:ind.category||"?", confidence:conf},
        evidence:evs.slice(0,8).map(e=>e.raw)});
    }
    return alerts;
  }

  root.MiniSIEM = {parseText, parseAuth, parseApache, parseUfw, parseEvtxBlock,
                   runRules, matches, matchField, selected, enrich, SEVERITY_ORDER, GEO,
                   ctiIndex, ctiEnrich, ctiDetectContacts};
  if (typeof module !== "undefined" && module.exports) module.exports = root.MiniSIEM;
})(typeof window !== "undefined" ? window : globalThis);
