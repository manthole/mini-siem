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
  // « 0x00001410 » -> « 0x1410 » : même écriture quel que soit l'outil d'export
  function hex(v) {
    if (!v) return null;
    const t = String(v).trim();
    return /^(0x)?[0-9a-f]+$/i.test(t) ? "0x" + parseInt(t, 16).toString(16) : t.toLowerCase();
  }

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
      ev.granted_access = hex(data.GrantedAccess);
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
            evidence: evs.slice(0, 8).map(e => e.raw),
            host: first.host && first.host !== "-" ? first.host : null, grouped_in: null};
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

  // --- Corrélation entre règles : plusieurs détections différentes sur une même
  // entité (l'hôte par défaut) dans une fenêtre -> un seul incident. Les alertes
  // regroupées sont marquées (grouped_in) pour pouvoir les replier dans la console.
  function pad(n) { return String(n).padStart(2, "0"); }
  function stamp(d) {
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
           `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }
  function chainAlert(rule, members) {
    members.forEach(a => { a.grouped_in = rule.id; });
    const pick = f => (members.find(a => a[f]) || {})[f] || null;
    return {rule_id: rule.id, title: rule.title, severity: rule.level || "high",
            attack: rule.attack || "-", tactic: rule.tactic || "-",
            source_ip: pick("source_ip"), user: pick("user"),
            first_seen: new Date(Math.min(...members.map(a => +a.first_seen))),
            last_seen: new Date(Math.max(...members.map(a => +a.last_seen))),
            count: members.length, description: rule.description || "",
            evidence: members.map(a => `${stamp(a.first_seen)} [${a.severity}] ${a.rule_id} — ${a.title} (${a.attack})`),
            host: members[0].host, grouped_in: null};
  }
  function runCorrelation(rule, alerts) {
    const wanted = new Set(rule.rules || []);
    const gb = rule.group_by || ["host"];
    const win = (rule.window_seconds || 900) * 1000, need = rule.min_rules || 2;
    const buckets = {};
    for (const a of alerts) {
      if (!wanted.has(a.rule_id) || a.grouped_in) continue;
      if (gb.some(f => a[f] == null)) continue;
      const k = gb.map(f => a[f]).join("||");
      (buckets[k] = buckets[k] || []).push(a);
    }
    const out = [];
    for (const g of Object.values(buckets)) {
      g.sort((x, y) => (x.first_seen - y.first_seen) || (x.rule_id < y.rule_id ? -1 : x.rule_id > y.rule_id ? 1 : 0));
      let i = 0;
      while (i < g.length) {
        let j = i;
        while (j + 1 < g.length && g[j + 1].first_seen - g[i].first_seen <= win) j++;
        const members = g.slice(i, j + 1);
        if (new Set(members.map(a => a.rule_id)).size >= need) { out.push(chainAlert(rule, members)); i = j + 1; }
        else i++;
      }
    }
    return out;
  }

  // Règles sur les événements d'abord, puis corrélations sur les alertes obtenues
  function runRules(rules, events) {
    let alerts = [];
    const correlations = [];
    for (const rule of rules) {
      if (rule.type === "correlation") { correlations.push(rule); continue; }
      const runner = RUNNERS[rule.type || "match"];
      if (runner) alerts = alerts.concat(runner(rule, events));
    }
    for (const rule of correlations) alerts = alerts.concat(runCorrelation(rule, alerts));
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


  // --- Fichiers .evtx binaires (portage de minisiem/evtx.py) --------------
  // En-tête de 4 Ko, blocs de 64 Ko, événements en XML binaire (jetons + modèles
  // partagés + valeurs typées). Chaque événement est rendu en XML texte, puis lu
  // par parseEvtxBlock comme un export classique.
  const EVTX = (function () {
    const MAGIC = "ElfFile\0", CHUNK = 0x10000, CHUNK_HDR = 0x200, REC = 0x2a2a;
    const T = {NULL: 0, WSTR: 1, STR: 2, I8: 3, U8: 4, I16: 5, U16: 6, I32: 7, U32: 8,
               I64: 9, U64: 10, R32: 11, R64: 12, BOOL: 13, BIN: 14, GUID: 15, SIZET: 16,
               FT: 17, ST: 18, SID: 19, H32: 20, H64: 21, BINXML: 33};
    const FIXED = {3: 1, 4: 1, 5: 2, 6: 2, 7: 4, 8: 4, 9: 8, 10: 8, 11: 4, 12: 8, 13: 4,
                   15: 16, 17: 8, 18: 16, 20: 4, 21: 8};
    const BAD = /[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]/g;
    const dec16 = new TextDecoder("utf-16le"), dec8 = new TextDecoder("latin1");
    const xmlText = s => s.replace(BAD, "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const xmlAttr = s => xmlText(s).replace(/"/g, "&quot;");
    const hexOf = (b) => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");

    function isEvtx(bytes) {
      if (bytes.length < 8) return false;
      for (let i = 0; i < 8; i++) if (bytes[i] !== MAGIC.charCodeAt(i)) return false;
      return true;
    }

    function filetime(ticks) {                       // BigInt, centaines de ns depuis 1601
      const sec = ticks / 10000000n, frac = ticks % 10000000n;
      const d = new Date(Number(sec - 11644473600n) * 1000);
      return d.toISOString().slice(0, 19) + "." + frac.toString().padStart(7, "0") + "Z";
    }

    function Chunk(b) { this.b = b; this.dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
                        this.names = new Map(); this.templates = new Map(); }
    const C = Chunk.prototype;
    C.u16 = function (p) { return this.dv.getUint16(p, true); };
    C.u32 = function (p) { return this.dv.getUint32(p, true); };
    C.utf16 = function (p, n) { return dec16.decode(this.b.subarray(p, p + 2 * n)); };
    C.name = function (off, pos) {
      if (!this.names.has(off)) { const n = this.u16(off + 6); this.names.set(off, [this.utf16(off + 8, n), 10 + 2 * n]); }
      const [text, len] = this.names.get(off);
      return [text, off === pos ? pos + len : pos];
    };
    C.records = function () {
      const out = [];
      const free = Math.min(this.u32(0x30) || this.b.length, this.b.length);
      let pos = CHUNK_HDR;
      while (pos + 28 <= free) {
        const magic = this.u32(pos), size = this.u32(pos + 4);
        if (magic !== REC || size < 28 || pos + size > this.b.length) break;
        try { out.push(this.renderFragment(pos + 24)); } catch (e) { /* enregistrement abîmé */ }
        pos += size;
      }
      return out;
    };
    C.renderFragment = function (pos) { const out = []; this.render(this.fragment(pos)[0], [], out); return out.join(""); };
    C.fragment = function (pos) {
      const nodes = [];
      for (;;) {
        if (pos >= this.b.length) throw new Error("fin inattendue");
        const tok = this.b[pos];
        if (tok === 0x00) return [nodes, pos + 1];
        if (tok === 0x0f) pos += 4;
        else if (tok === 0x0c) { const r = this.templateInstance(pos); nodes.push(r[0]); return [nodes, r[1]]; }
        else if ((tok & 0x0f) === 0x01) { const r = this.element(pos); nodes.push(r[0]); pos = r[1]; }
        else throw new Error("jeton inattendu " + tok);
      }
    };
    C.element = function (pos) {
      const hasAttrs = this.b[pos] & 0x40;
      pos += 7;
      let name; [name, pos] = this.name(this.u32(pos), pos + 4);
      const attrs = [];
      if (hasAttrs) {
        const end = pos + 4 + this.u32(pos);
        pos += 4;
        while (pos < end) {
          const tok = this.b[pos];
          if ((tok & 0x0f) !== 0x06) throw new Error("attribut attendu");
          let an; [an, pos] = this.name(this.u32(pos + 1), pos + 5);
          let content; [content, pos] = this.content(pos, false);
          attrs.push([an, content]);
          if (!(tok & 0x40)) break;
        }
      }
      let tok = this.b[pos];
      if (tok === 0x03) return [["elem", name, attrs, null], pos + 1];
      if (tok !== 0x02) throw new Error("fin de balise attendue");
      pos++;
      const children = [];
      for (;;) {
        tok = this.b[pos];
        if (tok === 0x04) return [["elem", name, attrs, children], pos + 1];
        if ((tok & 0x0f) === 0x01) { const r = this.element(pos); children.push(r[0]); pos = r[1]; }
        else { const r = this.content(pos, true); children.push(...r[0]); pos = r[1]; }
      }
    };
    C.content = function (pos, single) {
      const out = [];
      for (;;) {
        const tok = this.b[pos], base = tok & 0x0f;
        if (base === 0x05) {
          if (this.b[pos + 1] !== T.WSTR) throw new Error("valeur non textuelle");
          const n = this.u16(pos + 2); out.push(["text", this.utf16(pos + 4, n)]); pos += 4 + 2 * n;
        } else if (tok === 0x0d || tok === 0x0e) {
          out.push(["subst", this.u16(pos + 1), tok === 0x0e]); pos += 4;
        } else if (base === 0x08) {
          out.push(["raw", "&#" + this.u16(pos + 1) + ";"]); pos += 3;
        } else if (base === 0x09) {
          let en; [en, pos] = this.name(this.u32(pos + 1), pos + 5); out.push(["raw", "&" + en + ";"]);
        } else if (base === 0x07) {
          const n = this.u16(pos + 1); out.push(["text", this.utf16(pos + 3, n)]); pos += 3 + 2 * n;
        } else if (tok === 0x0a) {
          let target; [target, pos] = this.name(this.u32(pos + 1), pos + 5);
          let data = "";
          if (this.b[pos] === 0x0b) { const n = this.u16(pos + 1); data = this.utf16(pos + 3, n); pos += 3 + 2 * n; }
          out.push(["raw", "<?" + target + " " + data + "?>"]);
        } else {
          if (!out.length) throw new Error("valeur attendue");
          return [out, pos];
        }
        if (single) return [out, pos];
      }
    };
    C.templateInstance = function (pos) {
      const def = this.u32(pos + 6);
      pos += 10;
      if (!this.templates.has(def)) this.templates.set(def, this.fragment(def + 24)[0]);
      if (def === pos) pos = def + 24 + this.u32(def + 20);
      const count = this.u32(pos); pos += 4;
      const descs = [];
      for (let i = 0; i < count; i++) descs.push([this.u16(pos + 4 * i), this.b[pos + 4 * i + 2]]);
      pos += 4 * count;
      const values = [];
      for (const [size, type] of descs) { values.push([type, pos, size]); pos += size; }
      return [["tmpl", this.templates.get(def), values], pos];
    };
    C.render = function (nodes, values, out) {
      for (const node of nodes) {
        if (node[0] === "tmpl") { this.render(node[1], node[2], out); continue; }
        if (node[0] !== "elem") continue;
        const [, name, attrs, children] = node;
        out.push("<" + name);
        for (const [an, content] of attrs) {
          const text = this.textOf(content, values);
          if (text !== null) out.push(" " + an + '="' + xmlAttr(text) + '"');
        }
        if (children === null) { out.push("/>"); continue; }
        out.push(">");
        for (const c of children) {
          if (c[0] === "elem" || c[0] === "tmpl") this.render([c], values, out);
          else if (c[0] === "subst") out.push(this.valueXml(values, c[1]));
          else if (c[0] === "raw") out.push(c[1]);
          else out.push(xmlText(c[1]));
        }
        out.push("</" + name + ">");
      }
    };
    C.textOf = function (content, values) {
      const parts = [];
      for (const c of content) {
        if (c[0] === "subst") {
          const v = this.value(values, c[1]);
          if (v === null && c[2] && content.length === 1) return null;
          parts.push(v || "");
        } else parts.push(c[1]);
      }
      return parts.join("");
    };
    C.valueXml = function (values, i) {
      if (i >= values.length) return "";
      const [type, pos, size] = values[i];
      if (type === T.BINXML) return size ? this.renderFragment(pos) : "";
      return xmlText(this.value(values, i) || "");
    };
    C.value = function (values, i) {
      if (i >= values.length) return null;
      const [type, pos, size] = values[i];
      if (type === T.NULL || size === 0) return null;
      const raw = this.b.subarray(pos, pos + size);
      if (type & 0x80) return splitArray(type & 0x7f, raw).map(x => scalar(type & 0x7f, x)).join(", ");
      return scalar(type, raw);
    };

    function splitArray(type, raw) {
      if (type === T.WSTR) return dec16.decode(raw).split("\0").filter(Boolean).map(s => {
        const u = new Uint8Array(s.length * 2); for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); u[2*i] = c & 255; u[2*i+1] = c >> 8; } return u; });
      if (type === T.STR) { const parts = []; let st = 0; for (let i = 0; i <= raw.length; i++) if (i === raw.length || raw[i] === 0) { if (i > st) parts.push(raw.subarray(st, i)); st = i + 1; } return parts; }
      const w = FIXED[type];
      if (!w) return [raw];
      const out = []; for (let i = 0; i + w <= raw.length; i += w) out.push(raw.subarray(i, i + w)); return out;
    }

    function scalar(type, raw) {
      const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
      switch (type) {
        case T.WSTR: return dec16.decode(raw).replace(/\0+$/, "");
        case T.STR: return dec8.decode(raw).replace(/\0+$/, "");
        case T.I8: return String(dv.getInt8(0));
        case T.U8: return String(dv.getUint8(0));
        case T.I16: return String(dv.getInt16(0, true));
        case T.U16: return String(dv.getUint16(0, true));
        case T.I32: return String(dv.getInt32(0, true));
        case T.U32: return String(dv.getUint32(0, true));
        case T.I64: return dv.getBigInt64(0, true).toString();
        case T.U64: return dv.getBigUint64(0, true).toString();
        case T.H32: return "0x" + dv.getUint32(0, true).toString(16);
        case T.H64: return "0x" + dv.getBigUint64(0, true).toString(16).padStart(16, "0");
        case T.SIZET: { let v = 0n; for (let i = raw.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(raw[i]); return "0x" + v.toString(16).padStart(2 * raw.length, "0"); }
        case T.BOOL: return dv.getUint32(0, true) ? "true" : "false";
        case T.R32: return String(dv.getFloat32(0, true));
        case T.R64: return String(dv.getFloat64(0, true));
        case T.FT: return filetime(dv.getBigUint64(0, true));
        case T.ST: {
          const v = i => dv.getUint16(2 * i, true), p = (n, w) => String(n).padStart(w, "0");
          return `${p(v(0), 4)}-${p(v(1), 2)}-${p(v(3), 2)}T${p(v(4), 2)}:${p(v(5), 2)}:${p(v(6), 2)}.${p(v(7), 3)}Z`;
        }
        case T.GUID: {
          const h = (n, w) => n.toString(16).toUpperCase().padStart(w, "0");
          return "{" + h(dv.getUint32(0, true), 8) + "-" + h(dv.getUint16(4, true), 4) + "-" + h(dv.getUint16(6, true), 4) +
                 "-" + hexOf(raw.subarray(8, 10)).toUpperCase() + "-" + hexOf(raw.subarray(10, 16)).toUpperCase() + "}";
        }
        case T.SID: {
          const count = raw[1];
          let auth = 0; for (let i = 2; i < 8; i++) auth = auth * 256 + raw[i];
          const subs = []; for (let i = 0; i < count; i++) subs.push(dv.getUint32(8 + 4 * i, true));
          return "S-" + [raw[0], auth, ...subs].join("-");
        }
        case T.BIN: return hexOf(raw).toUpperCase();
        default: return "";
      }
    }

    function read(bytes) {
      if (!isEvtx(bytes)) throw new Error("ce n'est pas un fichier .evtx");
      const start = (bytes[0x28] | (bytes[0x29] << 8)) || 0x1000;
      const out = [];
      for (let off = start; off + CHUNK_HDR <= bytes.length; off += CHUNK) {
        const chunk = bytes.subarray(off, Math.min(off + CHUNK, bytes.length));
        if (String.fromCharCode(...chunk.subarray(0, 8)) === "ElfChnk\0") out.push(...new Chunk(chunk).records());
      }
      return out;
    }
    return {isEvtx, read};
  })();

  // Octets d'un fichier .evtx -> événements normalisés
  function parseEvtx(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
    return EVTX.read(bytes).map(parseEvtxBlock).filter(Boolean);
  }

  root.MiniSIEM = {parseText, parseAuth, parseApache, parseUfw, parseEvtxBlock,
                   parseEvtx, isEvtx: EVTX.isEvtx, readEvtx: EVTX.read,
                   runRules, matches, matchField, selected, enrich, SEVERITY_ORDER, GEO,
                   ctiIndex, ctiEnrich, ctiDetectContacts};
  if (typeof module !== "undefined" && module.exports) module.exports = root.MiniSIEM;
})(typeof window !== "undefined" ? window : globalThis);
