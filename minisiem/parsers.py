"""Parsers : ligne brute -> Event normalisé.

V1 ne couvre que auth.log (Linux/SSH/sudo). Chaque source future (Apache,
EVTX, pare-feu) ajoutera son propre parser ici, en produisant le même Event.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from .events import Event

# auth.log classique : "Nov  8 13:37:01 web01 sshd[1234]: <message>"
# L'année n'est pas dans la ligne : on la passe en paramètre (défaut = année courante).
_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>\w+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# Sous-motifs sur le message sshd/sudo
_FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_ACCEPTED = re.compile(r"Accepted \w+ for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_SUDO = re.compile(r"(?P<user>\S+) : .*COMMAND=(?P<cmd>.*)$")
_SUDO_FAIL = re.compile(r"(?P<user>\S+) : (?:command not allowed|user NOT in sudoers)")


def _ts(mon: str, day: str, time: str, year: int) -> datetime:
    return datetime(year, _MONTHS[mon], int(day),
                    *(int(x) for x in time.split(":")))


def parse_auth_line(line: str, year: Optional[int] = None) -> Optional[Event]:
    """Transforme une ligne d'auth.log en Event, ou None si non reconnue."""
    line = line.rstrip("\n")
    m = _SYSLOG.match(line)
    if not m:
        return None
    year = year or datetime.now().year
    ts = _ts(m["mon"], m["day"], m["time"], year)
    host, proc, msg = m["host"], m["proc"], m["msg"]

    common = dict(timestamp=ts, source="auth.log", host=host, raw=line)

    if proc == "sshd":
        if (f := _FAILED.search(msg)):
            return Event(event_type="ssh_login", outcome="failure",
                         user=f["user"], source_ip=f["ip"], **common)
        if (a := _ACCEPTED.search(msg)):
            return Event(event_type="ssh_login", outcome="success",
                         user=a["user"], source_ip=a["ip"], **common)
        if (i := _INVALID.search(msg)):
            return Event(event_type="ssh_login", outcome="failure",
                         user=i["user"], source_ip=i["ip"], **common)

    if proc == "sudo":
        if _SUDO_FAIL.search(msg):
            u = _SUDO_FAIL.search(msg)["user"]
            return Event(event_type="sudo", outcome="failure", user=u, **common)
        if (s := _SUDO.search(msg)):
            return Event(event_type="sudo", outcome="success", user=s["user"], **common)

    return None


# --- Apache/Nginx, format "combined log" ---------------------------------
# 203.0.113.9 - - [08/Nov/2026:13:37:01 +0100] "GET /path HTTP/1.1" 404 512 "-" "UA"
_APACHE = re.compile(
    r'^(?P<ip>[\d.:a-fA-F]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+[^"]*"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)
_APACHE_TS = "%d/%b/%Y:%H:%M:%S %z"


def parse_apache_line(line: str, year: Optional[int] = None) -> Optional[Event]:
    m = _APACHE.match(line.rstrip("\n"))
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], _APACHE_TS).replace(tzinfo=None)
    except ValueError:
        return None
    status = int(m["status"])
    outcome = "failure" if status >= 400 else "success"
    return Event(timestamp=ts, source="access.log", event_type="web_request",
                 outcome=outcome, source_ip=m["ip"], method=m["method"],
                 url=m["url"], status=status, user_agent=m["ua"] or "-",
                 raw=line.rstrip("\n"))


# --- Pare-feu UFW/iptables ------------------------------------------------
# Nov  8 13:37:01 web01 kernel: [UFW BLOCK] IN=eth0 ... SRC=203.0.113.9
#   DST=10.0.0.5 ... PROTO=TCP SPT=50000 DPT=23 ...
_UFW_KV = re.compile(r"(\b[A-Z]+)=(\S+)")


def parse_ufw_line(line: str, year: Optional[int] = None) -> Optional[Event]:
    line = line.rstrip("\n")
    if "UFW BLOCK" not in line and "iptables" not in line.lower():
        return None
    m = _SYSLOG.match(line)
    if not m:
        return None
    year = year or datetime.now().year
    ts = _ts(m["mon"], m["day"], m["time"], year)
    kv = dict(_UFW_KV.findall(m["msg"]))
    src = kv.get("SRC")
    if not src:
        return None
    dpt = kv.get("DPT")
    return Event(timestamp=ts, source="ufw.log", event_type="fw_block",
                 outcome="blocked", host=m["host"], source_ip=src,
                 dest_port=int(dpt) if dpt and dpt.isdigit() else None,
                 proto=kv.get("PROTO"), raw=line)


# --- Windows EVTX (rendu en XML par wevtutil / Get-WinEvent / evtx_dump) ---
# Un .evtx binaire se convertit en ce même XML avec `evtx_dump fichier.evtx`.
import xml.etree.ElementTree as ET

# EventID Windows -> (event_type normalisé, outcome)
_EVTX_MAP = {
    4625: ("win_logon", "failure"),           # échec d'ouverture de session
    4624: ("win_logon", "success"),           # ouverture de session réussie
    4672: ("win_special_priv", "info"),       # privilèges spéciaux assignés
    4720: ("win_account_created", "info"),     # compte créé
    4732: ("win_group_add", "info"),           # ajout à un groupe local
    1102: ("win_log_cleared", "info"),         # journal de sécurité effacé
}

_EVENT_BLOCK = re.compile(r"<Event\b.*?</Event>", re.S)


def _evtx_time(raw: str) -> Optional[datetime]:
    raw = raw.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(raw).replace(tzinfo=None)
    except ValueError:
        return None


def parse_evtx_xml(block: str) -> Optional[Event]:
    """Transforme un enregistrement <Event>…</Event> (XML Windows) en Event."""
    clean = re.sub(r'\sxmlns="[^"]+"', "", block)  # retire le namespace par défaut
    try:
        root = ET.fromstring(clean)
    except ET.ParseError:
        return None

    system = root.find("System")
    if system is None:
        return None
    eid_el = system.find("EventID")
    if eid_el is None or not (eid_el.text or "").strip().isdigit():
        return None
    eid = int(eid_el.text.strip())
    if eid not in _EVTX_MAP:
        return None

    tc = system.find("TimeCreated")
    ts = _evtx_time(tc.get("SystemTime", "")) if tc is not None else None
    if ts is None:
        return None
    host_el = system.find("Computer")
    host = (host_el.text if host_el is not None else "-") or "-"

    data = {d.get("Name"): (d.text or "") for d in root.iter("Data")}
    event_type, outcome = _EVTX_MAP[eid]

    user = data.get("TargetUserName") or data.get("SubjectUserName")
    ip = data.get("IpAddress")
    if ip in ("-", "::1", "127.0.0.1", ""):
        ip = None
    detail = None
    if eid == 4732:  # ajout à un groupe : la cible est le groupe, le membre l'utilisateur
        detail = data.get("TargetUserName")      # nom du groupe
        user = data.get("MemberName") or data.get("MemberSid") or user
    elif eid in (4625, 4624):
        detail = data.get("LogonType")

    return Event(timestamp=ts, source="windows", event_type=event_type,
                 outcome=outcome, host=host, source_ip=ip, user=user,
                 event_id=eid, detail=detail, raw=" ".join(block.split()))


def parse_evtx_file(path: str, year: Optional[int] = None) -> Iterator[Event]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    for block in _EVENT_BLOCK.findall(text):
        ev = parse_evtx_xml(block)
        if ev is not None:
            yield ev


# Ordre d'essai pour l'auto-détection par ligne.
_PARSERS = [parse_ufw_line, parse_auth_line, parse_apache_line]


def parse_line(line: str, year: Optional[int] = None) -> Optional[Event]:
    """Essaie chaque parser et renvoie le premier Event reconnu."""
    for parser in _PARSERS:
        ev = parser(line, year=year)
        if ev is not None:
            return ev
    return None


def parse_file(path: str, year: Optional[int] = None) -> Iterator[Event]:
    """Lit un fichier de log et produit les Events reconnus.

    Détecte les journaux Windows (XML, commençant par « < ») et les route vers
    le parser EVTX ; sinon, auto-détection ligne par ligne (auth/Apache/pare-feu).
    """
    with open(path, encoding="utf-8", errors="replace") as fh:
        head = fh.read(256).lstrip()
    if head.startswith("<"):
        yield from parse_evtx_file(path, year=year)
        return
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            ev = parse_line(line, year=year)
            if ev is not None:
                yield ev
