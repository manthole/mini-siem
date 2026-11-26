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
from .evtx import is_evtx, read_evtx_file

# auth.log classique : "Nov  8 13:37:01 web01 sshd[1234]: <message>"
# L'année n'est pas dans la ligne : on la passe en paramètre (défaut = année courante).
# re.ASCII : \s, \d, \w et \S ont alors exactement le sens de la version JavaScript
# (le fuzzing différentiel a trouvé des lignes lues différemment sans ce drapeau).
_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>\w+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$", re.ASCII
)

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# Sous-motifs sur le message sshd/sudo
_FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)", re.ASCII)
_ACCEPTED = re.compile(r"Accepted \w+ for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)", re.ASCII)
_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)", re.ASCII)
# Ancrées en début de message (sudo écrit toujours le compte en premier) : sans ancre,
# une ligne de 40 000 caractères sans espace prenait 15 s (retour arrière quadratique).
_SUDO = re.compile(r"^\s*(?P<user>\S+) : .*COMMAND=(?P<cmd>.*)$", re.ASCII)
_SUDO_FAIL = re.compile(r"^\s*(?P<user>\S+) : (?:command not allowed|user NOT in sudoers)", re.ASCII)


def _ts(mon: str, day: str, time: str, year: int) -> Optional[datetime]:
    """Date validée, ou None (mois inconnu, 31 novembre, 25 h…) : une ligne abîmée est
    ignorée au lieu d'interrompre l'analyse. Même règle en JavaScript."""
    try:
        return datetime(year, _MONTHS[mon], int(day), *(int(x) for x in time.split(":")))
    except (KeyError, ValueError):
        return None


def parse_auth_line(line: str, year: Optional[int] = None) -> Optional[Event]:
    """Transforme une ligne d'auth.log en Event, ou None si non reconnue."""
    line = line.rstrip("\n")
    m = _SYSLOG.match(line)
    if not m:
        return None
    year = year or datetime.now().year
    ts = _ts(m["mon"], m["day"], m["time"], year)
    if ts is None:
        return None
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
    r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?', re.ASCII
)
# « 08/Nov/2026:13:37:01 +0100 » : le fuseau est ignoré (heure locale du serveur)
_APACHE_TS = re.compile(r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})", re.ASCII)


def parse_apache_line(line: str, year: Optional[int] = None) -> Optional[Event]:
    m = _APACHE.match(line.rstrip("\n"))
    if not m:
        return None
    t = _APACHE_TS.match(m["ts"])
    if not t:
        return None
    ts = _ts(t[2], t[1], f"{t[4]}:{t[5]}:{t[6]}", int(t[3]))
    if ts is None:
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
_UFW_KV = re.compile(r"(\b[A-Z]+)=(\S+)", re.ASCII)


def _port(value: Optional[str]) -> Optional[int]:
    """Port valide (1 à 5 chiffres ASCII, au plus 65535) ou None. (« ² ».isdigit() est vrai
    en Python mais int(« ² ») échoue : le fuzzing l'a trouvé.)"""
    if value and re.fullmatch(r"[0-9]{1,5}", value) and int(value) <= 65535:
        return int(value)
    return None


def parse_ufw_line(line: str, year: Optional[int] = None) -> Optional[Event]:
    line = line.rstrip("\n")
    if "UFW BLOCK" not in line and "iptables" not in line.lower():
        return None
    m = _SYSLOG.match(line)
    if not m:
        return None
    year = year or datetime.now().year
    ts = _ts(m["mon"], m["day"], m["time"], year)
    if ts is None:
        return None
    kv = dict(_UFW_KV.findall(m["msg"]))
    src = kv.get("SRC")
    if not src:
        return None
    dpt = kv.get("DPT")
    return Event(timestamp=ts, source="ufw.log", event_type="fw_block",
                 outcome="blocked", host=m["host"], source_ip=src,
                 dest_port=_port(dpt),
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

# --- Sysmon (canal Microsoft-Windows-Sysmon/Operational) ---
# Même enveloppe XML que les autres journaux Windows ; on reconnaît Sysmon à son
# fournisseur ou à son canal. L'event_type reprend la catégorie de journal Sigma,
# ce qui rend l'export Sigma direct (logsource product: windows, category: …).
_SYSMON_MAP = {
    1: "process_creation",     # création de processus (ligne de commande, parent)
    3: "network_connection",   # connexion réseau
    10: "process_access",      # un processus ouvre un autre processus (ex. LSASS)
    11: "file_event",          # création de fichier
    13: "registry_set",        # écriture d'une valeur de registre
    22: "dns_query",           # requête DNS
}

_EVENT_START = re.compile(r"<Event\b")


def event_blocks(text: str) -> Iterator[str]:
    """Blocs <Event>…</Event> d'un texte, en un seul passage. (Une expression
    « <Event.*?</Event> » devenait quadratique sur des ouvertures jamais fermées.)"""
    pos = 0
    while (m := _EVENT_START.search(text, pos)) is not None:
        end = text.find("</Event>", m.end())
        if end < 0:
            return
        yield text[m.start():end + 8]
        pos = end + 8


def _is_sysmon(system: ET.Element) -> bool:
    prov = system.find("Provider")
    chan = system.find("Channel")
    names = [prov.get("Name", "") if prov is not None else "",
             (chan.text or "") if chan is not None else ""]
    return any("sysmon" in n.lower() for n in names)


def _hex(value: Optional[str]) -> Optional[str]:
    """« 0x00001410 », « 0X1410 » -> « 0x1410 » : même écriture quel que soit l'outil d'export."""
    if not value:
        return None
    try:
        return f"0x{int(value.strip(), 16):x}"
    except ValueError:
        return value.strip().lower()


def _bare_user(user: Optional[str]) -> Optional[str]:
    """« PC-COMPTA01\\mmartin » -> « mmartin », pour pivoter avec les autres sources."""
    return user.split("\\")[-1] if user else None


def _sysmon_event(eid: int, ts: datetime, host: str, data: dict, raw: str) -> Event:
    ev = Event(timestamp=ts, source="sysmon", event_type=_SYSMON_MAP[eid],
               outcome="info", host=host, event_id=eid, raw=raw,
               user=_bare_user(data.get("User") or data.get("SourceUser")))
    if eid == 1:
        ev.process = data.get("Image")
        ev.parent_process = data.get("ParentImage")
        ev.command_line = data.get("CommandLine")
        ev.detail = data.get("IntegrityLevel")
    elif eid == 3:
        ev.process = data.get("Image")
        ev.source_ip = data.get("SourceIp") or None
        ev.dest_ip = data.get("DestinationIp") or None
        ev.dest_port = _port((data.get("DestinationPort") or "").strip())
        ev.proto = data.get("Protocol")
        ev.target = data.get("DestinationHostname") or None
    elif eid == 10:
        ev.process = data.get("SourceImage")
        ev.target = data.get("TargetImage")
        ev.granted_access = _hex(data.get("GrantedAccess"))
    elif eid == 11:
        ev.process = data.get("Image")
        ev.target = data.get("TargetFilename")
    elif eid == 13:
        ev.process = data.get("Image")
        ev.target = data.get("TargetObject")
        ev.detail = data.get("Details")
    elif eid == 22:
        ev.process = data.get("Image")
        ev.target = data.get("QueryName")
        ev.detail = data.get("QueryResults")
    return ev


def _evtx_time(raw: str) -> Optional[datetime]:
    raw = raw.strip().replace("Z", "+00:00")
    # Windows écrit 7 chiffres de fraction (100 ns) : on garde les microsecondes
    raw = re.sub(r"(\.\d{6})\d+", r"\1", raw)
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
    # chiffres ASCII seulement, et pas des milliers (int() refuse au-delà de 4 300 chiffres)
    if eid_el is None or not re.fullmatch(r"[0-9]{1,10}", (eid_el.text or "").strip()):
        return None
    eid = int(eid_el.text.strip())
    sysmon = _is_sysmon(system)
    if eid not in (_SYSMON_MAP if sysmon else _EVTX_MAP):
        return None

    tc = system.find("TimeCreated")
    ts = _evtx_time(tc.get("SystemTime", "")) if tc is not None else None
    if ts is None:
        return None
    host_el = system.find("Computer")
    host = (host_el.text if host_el is not None else "-") or "-"

    data = {d.get("Name"): (d.text or "") for d in root.iter("Data")}
    if sysmon:
        return _sysmon_event(eid, ts, host, data, " ".join(block.split()))
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
    for block in event_blocks(text):
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

    - .evtx binaire (signature « ElfFile ») : lu directement, sans export préalable ;
    - XML Windows (commençant par « < » : journal de sécurité ou Sysmon exporté) ;
    - sinon, auto-détection ligne par ligne (auth/Apache/pare-feu).
    """
    with open(path, "rb") as fb:
        magic = fb.read(8)
    if is_evtx(magic):
        for xml in read_evtx_file(path):
            ev = parse_evtx_xml(xml)
            if ev is not None:
                yield ev
        return
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
