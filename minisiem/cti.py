"""Cyber Threat Intelligence (CTI) : enrichissement par des flux de menace.

Deux apports :
  1. Enrichissement — une alerte dont l'IP source figure dans un flux connu
     reçoit un contexte (flux, catégorie, score de confiance) et peut voir sa
     sévérité relevée.
  2. Détection — une IP déjà référencée comme malveillante est signalée même si
     aucune règle de volume ne s'est déclenchée (un simple contact suffit).

Branchable comme le GeoIP : un flux de démo est embarqué (data/threat_feed.json),
remplaçable par un vrai feed via la variable MINISIEM_CTI_FEED (JSON ou CSV).
Formats réels compatibles après conversion : abuse.ch Feodo Tracker, blocklist.de,
AbuseIPDB, listes de nœuds de sortie Tor, exports MISP/OTX.
"""
from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Optional

from .events import Event, Alert

_DEMO_PATH = Path(__file__).resolve().parent / "data" / "threat_feed.json"

# catégorie d'indicateur -> (technique ATT&CK, tactique) pour les alertes CTI
_CATEGORY_ATTACK = {
    "c2": ("T1071", "Command and Control"),
    "bruteforce": ("T1110", "Credential Access"),
    "scanner": ("T1595", "Reconnaissance"),
    "exploit": ("T1190", "Initial Access"),
    "malware": ("T1105", "Command and Control"),
    "tool": ("T1595.002", "Reconnaissance"),
}


def _severity_from_confidence(conf: int) -> str:
    if conf >= 90:
        return "critical"
    if conf >= 75:
        return "high"
    return "medium"


class ThreatIntel:
    def __init__(self) -> None:
        self.feed_name = "aucun"
        self._ip: dict[str, dict] = {}
        self._ua: list[dict] = []
        self._url: list[dict] = []
        path = os.environ.get("MINISIEM_CTI_FEED")
        if path and Path(path).exists():
            self._load(Path(path))
        elif _DEMO_PATH.exists():
            self._load(_DEMO_PATH)

    def _add(self, ind: dict) -> None:
        t = ind.get("type")
        if t == "ip" and ind.get("value"):
            self._ip[ind["value"]] = ind
        elif t == "user_agent":
            self._ua.append(ind)
        elif t == "url_substring":
            self._url.append(ind)

    def _load(self, path: Path) -> None:
        if path.suffix.lower() == ".csv":
            with open(path, encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    row.setdefault("type", "ip")
                    row["confidence"] = int(row.get("confidence") or 50)
                    self._add(row)
            self.feed_name = path.name
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        self.feed_name = data.get("feed", path.name)
        for ind in data.get("indicators", []):
            self._add(ind)

    @property
    def size(self) -> int:
        return len(self._ip) + len(self._ua) + len(self._url)

    def match_ip(self, ip: Optional[str]) -> Optional[dict]:
        return self._ip.get(ip) if ip else None

    def match_event(self, ev: Event) -> list[dict]:
        hits = []
        if ev.source_ip and ev.source_ip in self._ip:
            hits.append(self._ip[ev.source_ip])
        if ev.user_agent:
            ua = ev.user_agent.lower()
            hits += [i for i in self._ua if str(i["value"]).lower() in ua]
        if ev.url:
            u = ev.url.lower()
            hits += [i for i in self._url if str(i["value"]).lower() in u]
        return hits


def enrich_alerts(alerts: list[Alert], ti: ThreatIntel) -> int:
    """Ajoute le contexte CTI aux alertes et relève la sévérité si besoin.
    Renvoie le nombre d'alertes enrichies."""
    n = 0
    for a in alerts:
        ind = ti.match_ip(a.source_ip)
        if not ind:
            continue
        a.threat = {"feed": ti.feed_name, "source": ind.get("source", ti.feed_name),
                    "category": ind.get("category", "?"),
                    "confidence": ind.get("confidence", 0)}
        n += 1
        # Une IP en flux C2/exploit à haute confiance justifie une sévérité critique
        if ind.get("category") in ("c2", "exploit", "malware") and ind.get("confidence", 0) >= 90:
            a.severity = "critical"
    return n


def detect_threat_contacts(ti: ThreatIntel, events: list[Event],
                           existing: list[Alert]) -> list[Alert]:
    """Signale les IP déjà connues comme malveillantes qui apparaissent dans les
    logs sans qu'aucune règle ne les ait déjà fait remonter."""
    already = {a.source_ip for a in existing if a.source_ip}
    by_ip: dict[str, list[Event]] = {}
    for e in events:
        if e.source_ip and e.source_ip in ti._ip and e.source_ip not in already:
            by_ip.setdefault(e.source_ip, []).append(e)

    alerts: list[Alert] = []
    for ip, evs in by_ip.items():
        ind = ti._ip[ip]
        conf = ind.get("confidence", 50)
        attack, tactic = _CATEGORY_ATTACK.get(ind.get("category", ""), ("T1071", "Command and Control"))
        evs.sort(key=lambda e: e.timestamp)
        alerts.append(Alert(
            rule_id="THREAT_INTEL_HIT",
            title=f"Contact avec une IP malveillante connue ({ind.get('category','?')})",
            severity=_severity_from_confidence(conf),
            attack=attack, tactic=tactic,
            source_ip=ip, user=evs[0].user,
            first_seen=evs[0].timestamp, last_seen=evs[-1].timestamp, count=len(evs),
            description=f"IP référencée par {ind.get('source', ti.feed_name)} "
                        f"(confiance {conf}%). Détectée par renseignement, sans seuil de volume.",
            threat={"feed": ti.feed_name, "source": ind.get("source", ti.feed_name),
                    "category": ind.get("category", "?"), "confidence": conf},
            evidence=[e.raw for e in evs[:8]],
        ))
    return alerts
