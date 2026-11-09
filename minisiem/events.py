"""Schéma d'événement normalisé, inspiré d'ECS (Elastic Common Schema).

Chaque ligne de log brute est transformée en un Event au format commun,
quelle que soit la source. C'est ce qui permet d'écrire les détections une
seule fois, sans se soucier du format d'origine.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


@dataclass
class Event:
    timestamp: datetime          # quand l'événement s'est produit
    source: str                  # fichier/source d'origine (ex: "auth.log")
    event_type: str              # ssh_login, web_request, fw_block, ...
    outcome: str                 # "success", "failure", "blocked" ou "info"
    host: str = "-"              # machine qui a produit le log
    source_ip: Optional[str] = None
    user: Optional[str] = None
    raw: str = ""                # ligne brute, conservée comme preuve

    # champs web (Apache/Nginx)
    method: Optional[str] = None
    url: Optional[str] = None
    status: Optional[int] = None
    user_agent: Optional[str] = None

    # champs réseau (pare-feu)
    dest_port: Optional[int] = None
    proto: Optional[str] = None

    # champs Windows (EVTX)
    event_id: Optional[int] = None
    detail: Optional[str] = None   # groupe ciblé, type d'ouverture de session...

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat(sep=" ")
        return d


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str                # low | medium | high | critical
    attack: str                  # technique MITRE ATT&CK, ex "T1110.001"
    source_ip: Optional[str]
    user: Optional[str]
    first_seen: datetime
    last_seen: datetime
    count: int                   # nb d'événements ayant déclenché l'alerte
    description: str
    tactic: str = "-"            # tactique MITRE ATT&CK (ex "Credential Access")
    evidence: list[str] = field(default_factory=list)  # lignes brutes

    # champs d'enrichissement, remplis après coup
    country: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    threat: Optional[dict] = None   # renseignement CTI : flux, catégorie, confiance

    def to_dict(self) -> dict:
        d = asdict(self)
        d["first_seen"] = self.first_seen.isoformat(sep=" ")
        d["last_seen"] = self.last_seen.isoformat(sep=" ")
        return d


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
