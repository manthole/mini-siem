"""Enrichissement géographique des adresses IP (branchable).

Priorité :
  1. Base MaxMind GeoLite2 si disponible (lib `geoip2` + fichier .mmdb pointé
     par la variable d'environnement MINISIEM_GEOIP_DB) — pour la prod.
  2. Sinon, petite table de démo embarquée (data/geo_demo.json) — pour que la
     carte du rapport s'affiche sans téléchargement.

Les IP privées / réservées ne sont jamais géolocalisées (elles sont locales).
"""
from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_DEMO_PATH = Path(__file__).resolve().parent / "data" / "geo_demo.json"


@dataclass
class GeoInfo:
    country: str
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (addr.is_private or addr.is_loopback or addr.is_reserved
            or addr.is_link_local or addr.is_multicast)


class GeoResolver:
    def __init__(self) -> None:
        self._mmdb = None
        self._demo: dict = {}
        db_path = os.environ.get("MINISIEM_GEOIP_DB")
        if db_path and Path(db_path).exists():
            try:
                import geoip2.database  # type: ignore
                self._mmdb = geoip2.database.Reader(db_path)
            except Exception:
                self._mmdb = None
        if self._mmdb is None and _DEMO_PATH.exists():
            self._demo = json.loads(_DEMO_PATH.read_text(encoding="utf-8"))

    @property
    def mode(self) -> str:
        return "maxmind" if self._mmdb else "demo"

    def lookup(self, ip: Optional[str]) -> Optional[GeoInfo]:
        if not ip:
            return None
        # Une entrée explicite de la table de démo l'emporte : les plages de
        # documentation (RFC 5737) sont considérées « privées » par Python mais
        # servent justement d'IP d'attaquant fictives dans le jeu de démo.
        d = self._demo.get(ip)
        if d:
            return GeoInfo(country=d.get("country", "?"), city=d.get("city"),
                           lat=d.get("lat"), lon=d.get("lon"))
        if _is_private(ip):
            return None
        if self._mmdb is not None:
            try:
                r = self._mmdb.city(ip)
                return GeoInfo(country=r.country.name or "?",
                              city=r.city.name,
                              lat=r.location.latitude, lon=r.location.longitude)
            except Exception:
                return None
        return None


def enrich(alerts, resolver: Optional[GeoResolver] = None) -> None:
    """Ajoute pays / ville / coordonnées aux alertes, sur place."""
    resolver = resolver or GeoResolver()
    for a in alerts:
        info = resolver.lookup(a.source_ip)
        if info:
            a.country, a.city, a.lat, a.lon = info.country, info.city, info.lat, info.lon
