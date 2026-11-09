"""Configuration : listes blanches et réglages, pour maîtriser les faux positifs.

Un fichier config.yml optionnel permet d'ignorer des IP de confiance (réseau
interne, scanners de supervision légitimes), des comptes, et de désactiver des
règles par leur id.

Exemple :
    allowlist:
      ips:   [10.0.0.0/8, 192.168.0.0/16, 198.51.100.200]
      users: [nagios, backup-svc]
    disabled_rules: [WEB_SCAN]
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Config:
    allow_nets: list = field(default_factory=list)
    allow_users: set = field(default_factory=set)
    disabled_rules: set = field(default_factory=set)

    @classmethod
    def load(cls, path: str | None) -> "Config":
        if not path or not Path(path).exists():
            return cls()
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        allow = raw.get("allowlist", {}) or {}
        nets = []
        for item in allow.get("ips", []) or []:
            try:
                nets.append(ipaddress.ip_network(str(item), strict=False))
            except ValueError:
                pass
        return cls(
            allow_nets=nets,
            allow_users=set(allow.get("users", []) or []),
            disabled_rules=set(raw.get("disabled_rules", []) or []),
        )

    def is_allowed_ip(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.allow_nets)

    def suppresses(self, alert) -> bool:
        """L'alerte doit-elle être supprimée (liste blanche / règle désactivée) ?"""
        if alert.rule_id in self.disabled_rules:
            return True
        if self.is_allowed_ip(alert.source_ip):
            return True
        if alert.user and alert.user in self.allow_users:
            return True
        return False


def apply_config(alerts: list, config: Config) -> list:
    return [a for a in alerts if not config.suppresses(a)]
