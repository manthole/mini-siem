"""Exports : alertes en JSON, et règles internes converties au format Sigma.

- JSON : pour intégrer les alertes à un autre outil (ticketing, autre SIEM).
- Sigma : prouve la compatibilité avec le standard de l'industrie
  (https://github.com/SigmaHQ/sigma) et permet de rejouer les règles ailleurs.
"""
from __future__ import annotations

import json

import yaml

# Correspondance type interne -> logsource Sigma (indicatif).
_LOGSOURCE = {
    "ssh_login": {"product": "linux", "service": "sshd"},
    "sudo": {"product": "linux", "service": "sudo"},
    "web_request": {"category": "webserver"},
    "fw_block": {"product": "linux", "service": "firewall"},
    "win_logon": {"product": "windows", "service": "security"},
    "win_group_add": {"product": "windows", "service": "security"},
    "win_account_created": {"product": "windows", "service": "security"},
    "win_log_cleared": {"product": "windows", "service": "security"},
}

_LEVEL = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def alerts_to_json(alerts) -> str:
    return json.dumps([a.to_dict() for a in alerts], ensure_ascii=False, indent=2)


def _selection_for_sigma(sel: dict) -> dict:
    """Traduit une sélection interne en détection Sigma (approximation lisible)."""
    out = {}
    for field_name, cond in sel.items():
        if isinstance(cond, dict):
            if "contains" in cond:
                vals = cond["contains"]
                out[f"{field_name}|contains"] = vals if isinstance(vals, list) else [vals]
            elif "regex" in cond:
                out[f"{field_name}|re"] = cond["regex"]
            elif "in" in cond:
                out[field_name] = cond["in"]
            else:
                out[field_name] = str(cond)
        else:
            out[field_name] = cond
    return out


def rule_to_sigma(rule: dict) -> str:
    """Convertit une règle interne en règle Sigma (YAML)."""
    event_type = (rule.get("selection", {}).get("event_type")
                  or rule.get("trigger", {}).get("event_type"))
    doc = {
        "title": rule["title"],
        "id": rule["id"],
        "status": "experimental",
        "description": " ".join(rule.get("description", "").split()),
        "logsource": _LOGSOURCE.get(event_type, {"product": "unknown"}),
        "detection": {
            "selection": _selection_for_sigma(
                rule.get("selection") or rule.get("precondition", {})),
            "condition": "selection",
        },
        "level": _LEVEL.get(rule.get("level", "medium"), "medium"),
        "tags": [f"attack.{rule.get('attack', '').lower()}"] if rule.get("attack") else [],
    }
    # Les seuils / séquences ne sont pas natifs en Sigma : on les documente.
    notes = []
    if rule.get("type") == "threshold":
        notes.append(f"count >= {rule.get('count')} en {rule.get('window_seconds')}s "
                     f"group_by {rule.get('group_by')}"
                     + (f" distinct {rule['distinct']}" if rule.get("distinct") else ""))
    elif rule.get("type") == "sequence":
        notes.append("corrélation : precondition puis trigger, même "
                     f"{rule.get('group_by')} en {rule.get('window_seconds')}s")
    elif rule.get("type") == "baseline_hour":
        notes.append("détection comportementale : heure hors baseline du compte")
    if notes:
        doc["falsepositives"] = ["à affiner selon l'environnement"]
        doc["description"] += "  [logique mini-SIEM : " + " ; ".join(notes) + "]"
    return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)
