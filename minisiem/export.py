"""Exports : alertes en JSON, et règles internes converties au format Sigma.

- JSON : pour intégrer les alertes à un autre outil (ticketing, autre SIEM).
- Sigma : rejoue les règles dans n'importe quel SIEM (Splunk, Elastic, Sentinel…)
  grâce au standard de l'industrie (https://github.com/SigmaHQ/sigma).

Conversion fidèle, vérifiée en intégration continue par le validateur officiel
(`sigma check`) :
  - match         -> une règle Sigma ;
  - threshold     -> une règle de base + une corrélation Sigma event_count
                     (ou value_count quand la règle compte des valeurs distinctes) ;
  - sequence      -> règles de base + corrélations : event_count sur la condition
                     préalable, puis temporal_ordered avec le déclencheur ;
  - baseline_hour -> la règle de base seule : une baseline par compte ne
                     s'exprime pas en Sigma, le SIEM cible doit la calculer.
Les identifiants Sigma sont des UUID stables dérivés de l'id interne (uuid5),
et les champs normalisés du mini-SIEM sont renommés selon la taxonomie Sigma
de chaque source (Image, CommandLine, EventID, cs-uri-query…).
"""
from __future__ import annotations

import json
import uuid

import yaml

_NAMESPACE = uuid.UUID("8f6b2c1e-4d3a-5b7c-9e1f-2a4b6c8d0e1f")
_AUTHOR = "Manthole"
_REFERENCES = ["https://github.com/manthole/mini-siem"]

_SYSMON = {"process_creation", "network_connection", "process_access",
           "file_event", "registry_set", "dns_query"}

# Journaux Linux sans champs structurés : l'event_type et l'outcome internes
# redeviennent les mots-clés de la ligne brute.
_KEYWORDS = {
    ("ssh_login", "failure"): ["Failed password", "Invalid user"],
    ("ssh_login", "success"): ["Accepted password", "Accepted publickey"],
    ("sudo", "failure"): ["user NOT in sudoers", "command not allowed"],
    ("sudo", "success"): ["COMMAND="],
    ("fw_block", None): ["[UFW BLOCK]"],
}

# Champs normalisés -> noms de champs de la taxonomie Sigma, par source.
_FIELDS_WINDOWS = {"event_id": "EventID", "user": "TargetUserName",
                   "source_ip": "IpAddress", "host": "Computer"}
_FIELDS_WEB = {"url": "cs-uri-query", "user_agent": "cs-user-agent", "status": "sc-status",
               "source_ip": "c-ip", "method": "cs-method"}
_FIELDS_UFW = {"source_ip": "SRC", "dest_port": "DPT", "proto": "PROTO"}
_FIELDS_SYSMON = {"process": "Image", "parent_process": "ParentImage",
                  "command_line": "CommandLine", "user": "User", "host": "Computer",
                  "source_ip": "SourceIp", "dest_ip": "DestinationIp",
                  "dest_port": "DestinationPort", "granted_access": "GrantedAccess"}
_SYSMON_TARGET = {"process_access": "TargetImage", "file_event": "TargetFilename",
                  "registry_set": "TargetObject", "dns_query": "QueryName",
                  "network_connection": "DestinationHostname"}

_LEVEL = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def alerts_to_json(alerts) -> str:
    return json.dumps([a.to_dict() for a in alerts], ensure_ascii=False, indent=2)


# --- Source : logsource Sigma et table de champs ---------------------------
def _source(sel: dict) -> tuple[dict, dict, str | None]:
    """Renvoie (logsource, table de champs, event_type implicite) d'une sélection."""
    et = sel.get("event_type")
    if et in _SYSMON:
        fields = dict(_FIELDS_SYSMON, target=_SYSMON_TARGET.get(et, "TargetObject"))
        if et == "process_access":
            fields.update(process="SourceImage", user="SourceUser")
        return {"product": "windows", "category": et}, fields, et
    if et == "web_request":
        return {"category": "webserver"}, _FIELDS_WEB, et
    if et == "ssh_login":
        return {"product": "linux", "service": "sshd"}, {}, et
    if et == "sudo":
        return {"product": "linux", "service": "sudo"}, {}, et
    if et == "fw_block":
        return {"product": "linux", "service": "ufw"}, _FIELDS_UFW, et
    if "event_id" in sel or str(et or "").startswith("win_"):
        return {"product": "windows", "service": "security"}, _FIELDS_WINDOWS, None
    return {"product": "linux"}, {}, None


def _items(cond: dict, fields: dict, skip: set) -> dict:
    """Sélection interne -> éléments de détection Sigma (avec modificateurs)."""
    out: dict = {}
    for name, expected in cond.items():
        if name in skip:
            continue
        sig = fields.get(name, name)
        if isinstance(expected, dict):
            for op, operand in expected.items():
                if op in ("contains", "endswith"):
                    out[f"{sig}|{op}"] = operand if isinstance(operand, list) else [operand]
                elif op == "regex":
                    out[f"{sig}|re|i"] = operand      # le moteur ignore la casse
                elif op == "in":
                    out[sig] = operand if isinstance(operand, list) else [operand]
                elif op in ("gte", "lte"):
                    out[f"{sig}|{op}"] = operand
                else:
                    raise ValueError(f"opérateur sans équivalent Sigma : {op!r}")
        else:
            out[sig] = expected
    return out


def _detection(sel: dict, flt: dict | None, fields: dict, et: str | None) -> dict:
    det: dict = {}
    parts = []
    kw = _KEYWORDS.get((et, sel.get("outcome"))) or _KEYWORDS.get((et, None))
    skip = {"event_type"} if et else set()
    if kw:
        skip.add("outcome")
        det["keywords"] = kw
        parts.append("keywords")
    items = _items(sel, fields, skip)
    if items or not parts:
        det["selection"] = items
        parts.append("selection")
    cond = " and ".join(parts)
    if flt:
        det["filter"] = _items(flt, fields, set())
        cond = f"{cond} and not filter" if len(parts) == 1 else f"({cond}) and not filter"
    det["condition"] = cond
    return det


# --- Documents Sigma -------------------------------------------------------
def _uid(rule_id: str, part: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, f"mini-siem:{rule_id}:{part}"))


def _timespan(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def _tags(rule: dict) -> list[str]:
    return [f"attack.{rule['attack'].lower()}"] if rule.get("attack") else []


def _meta(rule: dict, part: str, title: str, description: str) -> dict:
    return {"title": title, "id": _uid(rule["id"], part),
            "name": f"{rule['id'].lower()}{'' if part == 'main' else '_' + part}",
            "status": "experimental", "description": description,
            "references": _REFERENCES, "author": _AUTHOR}


def _base(rule: dict, part: str, title: str, key: str, level: str) -> dict:
    sel = rule.get(key) or {}
    logsource, fields, et = _source(sel)
    doc = _meta(rule, part, title, " ".join(rule.get("description", "").split()))
    doc.update({"logsource": logsource,
                "detection": _detection(sel, rule.get("filter"), fields, et),
                "level": level, "tags": _tags(rule)})
    return doc


def _correlation(rule: dict, part: str, title: str, corr: dict, level: str) -> dict:
    doc = _meta(rule, part, title, " ".join(rule.get("description", "").split()))
    doc.update({"correlation": corr, "level": level, "tags": _tags(rule)})
    return doc


def _group_by(rule: dict, key: str, default: list[str]) -> list[str]:
    _, fields, _ = _source(rule.get(key) or {})
    return [fields.get(g, g) for g in rule.get("group_by", default)]


def rule_to_sigma_docs(rule: dict) -> list[dict]:
    """Convertit une règle interne en documents Sigma (règles + corrélations)."""
    kind = rule.get("type", "match")
    level = _LEVEL.get(rule.get("level", "medium"), "medium")
    title = rule["title"]

    if kind == "match":
        return [_base(rule, "main", title, "selection", level)]

    if kind == "threshold":
        base = _base(rule, "event", f"{title} : événement unitaire", "selection",
                     "informational")
        cond: dict = {"gte": rule.get("count", 10)}
        corr = {"type": "event_count", "rules": [base["name"]],
                "group-by": _group_by(rule, "selection", ["source_ip"]),
                "timespan": _timespan(rule.get("window_seconds", 300)),
                "condition": cond}
        if rule.get("distinct"):
            _, fields, _ = _source(rule.get("selection") or {})
            corr["type"] = "value_count"
            cond["field"] = fields.get(rule["distinct"], rule["distinct"])
        return [base, _correlation(rule, "main", title, corr, level)]

    if kind == "sequence":
        group = _group_by(rule, "precondition", ["source_ip"])
        span = _timespan(rule.get("window_seconds", 600))
        n = rule.get("min_preconditions", 1)
        pre = _base(rule, "pre", f"{title} : condition préalable", "precondition",
                    "informational")
        trig = _base(rule, "trigger", f"{title} : déclencheur", "trigger", "informational")
        docs = [pre]
        first = pre["name"]
        if n > 1:
            count = _correlation(rule, "pre_count", f"{title} : {n} conditions préalables",
                                 {"type": "event_count", "rules": [pre["name"]],
                                  "group-by": group, "timespan": span,
                                  "condition": {"gte": n}}, "informational")
            docs.append(count)
            first = count["name"]
        docs.append(trig)
        docs.append(_correlation(rule, "main", title,
                                 {"type": "temporal_ordered", "rules": [first, trig["name"]],
                                  "group-by": group, "timespan": span}, level))
        return docs

    if kind == "baseline_hour":
        doc = _base(rule, "main", f"{title} : événements de base", "selection",
                    "informational")
        doc["description"] += (" [mini-SIEM : la baseline des heures habituelles, par "
                               f"{', '.join(rule.get('group_by', ['user']))}, n'a pas "
                               "d'équivalent Sigma ; le SIEM cible doit la calculer.]")
        doc["falsepositives"] = ["toute connexion, tant que la baseline n'est pas appliquée"]
        return [doc]

    raise ValueError(f"type de règle sans équivalent Sigma : {kind!r}")


def rule_to_sigma(rule: dict) -> str:
    """Règle interne -> YAML Sigma (plusieurs documents si corrélation)."""
    return yaml.safe_dump_all(rule_to_sigma_docs(rule), allow_unicode=True,
                              sort_keys=False, width=100)
