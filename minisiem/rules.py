"""Moteur de détection piloté par des règles YAML (format proche de Sigma).

Trois types de règles sont gérés en V1 :
  - match      : un seul événement suffit (ex : échec sudo "NOT in sudoers")
  - threshold  : N événements d'une même clé dans une fenêtre de temps
  - sequence   : des événements A suivis d'un événement B, même clé
Ajouter une détection = ajouter un fichier .yml, sans toucher au code.
"""
from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from .events import Event, Alert


def _as_list(v: Any) -> list:
    return v if isinstance(v, list) else [v]


def _match_field(value: Any, expected: Any) -> bool:
    """Compare une valeur d'événement à la condition d'une règle.

    `expected` peut être :
      - une valeur          -> égalité
      - une liste           -> appartenance
      - un dict d'opérateur -> {contains|regex|in|gte|lte: ...}
    """
    if isinstance(expected, dict):
        for op, operand in expected.items():
            if op == "contains":
                hay = str(value or "").lower()
                if not any(str(o).lower() in hay for o in _as_list(operand)):
                    return False
            elif op == "regex":
                if value is None or not re.search(operand, str(value), re.I):
                    return False
            elif op == "in":
                if value not in _as_list(operand):
                    return False
            elif op == "gte":
                if value is None or value < operand:
                    return False
            elif op == "lte":
                if value is None or value > operand:
                    return False
            else:
                raise ValueError(f"opérateur de règle inconnu : {op!r}")
        return True
    if isinstance(expected, list):
        return value in expected
    return value == expected


def load_rules(rules_dir: str) -> list[dict[str, Any]]:
    rules = []
    for path in sorted(Path(rules_dir).glob("*.y*ml")):
        with open(path, encoding="utf-8") as fh:
            rule = yaml.safe_load(fh)
        rule["_file"] = path.name
        rules.append(rule)
    return rules


def _matches(ev: Event, conditions: dict[str, Any]) -> bool:
    """Un événement satisfait-il les conditions `selection` d'une règle ?"""
    for field_name, expected in conditions.items():
        if not _match_field(getattr(ev, field_name, None), expected):
            return False
    return True


def _key(ev: Event, group_by: list[str]) -> tuple:
    return tuple(getattr(ev, g, None) for g in group_by)


def _alert_from(rule: dict, events: list[Event]) -> Alert:
    events = sorted(events, key=lambda e: e.timestamp)
    first, last = events[0], events[-1]
    return Alert(
        rule_id=rule["id"],
        title=rule["title"],
        severity=rule.get("level", "medium"),
        attack=rule.get("attack", "-"),
        source_ip=first.source_ip,
        user=first.user,
        first_seen=first.timestamp,
        last_seen=last.timestamp,
        count=len(events),
        description=rule.get("description", ""),
        tactic=rule.get("tactic", "-"),
        evidence=[e.raw for e in events[:8]],  # 8 preuves max par alerte
    )


def _run_match(rule: dict, events: list[Event]) -> list[Alert]:
    """Une alerte par groupe (défaut : source_ip + user), pas par événement :
    on agrège les occurrences comme le ferait un vrai SIEM."""
    sel = rule.get("selection", {})
    group_by = rule.get("group_by", ["source_ip", "user"])
    buckets: dict[tuple, list[Event]] = {}
    for e in events:
        if _matches(e, sel):
            buckets.setdefault(_key(e, group_by), []).append(e)
    return [_alert_from(rule, group) for group in buckets.values()]


def _run_threshold(rule: dict, events: list[Event]) -> list[Alert]:
    sel = rule.get("selection", {})
    group_by = rule.get("group_by", ["source_ip"])
    window = timedelta(seconds=rule.get("window_seconds", 300))
    threshold = rule.get("count", 10)
    distinct = rule.get("distinct")  # ex "dest_port" : compte les valeurs uniques

    buckets: dict[tuple, list[Event]] = {}
    for e in sorted((e for e in events if _matches(e, sel)), key=lambda e: e.timestamp):
        buckets.setdefault(_key(e, group_by), []).append(e)

    def reached(window_events: list[Event]) -> bool:
        if distinct:
            return len({getattr(e, distinct) for e in window_events}) >= threshold
        return len(window_events) >= threshold

    alerts: list[Alert] = []
    for group in buckets.values():
        # fenêtre glissante : on cherche quand le seuil est atteint en `window`
        start = 0
        for end in range(len(group)):
            while group[end].timestamp - group[start].timestamp > window:
                start += 1
            if reached(group[start:end + 1]):
                alerts.append(_alert_from(rule, group[start:end + 1]))
                break  # une alerte par groupe suffit pour le rapport
    return alerts


def _run_sequence(rule: dict, events: list[Event]) -> list[Alert]:
    """A suivi de B, pour une même clé, B dans la fenêtre après le dernier A."""
    pre = rule.get("precondition", {})
    trig = rule.get("trigger", {})
    group_by = rule.get("group_by", ["source_ip"])
    window = timedelta(seconds=rule.get("window_seconds", 600))
    min_pre = rule.get("min_preconditions", 1)

    pending: dict[tuple, list[Event]] = {}
    alerts: list[Alert] = []
    for e in sorted(events, key=lambda e: e.timestamp):
        k = _key(e, group_by)
        if _matches(e, pre):
            pending.setdefault(k, []).append(e)
        elif _matches(e, trig):
            befores = [p for p in pending.get(k, [])
                       if timedelta(0) <= e.timestamp - p.timestamp <= window]
            if len(befores) >= min_pre:
                alerts.append(_alert_from(rule, befores + [e]))
                pending[k] = []  # évite les doublons en cascade
    return alerts


def _run_baseline_hour(rule: dict, events: list[Event]) -> list[Alert]:
    """Signale les connexions à une heure inhabituelle pour l'utilisateur.

    On construit, par utilisateur, l'ensemble de ses heures « habituelles »
    (celles où il se connecte au moins `min_support` fois). Une connexion dont
    l'heure n'est pas habituelle est signalée.
    """
    sel = rule.get("selection", {})
    group_by = rule.get("group_by", ["user"])
    min_support = rule.get("min_support", 2)

    by_user: dict[tuple, list[Event]] = {}
    for e in events:
        if _matches(e, sel):
            by_user.setdefault(_key(e, group_by), []).append(e)

    alerts: list[Alert] = []
    for group in by_user.values():
        hours: dict[int, int] = {}
        for e in group:
            hours[e.timestamp.hour] = hours.get(e.timestamp.hour, 0) + 1
        usual = {h for h, n in hours.items() if n >= min_support}
        if not usual:
            continue  # pas assez d'historique pour juger
        odd = [e for e in group if e.timestamp.hour not in usual]
        if odd:
            alerts.append(_alert_from(rule, odd))
    return alerts


_RUNNERS = {
    "match": _run_match,
    "threshold": _run_threshold,
    "sequence": _run_sequence,
    "baseline_hour": _run_baseline_hour,
}


def run_rules(rules: list[dict], events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in rules:
        runner = _RUNNERS.get(rule.get("type", "match"))
        if runner is None:
            raise ValueError(f"type de règle inconnu : {rule.get('type')!r} "
                             f"({rule.get('_file')})")
        alerts.extend(runner(rule, events))
    return alerts
