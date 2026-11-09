#!/usr/bin/env python3
"""mini-SIEM — point d'entrée CLI.

Exemples :
    python analyze.py samples/auth.log
    python analyze.py samples/auth.log --rules rules --out rapport.html
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from minisiem.parsers import parse_file
from minisiem.rules import load_rules, run_rules
from minisiem.report import render_report
from minisiem.events import SEVERITY_ORDER
from minisiem.geo import GeoResolver, enrich
from minisiem.config import Config, apply_config
from minisiem.export import alerts_to_json, rule_to_sigma
from minisiem.cti import ThreatIntel, enrich_alerts, detect_threat_contacts


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Analyseur de logs défensif (mini-SIEM).")
    p.add_argument("logs", nargs="*", help="fichiers de log à analyser (ex: auth.log)")
    p.add_argument("--rules", default="rules", help="dossier des règles YAML")
    p.add_argument("--out", default="rapport.html", help="fichier HTML de sortie")
    p.add_argument("--config", default=None, help="config.yml (listes blanches, règles désactivées)")
    p.add_argument("--json", default=None, help="exporte aussi les alertes en JSON")
    p.add_argument("--min-severity", default="low",
                   choices=["low", "medium", "high", "critical"],
                   help="n'affiche que les alertes de sévérité >= ce niveau")
    p.add_argument("--year", type=int, default=None,
                   help="année à appliquer aux timestamps (auth.log ne la contient pas)")
    p.add_argument("--list-rules", action="store_true", help="liste les règles et quitte")
    p.add_argument("--export-sigma", metavar="DIR", default=None,
                   help="convertit les règles au format Sigma dans DIR et quitte")
    args = p.parse_args(argv)

    rules = load_rules(args.rules)

    if args.list_rules:
        for r in rules:
            print(f"{r['id']:24} [{r.get('level','?'):8}] {r['title']}  ({r.get('attack','-')})")
        return 0

    if args.export_sigma:
        outdir = Path(args.export_sigma)
        outdir.mkdir(parents=True, exist_ok=True)
        for r in rules:
            (outdir / f"{r['id'].lower()}.yml").write_text(rule_to_sigma(r), encoding="utf-8")
        print(f"[+] {len(rules)} règles exportées en Sigma dans {outdir}")
        return 0

    if not args.logs:
        p.error("aucun fichier de log fourni")

    events = []
    for path in args.logs:
        if not Path(path).exists():
            print(f"[!] fichier introuvable : {path}", file=sys.stderr)
            return 2
        events.extend(parse_file(path, year=args.year))

    if not events:
        print("[!] aucun événement reconnu dans les logs fournis.", file=sys.stderr)
        return 1

    alerts = run_rules(rules, events)

    # CTI : détecte les contacts avec des IP connues malveillantes (même sans
    # seuil de volume), puis enrichit toutes les alertes avec le renseignement.
    ti = ThreatIntel()
    alerts += detect_threat_contacts(ti, events, alerts)
    cti_enriched = enrich_alerts(alerts, ti)

    config = Config.load(args.config)
    before = len(alerts)
    alerts = apply_config(alerts, config)
    suppressed = before - len(alerts)

    min_rank = SEVERITY_ORDER[args.min_severity]
    alerts = [a for a in alerts if SEVERITY_ORDER.get(a.severity, 9) <= min_rank]

    resolver = GeoResolver()
    enrich(alerts, resolver)

    print(f"[+] {len(events)} événements analysés, {len(rules)} règles chargées.")
    print(f"[+] GeoIP : mode {resolver.mode}."
          + (f"  Listes blanches : {suppressed} alerte(s) supprimée(s)." if suppressed else ""))
    print(f"[+] CTI : flux « {ti.feed_name} », {ti.size} indicateurs, "
          f"{cti_enriched} alerte(s) enrichie(s).")
    print(f"[+] {len(alerts)} alerte(s) :")
    for a in sorted(alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 9)):
        ip = a.source_ip or "-"
        print(f"    - [{a.severity.upper():8}] {a.title}  ip={ip} "
              f"user={a.user or '-'} x{a.count}  {a.attack}")

    Path(args.out).write_text(render_report(alerts, events), encoding="utf-8")
    print(f"[+] rapport écrit : {args.out}")
    if args.json:
        Path(args.json).write_text(alerts_to_json(alerts), encoding="utf-8")
        print(f"[+] alertes JSON : {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
