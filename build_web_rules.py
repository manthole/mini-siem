#!/usr/bin/env python3
"""Génère les fichiers JS de la démo web à partir des sources Python, pour
éviter toute duplication : règles (YAML) et logs d'exemple restent uniques.

  web/rules.data.js  <- rules/*.yml
  web/samples.js     <- samples/*
"""
import json
from pathlib import Path

from minisiem.rules import load_rules

# --- Règles ---
rules = load_rules("rules")
for r in rules:
    r.pop("_file", None)

rules_js = ("/* Généré par build_web_rules.py — ne pas éditer à la main. */\n"
            "(function (root) {\n  root.MINISIEM_RULES = " +
            json.dumps(rules, ensure_ascii=False, indent=2) +
            ";\n  if (typeof module !== 'undefined' && module.exports) module.exports = root.MINISIEM_RULES;\n"
            "})(typeof window !== 'undefined' ? window : globalThis);\n")
Path("web/rules.data.js").write_text(rules_js, encoding="utf-8")
print(f"[+] {len(rules)} règles -> web/rules.data.js")

# --- Logs d'exemple embarqués ---
samples = {
    "auth": Path("samples/auth.log").read_text(encoding="utf-8"),
    "web": Path("samples/access.log").read_text(encoding="utf-8"),
    "win": Path("samples/windows_events.xml").read_text(encoding="utf-8"),
}
samples_js = ("/* Généré par build_web_rules.py — logs d'exemple synthétiques. */\n"
              "(function (root) {\n  root.MINISIEM_SAMPLES = " +
              json.dumps(samples, ensure_ascii=False) + ";\n"
              "})(typeof window !== 'undefined' ? window : globalThis);\n")
Path("web/samples.js").write_text(samples_js, encoding="utf-8")
print(f"[+] {len(samples)} jeux d'exemple -> web/samples.js")

# --- Flux CTI embarqué ---
feed = json.loads(Path("minisiem/data/threat_feed.json").read_text(encoding="utf-8"))
feed_js = ("/* Généré par build_web_rules.py — flux CTI de démo. */\n"
           "(function (root) {\n  root.MINISIEM_CTI = " +
           json.dumps(feed, ensure_ascii=False) + ";\n"
           "  if (typeof module !== 'undefined' && module.exports) module.exports = root.MINISIEM_CTI;\n"
           "})(typeof window !== 'undefined' ? window : globalThis);\n")
Path("web/threat_feed.js").write_text(feed_js, encoding="utf-8")
print(f"[+] {len(feed.get('indicators', []))} indicateurs CTI -> web/threat_feed.js")

# --- Console autonome : un seul fichier HTML, tous les scripts intégrés ---
import re
console = Path("web/console.html").read_text(encoding="utf-8")


def _inline(match):
    src = match.group(1)
    code = Path("web") / src
    return "<script>\n" + code.read_text(encoding="utf-8") + "\n</script>"


standalone = re.sub(r'<script src="([^"]+)"></script>', _inline, console)
Path("web/console.standalone.html").write_text(standalone, encoding="utf-8")
print(f"[+] console autonome -> web/console.standalone.html ({len(standalone)} octets)")
