#!/usr/bin/env python3
"""Génère les fichiers JS de la démo web à partir des sources Python, pour
éviter toute duplication : règles (YAML) et logs d'exemple restent uniques.

  web/rules.data.js           <- rules/*.yml
  web/samples.js              <- samples/*
  web/threat_feed.js          <- minisiem/data/threat_feed.json
  web/console.standalone.html <- web/console.html + scripts + styles intégrés
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
    "fw": Path("samples/ufw.log").read_text(encoding="utf-8"),
    "win": Path("samples/windows_events.xml").read_text(encoding="utf-8"),
    "sysmon": Path("samples/sysmon_events.xml").read_text(encoding="utf-8"),
    # le même journal Sysmon au format binaire .evtx, encodé en Base64
    "sysmon_evtx": __import__("base64").b64encode(Path("samples/sysmon_events.evtx").read_bytes()).decode(),
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

# --- Console autonome : un seul fichier HTML, scripts et styles intégrés ---
# La version servie (console.html) charge des fichiers externes sous une CSP
# « 'self' ». Le fichier autonome intègre tout : sa CSP autorise alors chaque
# bloc par son empreinte SHA-256, et rien d'autre (pas de 'unsafe-inline').
import base64
import hashlib
import re

console = Path("web/console.html").read_text(encoding="utf-8")


def _safe(code: str) -> str:
    # Une chaîne « </script » ou « <!-- » dans les données fermerait le bloc
    return code.replace("</script", "<\\/script").replace("<!--", "<\\!--")


def _inline_script(match):
    return "<script>\n" + _safe((Path("web") / match.group(1)).read_text(encoding="utf-8")) + "\n</script>"


def _inline_style(match):
    return "<style>\n" + (Path("web") / match.group(1)).read_text(encoding="utf-8") + "\n</style>"


def _sha(blocks):
    return " ".join("'sha256-" + base64.b64encode(hashlib.sha256(b.encode("utf-8")).digest()).decode() + "'"
                    for b in blocks)


standalone = re.sub(r'<script src="([^"]+)"></script>', _inline_script, console)
standalone = re.sub(r'<link rel="stylesheet" href="([^"]+)">', _inline_style, standalone)
scripts = re.findall(r"<script>(.*?)</script>", standalone, re.S)
styles = re.findall(r"<style>(.*?)</style>", standalone, re.S)
csp = (f"default-src 'none'; script-src {_sha(scripts)}; style-src {_sha(styles)}; "
       "img-src 'self'; base-uri 'none'; form-action 'none'")
standalone, n = re.subn(r'(<meta http-equiv="Content-Security-Policy" content=")[^"]*(">)',
                        lambda m: m.group(1) + csp + m.group(2), standalone)
assert n == 1, "CSP introuvable dans console.html"
Path("web/console.standalone.html").write_text(standalone, encoding="utf-8")
print(f"[+] console autonome -> web/console.standalone.html ({len(standalone)} octets, "
      f"{len(scripts)} scripts et {len(styles)} feuille(s) autorisés par empreinte)")
