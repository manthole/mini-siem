#!/usr/bin/env python3
"""Couverture mesurée sur de vraies attaques : EVTX-ATTACK-SAMPLES.

Le dépôt public EVTX-ATTACK-SAMPLES (Samir Bousseaden) rassemble près de 280
enregistrements de journaux Windows capturés pendant l'exécution de vraies techniques
d'attaque, rangés par tactique ATT&CK. Ce script les passe tous dans mini-SIEM et
écrit le tableau des attaques détectées et de celles qui passent (COVERAGE.md).
L'intégration continue le refait à chaque envoi.

Les enregistrements ne sont pas copiés dans ce dépôt : ils sont sous une autre licence
(GPL-3.0) et ce sont des traces d'attaques. --fetch les télécharge à une version figée
(SAMPLES_COMMIT), et seulement les fichiers .evtx (le dépôt d'origine contient aussi
d'autres fichiers, qu'on ne veut pas récupérer).

    python attack_coverage.py --fetch /tmp/evtx-attack-samples --markdown COVERAGE.md --readme README.md
    python attack_coverage.py /tmp/evtx-attack-samples            # tableau dans le terminal
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from minisiem.evtx import EvtxError, read_evtx
from minisiem.parsers import _EVTX_MAP, _SYSMON_MAP, parse_evtx_xml
from minisiem.rules import load_rules, run_rules

SAMPLES_REPO = "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES"
SAMPLES_COMMIT = "4ceed2f4706daf601c212a8f91c113dd85349a2c"
# Seuls les .evtx sont extraits : le dépôt d'origine contient aussi des scripts, des
# captures réseau (.pcap), des traces ETW (.etl) et des images, jamais téléchargés.
SPARSE_PATTERNS = ["/**/*.evtx"]

# Dossier du jeu de données -> tactiques ATT&CK attendues. Depuis ATT&CK v19, Defense
# Evasion est scindée en Stealth et Defense Impairment : les règles emploient les
# nouveaux noms, le jeu de données l'ancien.
EXPECTED = {
    "Command and Control": {"Command and Control"},
    "Credential Access": {"Credential Access"},
    "Defense Evasion": {"Stealth", "Defense Impairment", "Defense Evasion"},
    "Discovery": {"Discovery"},
    "Execution": {"Execution"},
    "Lateral Movement": {"Lateral Movement"},
    "Persistence": {"Persistence"},
    "Privilege Escalation": {"Privilege Escalation"},
}
# Dossiers sans tactique unique (outils de test automatisés, divers, racine)
NO_TACTIC = "(sans tactique)"

DETECTED, FLAGGED, MISSED, OUT = "détectée", "signalée", "manquée", "hors périmètre"
VERDICTS = [DETECTED, FLAGGED, MISSED, OUT]
ICON = {DETECTED: "✅", FLAGGED: "🟡", MISSED: "❌", OUT: "⚪"}

_EID = re.compile(r"<EventID\b[^>]*>\s*([0-9]{1,10})\s*</EventID>")
_CHANNEL = re.compile(r"<Channel>([^<]*)</Channel>")
_SHORT_CHANNEL = {
    "Microsoft-Windows-Sysmon/Operational": "Sysmon",
    "Microsoft-Windows-PowerShell/Operational": "PowerShell",
    "Windows PowerShell": "PowerShell (classique)",
}

README_START = "<!-- couverture:debut (généré par attack_coverage.py) -->"
README_END = "<!-- couverture:fin -->"


@dataclass
class Result:
    path: str                       # chemin relatif dans le jeu de données
    folder: str                     # tactique du dossier, ou NO_TACTIC
    verdict: str = OUT
    rules: list[str] = field(default_factory=list)       # règles déclenchées
    tactics: list[str] = field(default_factory=list)
    sources: set[tuple[str, int]] = field(default_factory=set)   # (journal, EventID)
    records: int = 0
    events: int = 0                 # événements compris par mini-SIEM
    artifact_removed: bool = False
    error: str | None = None


# --------------------------------------------------------------------------
# Téléchargement
# --------------------------------------------------------------------------

def _git(*args: str, cwd: Path) -> str:
    res = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} : {res.stderr.strip()}")
    return res.stdout.strip()


def fetch(dest: Path) -> None:
    """Récupère uniquement les .evtx de SAMPLES_COMMIT dans dest (clone partiel et
    creux : les autres fichiers du dépôt ne sont jamais téléchargés)."""
    if (dest / ".git").is_dir():
        head = _git("rev-parse", "HEAD", cwd=dest)
        if head != SAMPLES_COMMIT:
            raise SystemExit(f"{dest} contient la version {head[:12]}, pas {SAMPLES_COMMIT[:12]} : "
                             "choisir un dossier vide")
    else:
        dest.mkdir(parents=True, exist_ok=True)
        if any(dest.iterdir()):
            raise SystemExit(f"{dest} n'est pas vide")
        _git("init", "-q", cwd=dest)
        _git("remote", "add", "origin", SAMPLES_REPO, cwd=dest)
        _git("config", "core.sparseCheckout", "true", cwd=dest)
        (dest / ".git" / "info").mkdir(exist_ok=True)
        (dest / ".git" / "info" / "sparse-checkout").write_text("\n".join(SPARSE_PATTERNS) + "\n")
        _git("fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", SAMPLES_COMMIT, cwd=dest)
        _git("-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD", cwd=dest)
    others = [p for p in dest.rglob("*") if p.is_file() and ".git" not in p.relative_to(dest).parts
              and p.suffix.lower() != ".evtx"]
    if others:
        raise SystemExit(f"fichiers inattendus dans {dest} : {[str(p) for p in others[:5]]}")


# --------------------------------------------------------------------------
# Mesure
# --------------------------------------------------------------------------

def _is_capture_artifact(xml: str, name: str) -> bool:
    """Dans une partie des enregistrements, le premier événement est l'effacement du
    journal de sécurité (1102) fait par l'auteur juste avant la capture. Ce n'est pas
    l'attaque : le garder ferait « détecter » ces fichiers par la règle WIN_LOG_CLEARED.
    On le retire, sauf quand l'effacement est justement l'attaque enregistrée."""
    m = _EID.search(xml)
    return bool(m and m[1] == "1102" and "1102" not in name)


def measure(root: Path, rules: list[dict]) -> list[Result]:
    results = []
    for path in sorted(root.rglob("*.evtx"), key=lambda p: p.relative_to(root).as_posix()):
        rel = path.relative_to(root)
        if ".git" in rel.parts:
            continue
        folder = rel.parts[0] if len(rel.parts) > 1 and rel.parts[0] in EXPECTED else NO_TACTIC
        r = Result(path=rel.as_posix(), folder=folder)
        try:
            xmls = list(read_evtx(path.read_bytes()))
        except EvtxError as exc:
            r.error = str(exc)
            results.append(r)
            continue
        r.records = len(xmls)
        if xmls and _is_capture_artifact(xmls[0], path.name):
            xmls = xmls[1:]
            r.artifact_removed = True
        for x in xmls:
            eid, chan = _EID.search(x), _CHANNEL.search(x)
            if eid:
                r.sources.add((chan[1] if chan else "?", int(eid[1])))
        events = [e for e in (parse_evtx_xml(x) for x in xmls) if e]
        r.events = len(events)
        alerts = run_rules(rules, events)
        r.rules = sorted({a.rule_id for a in alerts})
        r.tactics = sorted({a.tactic for a in alerts})
        if alerts:
            want = EXPECTED.get(folder, set())
            r.verdict = DETECTED if want & set(r.tactics) else FLAGGED
        else:
            r.verdict = MISSED if events else OUT
        results.append(r)
    return results


# --------------------------------------------------------------------------
# Rendu
# --------------------------------------------------------------------------

def _pct(a: int, b: int) -> str:
    return f"{100 * a / b:.1f} %".replace(".", ",") if b else "–"


def _md(s: str) -> str:
    return s.replace("|", "\\|")


def _channel(c: str) -> str:
    return _SHORT_CHANNEL.get(c, c)


def summary(results: list[Result]) -> dict:
    c = Counter(r.verdict for r in results)
    total = len(results)
    in_scope = total - c[OUT]
    alert = c[DETECTED] + c[FLAGGED]
    return {"total": total, "in_scope": in_scope, "alert": alert, **{v: c[v] for v in VERDICTS},
            "rate_in_scope": _pct(alert, in_scope), "rate_total": _pct(alert, total)}


def render_markdown(results: list[Result], n_rules: int) -> str:
    s = summary(results)
    out = []
    w = out.append
    w("# Couverture mesurée : EVTX-ATTACK-SAMPLES")
    w("")
    w("_Fichier généré par `attack_coverage.py` et vérifié par l'intégration continue à chaque "
      "envoi : il ne peut pas être retouché à la main sans que les tests échouent._")
    w("")
    w(f"Jeu de données : [EVTX-ATTACK-SAMPLES]({SAMPLES_REPO}) de Samir Bousseaden, version "
      f"[`{SAMPLES_COMMIT[:12]}`]({SAMPLES_REPO}/tree/{SAMPLES_COMMIT}) : {s['total']} "
      "enregistrements de journaux Windows capturés pendant de vraies techniques d'attaque. "
      "Ils ne sont pas copiés dans ce dépôt ; l'intégration continue les télécharge.")
    w("")
    w(f"Règles évaluées : {n_rules}.")
    w("")
    w("## Résultat")
    w("")
    w(f"- **{s['alert']} enregistrements sur {s['total']}** déclenchent au moins une alerte "
      f"({s['rate_total']}).")
    w(f"- Parmi les {s['in_scope']} enregistrements qui contiennent des événements que mini-SIEM "
      f"sait lire, **{s['alert']} déclenchent une alerte ({s['rate_in_scope']})**.")
    w(f"- {ICON[DETECTED]} **{s[DETECTED]} détectées** : au moins une alerte de la tactique attendue.")
    w(f"- {ICON[FLAGGED]} **{s[FLAGGED]} signalées** : une alerte, mais d'une autre tactique "
      "(ou dossier sans tactique unique). L'analyste est prévenu, avec une étiquette imparfaite.")
    w(f"- {ICON[MISSED]} **{s[MISSED]} manquées** : mini-SIEM lit des événements du fichier, "
      "aucune règle ne se déclenche. L'attaque passe.")
    w(f"- {ICON[OUT]} **{s[OUT]} hors périmètre** : aucun événement d'un journal ou d'un type "
      "que mini-SIEM lit (voir plus bas les sources les plus fréquentes).")
    w("")
    w("Le chiffre est volontairement modeste : mini-SIEM est un projet d'apprentissage avec une "
      "vingtaine de règles, et ce jeu de données couvre des centaines de techniques. Le tableau "
      "sert à montrer honnêtement ce qui passe et à suivre l'effet de chaque nouvelle règle.")
    w("")

    w("## Par tactique")
    w("")
    w("| Dossier (tactique) | Enregistrements | ✅ | 🟡 | ❌ | ⚪ | Alerte, dans le périmètre |")
    w("|---|---:|---:|---:|---:|---:|---:|")
    by_folder: dict[str, list[Result]] = defaultdict(list)
    for r in results:
        by_folder[r.folder].append(r)
    order = sorted(by_folder, key=lambda f: (f == NO_TACTIC, f))
    for f in order:
        rs = by_folder[f]
        c = Counter(r.verdict for r in rs)
        in_scope = len(rs) - c[OUT]
        w(f"| {f} | {len(rs)} | {c[DETECTED]} | {c[FLAGGED]} | {c[MISSED]} | {c[OUT]} | "
          f"{_pct(c[DETECTED] + c[FLAGGED], in_scope)} |")
    w(f"| **Total** | **{s['total']}** | **{s[DETECTED]}** | **{s[FLAGGED]}** | **{s[MISSED]}** | "
      f"**{s[OUT]}** | **{s['rate_in_scope']}** |")
    w("")

    w("## Règles qui se déclenchent")
    w("")
    w("| Règle | Enregistrements | dont tactique attendue |")
    w("|---|---:|---:|")
    fired: Counter = Counter()
    fired_ok: Counter = Counter()
    for r in results:
        for rule in r.rules:
            fired[rule] += 1
            if r.verdict == DETECTED:
                fired_ok[rule] += 1
    for rule, n in sorted(fired.items(), key=lambda kv: (-kv[1], kv[0])):
        w(f"| `{rule}` | {n} | {fired_ok[rule]} |")
    w("")

    w("## Ce qui manque le plus")
    w("")
    w("Sources (journal et numéro d'événement) présentes dans les enregistrements **manqués ou "
      "hors périmètre**, par nombre d'enregistrements : les meilleures pistes. Quand mini-SIEM "
      "lit déjà la source, ce sont des règles qui manquent ; sinon, un type d'événement à lire.")
    w("")
    w("| Journal | EventID | Enregistrements non détectés | Lu par mini-SIEM |")
    w("|---|---:|---:|---|")
    missing: Counter = Counter()
    for r in results:
        if r.verdict in (MISSED, OUT):
            missing.update(r.sources)
    for (chan, eid), n in sorted(missing.items(), key=lambda kv: (-kv[1], kv[0]))[:15]:
        known = eid in (_SYSMON_MAP if "sysmon" in chan.lower() else _EVTX_MAP)
        w(f"| {_md(_channel(chan))} | {eid} | {n} | {'oui : il manque des règles' if known else 'non'} |")
    w("")

    w("## Détail par enregistrement")
    w("")
    for f in order:
        rs = by_folder[f]
        c = Counter(r.verdict for r in rs)
        counts = " · ".join(f"{ICON[v]} {c[v]}" for v in VERDICTS if c[v])
        w(f"<details><summary><b>{f}</b> : {len(rs)} enregistrements ({counts})</summary>")
        w("")
        w("| Enregistrement | Verdict | Règles déclenchées |")
        w("|---|---|---|")
        for r in rs:
            name = r.path.split("/", 1)[1] if r.folder != NO_TACTIC and "/" in r.path else r.path
            rules = ", ".join(f"`{x}`" for x in r.rules) or "–"
            note = " (illisible)" if r.error else ""
            w(f"| `{_md(name)}` | {ICON[r.verdict]} {r.verdict}{note} | {rules} |")
        w("")
        w("</details>")
        w("")

    removed = sum(r.artifact_removed for r in results)
    w("## Méthode")
    w("")
    w("- Chaque enregistrement est lu par le lecteur `.evtx` de mini-SIEM (celui de la ligne de "
      "commande), puis passé seul dans toutes les règles, corrélations comprises.")
    w("- Le verdict compare la tactique des alertes au dossier où l'auteur a rangé "
      "l'enregistrement. Depuis ATT&CK v19, « Defense Evasion » correspond à Stealth ou "
      "Defense Impairment.")
    w(f"- Artefact de capture : dans {removed} enregistrements, le premier événement est "
      "l'effacement du journal de sécurité (1102) fait juste avant la capture. Il est retiré, "
      "sinon la règle `WIN_LOG_CLEARED` « détecterait » ces fichiers sans rien voir de l'attaque. "
      "Il est gardé quand l'effacement est l'attaque enregistrée (nom de fichier contenant 1102).")
    w("- **Ce n'est pas un test à l'aveugle.** Ces enregistrements ont déjà servi à repérer des "
      "manques (la règle `SYSMON_COMSVCS_MINIDUMP` vient de là). Une règle écrite pour un "
      "fichier précis ferait monter le chiffre sans rien améliorer ailleurs : le tableau sert à "
      "suivre l'évolution et à voir ce qui passe, pas à annoncer un taux de détection réel.")
    w("")
    w("Pour régénérer ce fichier :")
    w("")
    w("```")
    w("python attack_coverage.py --fetch /tmp/evtx-attack-samples --markdown COVERAGE.md --readme README.md")
    w("```")
    return "\n".join(out) + "\n"


def render_readme_block(results: list[Result]) -> str:
    s = summary(results)
    return (f"{README_START}\n"
            f"| Enregistrements | Alerte | ✅ tactique attendue | ❌ manquées | ⚪ hors périmètre |\n"
            f"|---:|---:|---:|---:|---:|\n"
            f"| {s['total']} | {s['alert']} ({s['rate_total']}) | {s[DETECTED]} | {s[MISSED]} | "
            f"{s[OUT]} |\n\n"
            f"Dans le périmètre de mini-SIEM (fichiers contenant des événements qu'il sait lire) : "
            f"**{s['alert']} sur {s['in_scope']} ({s['rate_in_scope']})**. "
            f"Détail, méthode et limites : [COVERAGE.md](COVERAGE.md).\n"
            f"{README_END}")


def update_readme(path: Path, block: str) -> None:
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(re.escape(README_START) + r".*?" + re.escape(README_END), re.S)
    if not pattern.search(text):
        raise SystemExit(f"{path} : marqueurs {README_START!r} … {README_END!r} absents")
    path.write_text(pattern.sub(lambda _: block, text), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Couverture de mini-SIEM sur EVTX-ATTACK-SAMPLES.")
    p.add_argument("samples", nargs="?", help="dossier EVTX-ATTACK-SAMPLES déjà téléchargé")
    p.add_argument("--fetch", metavar="DIR", help=f"télécharge d'abord les .evtx de la version "
                   f"{SAMPLES_COMMIT[:12]} dans DIR (vide), puis mesure")
    p.add_argument("--rules", default=str(Path(__file__).parent / "rules"), help="dossier des règles")
    p.add_argument("--markdown", metavar="FICHIER", help="écrit le tableau complet (COVERAGE.md)")
    p.add_argument("--readme", metavar="FICHIER", help="met à jour le résumé entre les marqueurs")
    p.add_argument("--summary", metavar="FICHIER",
                   help="ajoute le tableau à FICHIER (résumé de l'exécution GitHub Actions)")
    args = p.parse_args(argv)
    if not (args.samples or args.fetch):
        p.error("indiquer le dossier des enregistrements, ou --fetch DIR")
    root = Path(args.fetch or args.samples)
    if args.fetch:
        fetch(root)
    elif (root / ".git").is_dir() and _git("rev-parse", "HEAD", cwd=root) != SAMPLES_COMMIT:
        print(f"attention : {root} n'est pas à la version {SAMPLES_COMMIT[:12]}", file=sys.stderr)

    rules = load_rules(args.rules)
    results = measure(root, rules)
    if not results:
        raise SystemExit(f"aucun fichier .evtx dans {root}")
    md = render_markdown(results, len(rules))
    if args.markdown:
        Path(args.markdown).write_text(md, encoding="utf-8")
    if args.readme:
        update_readme(Path(args.readme), render_readme_block(results))
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(md)
    s = summary(results)
    print(f"{s['total']} enregistrements : {s['alert']} avec alerte ({s['rate_total']}), "
          f"dont {s[DETECTED]} de la tactique attendue ; {s[MISSED]} manqués ; "
          f"{s[OUT]} hors périmètre. Dans le périmètre : {s['rate_in_scope']}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
