"""Fuzzing : des entrées abîmées ou hostiles ne doivent ni planter ni bloquer l'analyse.

Le lecteur .evtx et les parsers de journaux texte reçoivent des fichiers fournis par
n'importe qui, en ligne de commande comme dans la console web. On leur envoie des
variantes mutées des échantillons (octets inversés, champs de taille ou de position
réécrits, coupures, morceaux recopiés ailleurs) et l'on vérifie, pour chacune :

  - aucune exception hors du cadre prévu, ni en Python ni en JavaScript ;
  - un temps de lecture borné (pas de boucle infinie, pas d'explosion) ;
  - un XML toujours exploitable par le parser, et des règles qui tournent ;
  - **le même résultat, octet pour octet, en Python et en JavaScript** (fuzzing
    différentiel : les deux lecteurs doivent rester d'accord même sur des fichiers
    absurdes, sinon l'un des deux a un bug).

Par défaut, quelques centaines de variantes (quelques secondes). L'intégration continue
en lance beaucoup plus, avec une graine différente à chaque exécution :
    FUZZ_ITERATIONS=20000 FUZZ_SEED=1234 python -m pytest tests/test_fuzz.py
La graine est affichée en cas d'échec : elle suffit à reproduire la variante fautive.
"""
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import evtx_craft as craft  # noqa: E402
from minisiem.evtx import EvtxError, read_evtx  # noqa: E402
from minisiem.parsers import parse_evtx_xml, parse_line  # noqa: E402
from minisiem.rules import load_rules, run_rules  # noqa: E402

RULES = load_rules(str(ROOT / "rules"))
NODE = shutil.which("node")
ITERATIONS = int(os.environ.get("FUZZ_ITERATIONS", "300"))
SEED = int(os.environ.get("FUZZ_SEED", "20261126"))
TIME_LIMIT = 2.0          # secondes par fichier, très large : les lectures prennent quelques ms


def _seeds() -> dict[str, bytes]:
    return {
        "windows": (ROOT / "samples" / "windows_events.evtx").read_bytes(),
        "sysmon": (ROOT / "samples" / "sysmon_events.evtx").read_bytes(),
        "riche": craft.evtx_file([craft.rich_record] * 3),
        "hostile": craft.evtx_file([craft.rich_record, lambda b: craft.hostile_record(b, 40),
                                    craft.rich_record]),
    }


_INTERESTING = [0, 1, 2, 0x7F, 0x80, 0xFF, 0x100, 0x200, 0x7FFF, 0xFFFF, 0x10000,
                0x7FFFFFFF, 0xFFFFFFFF]


def mutate(rng: random.Random, data: bytes) -> bytes:
    """Une à quatre mutations, ciblées sur le bloc (là où vit le XML binaire)."""
    b = bytearray(data)
    lo = 0x1000 + 0x200 if len(b) > 0x1300 else 0
    for _ in range(rng.randint(1, 4)):
        if len(b) <= lo + 8:
            break
        kind = rng.random()
        at = rng.randrange(lo, len(b) - 4)
        if kind < 0.35:                                   # bits inversés
            b[at] ^= 1 << rng.randrange(8)
        elif kind < 0.65:                                 # champ réécrit
            width = rng.choice((1, 2, 4))
            v = rng.choice(_INTERESTING + [rng.randrange(0x10000), rng.randrange(0x200, 0x10000)])
            b[at:at + width] = (v & ((1 << 8 * width) - 1)).to_bytes(width, "little")
        elif kind < 0.80:                                 # morceau recopié ailleurs
            n = rng.randint(1, min(64, len(b) - lo - 1))
            src = rng.randrange(lo, len(b) - n)
            b[at:at + n] = b[src:src + n]
        elif kind < 0.90:                                 # en-tête de bloc ou de fichier
            at = rng.choice((0x28, 0x2A, 0x1000 + 0x30, 0x1000 + 0x28, 0x1000 + 0x200 + 4))
            b[at:at + 2] = rng.choice(_INTERESTING).to_bytes(4, "little")[:2]
        else:                                             # fichier coupé
            del b[rng.randrange(lo, len(b)):]
    return bytes(b)


def _python_read(data: bytes):
    """XML rendus, ou None si le fichier est refusé d'emblée (signature absente)."""
    try:
        return list(read_evtx(data))
    except EvtxError:
        return None


def _check_python(name: str, data: bytes):
    t = time.perf_counter()
    xmls = _python_read(data)
    elapsed = time.perf_counter() - t
    assert elapsed < TIME_LIMIT, f"{name} : lecture en {elapsed:.1f} s"
    events = [e for e in (parse_evtx_xml(x) for x in xmls or []) if e]
    run_rules(RULES, events)
    return xmls


_JS = r"""
const S = require(process.argv[1] + "/web/minisiem.js");
const RULES = require(process.argv[1] + "/web/rules.data.js");
const fs = require("fs"), path = require("path");
const dir = process.argv[2], out = {};
for (const f of fs.readdirSync(dir)) {
  const bytes = new Uint8Array(fs.readFileSync(path.join(dir, f)));
  const t = Date.now();
  let xmls = null, error = null;
  try { xmls = S.readEvtx(bytes); } catch (e) { if (!/pas un fichier .evtx/.test(e.message)) error = String(e.stack || e); }
  const ms = Date.now() - t;
  try { const ev = (xmls || []).map(S.parseEvtxBlock).filter(Boolean); S.runRules(RULES, ev); }
  catch (e) { error = "règles/parser : " + String(e.stack || e); }
  out[f] = {xmls, error, ms};
}
process.stdout.write(JSON.stringify(out));
"""


def _js_read_dir(directory: str) -> dict:
    res = subprocess.run([NODE, "-e", _JS, str(ROOT), directory], capture_output=True,
                         text=True, check=True, env=dict(os.environ, TZ="UTC"))
    return json.loads(res.stdout)


# --------------------------------------------------------------------------
# Cas ciblés
# --------------------------------------------------------------------------

@pytest.mark.parametrize("depth", [24, 60, 2000])
def test_hostile_nested_fragments_are_rejected_quickly(depth):
    # Sans garde-fou : 0,5 s à 24 niveaux, x2,6 tous les deux niveaux (des heures à 40,
    # et la mémoire avec). Le fichier fait 70 Ko quelle que soit la profondeur.
    data = craft.evtx_file([craft.rich_record, lambda b: craft.hostile_record(b, depth),
                            craft.rich_record])
    t = time.perf_counter()
    xmls = list(read_evtx(data))
    assert time.perf_counter() - t < 0.5
    assert len(xmls) == 2                     # l'enregistrement hostile seul est écarté


def test_rich_seed_renders_every_value_type():
    (xml, *_) = read_evtx(craft.evtx_file([craft.rich_record]))
    for expected in ("S-1-5-21-1-2-3-1104", "2026-11-08T14:05:31.123Z", "0x8020000000000000",
                     ">-5<", ">0.1<", ">1.5e+20<", ">true<", ">0001ABFF<", ">alpha, beta<",
                     ">1, 2, 3<", ">A\x80é<", ">0x1010<", '<Inner k="v&quot;1">',
                     "<Misc>A&amp;&amp;bogus;x&lt;y&amp;zfin</Misc>"):
        assert expected in xml, expected
    assert "Vide=" not in xml                 # substitution optionnelle nulle : attribut omis
    assert parse_evtx_xml(xml) is not None


_PATHOLOGICAL = {
    "sudo sans espace": "Nov  8 10:00:01 web01 sudo[1]: " + "a" * 200_000,
    "sudo avec ' : '": "Nov  8 10:00:01 web01 sudo[1]: " + "a : " * 50_000,
    "Apache sans crochet fermant": "1.2.3.4 - - [" + "x" * 200_000,
    "Apache guillemet jamais fermé": '1.2.3.4 - - [08/Nov/2026:10:00:00 +0100] "GET ' + "a " * 100_000,
    "UFW en majuscules": "Nov  8 10:00:01 fw kernel: [UFW BLOCK] " + "A" * 200_000,
    "sshd répété": "Nov  8 10:00:01 web01 sshd[1]: " + "Failed password for " * 20_000,
}


@pytest.mark.parametrize("name", sorted(_PATHOLOGICAL))
def test_text_parsers_resist_regex_backtracking(name):
    # Avant correction, une ligne sudo de 40 000 caractères prenait 15 s en Python et 3 s
    # dans la console (retour arrière quadratique). On vise des lignes cinq fois plus longues.
    t = time.perf_counter()
    parse_line(_PATHOLOGICAL[name], 2026)
    assert time.perf_counter() - t < 0.5


def test_unclosed_event_blocks_are_linear():
    from minisiem.parsers import event_blocks
    t = time.perf_counter()
    assert list(event_blocks("<Event>" * 100_000)) == []
    assert time.perf_counter() - t < 0.5


@pytest.mark.skipif(NODE is None, reason="Node.js absent")
def test_js_resists_the_same_pathological_inputs(tmp_path):
    lines = json.dumps(list(_PATHOLOGICAL.values()) + ["<Event>" * 100_000])
    script = (f"const S = require({json.dumps(str(ROOT / 'web/minisiem.js'))});"
              "const L = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
              "const r = L.map(l => { const t = Date.now(); S.parseText(l, 2026); return Date.now() - t; });"
              "console.log(JSON.stringify(r));")
    out = subprocess.run([NODE, "-e", script], input=lines, capture_output=True, text=True,
                         check=True).stdout
    assert max(json.loads(out)) < 500


# --------------------------------------------------------------------------
# Fuzzing par mutation, différentiel Python / JavaScript
# --------------------------------------------------------------------------

def test_fuzz_evtx_python_and_js_agree_on_mutated_files():
    rng = random.Random(SEED)
    seeds = _seeds()
    names = sorted(seeds)
    batch = 400
    done = 0
    while done < ITERATIONS:
        n = min(batch, ITERATIONS - done)
        with tempfile.TemporaryDirectory() as d:
            expected = {}
            for i in range(n):
                seed_name = names[(done + i) % len(names)]
                data = mutate(rng, seeds[seed_name])
                name = f"{done + i:06d}_{seed_name}.evtx"
                Path(d, name).write_bytes(data)
                try:
                    expected[name] = _check_python(name, data)
                except Exception as exc:            # noqa: BLE001 — on veut voir tout échec
                    pytest.fail(f"graine {SEED}, variante {name} : Python a levé {exc!r}")
            if NODE:
                got = _js_read_dir(d)
                for name, xmls in expected.items():
                    js = got[name]
                    where = f"graine {SEED}, variante {name}"
                    assert js["error"] is None, f"{where} : JavaScript a levé {js['error']}"
                    assert js["ms"] < TIME_LIMIT * 1000, f"{where} : {js['ms']} ms en JavaScript"
                    assert js["xmls"] == xmls, f"{where} : Python et JavaScript divergent"
        done += n


def _line_mutations(rng: random.Random, line: str) -> str:
    chars = list(line)
    alphabet = ' :[]"=\\/\t\x00‮�é0123456789aZ-.'
    for _ in range(rng.randint(1, 5)):
        k = rng.random()
        at = rng.randrange(len(chars) + 1)
        if k < 0.4 and chars:
            chars[min(at, len(chars) - 1)] = rng.choice(alphabet)
        elif k < 0.7:
            chars.insert(at, rng.choice(alphabet + "COMMAND=" + " : "))
        elif k < 0.85 and chars:
            del chars[min(at, len(chars) - 1)]
        else:
            chars[at:at] = list(rng.choice(["Failed password for ", " from ", "SRC=", "DPT=",
                                            "invalid user ", " : ", "COMMAND=", '"GET /', "[UFW BLOCK]"]))
    return "".join(chars)


def _event_key(e: dict) -> list:
    return [e.get("event_type"), e.get("outcome"), e.get("user"), e.get("source_ip"),
            e.get("status"), e.get("url"), e.get("dest_port"), e.get("method")]


@pytest.mark.skipif(NODE is None, reason="Node.js absent")
def test_fuzz_text_lines_python_and_js_agree():
    rng = random.Random(SEED + 1)
    base = []
    for name in ("auth.log", "access.log", "ufw.log"):
        base += (ROOT / "samples" / name).read_text(encoding="utf-8").splitlines()
    lines = [_line_mutations(rng, rng.choice(base)) for _ in range(max(ITERATIONS, 300))]
    py = []
    for line in lines:
        ev = parse_line(line, 2026)
        py.append(None if ev is None else _event_key(ev.__dict__))
    script = (f"const S = require({json.dumps(str(ROOT / 'web/minisiem.js'))});"
              "const L = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
              "console.log(JSON.stringify(L.map(l => { const e = S.parseText(l, 2026); "
              "return e.length ? [e[0].event_type, e[0].outcome, e[0].user ?? null, e[0].source_ip ?? null,"
              " e[0].status ?? null, e[0].url ?? null, e[0].dest_port ?? null, e[0].method ?? null] : null; })));")
    out = subprocess.run([NODE, "-e", script], input=json.dumps(lines), capture_output=True,
                         text=True, check=True).stdout
    js = json.loads(out)
    for line, a, b in zip(lines, py, js):
        assert a == b, f"graine {SEED + 1} : divergence sur {line!r} : Python {a}, JavaScript {b}"


def _xml_mutations(rng: random.Random, xml: str) -> str:
    """Export XML abîmé : balises cassées, entités, chiffres non ASCII, nombres énormes."""
    chars = list(xml)
    pieces = ["<", ">", "&", "&amp;", "&#0;", "&#x10FFFF;", '"', "'", "/", "</Data>", "<Data Name=\"",
              "]]>", "<![CDATA[", "²", "٣", "9" * 5000, "-", "Z", "T", ":", ".", "\x00", "‮"]
    for _ in range(rng.randint(1, 6)):
        at = rng.randrange(len(chars) + 1)
        k = rng.random()
        if k < 0.45:
            chars[at:at] = list(rng.choice(pieces))
        elif k < 0.75 and chars:
            del chars[at:at + rng.randint(1, 12)]
        elif chars:
            chars[min(at, len(chars) - 1)] = rng.choice("<>&\"'/0123456789 ²")
    return "".join(chars)


def test_fuzz_xml_exports_never_crash():
    """Les exports XML (fichiers .xml déposés dans la console) : ni plantage ni lenteur,
    dans les deux moteurs. Les deux lisent le XML différemment (vrai parser en Python,
    expressions bornées en JavaScript) : on ne compare pas les résultats, seulement la tenue."""
    rng = random.Random(SEED + 2)
    base = []
    for name in ("windows_events.evtx", "sysmon_events.evtx"):
        base += list(read_evtx((ROOT / "samples" / name).read_bytes()))
    base += list(read_evtx(craft.evtx_file([craft.rich_record])))
    blocks = [_xml_mutations(rng, rng.choice(base)) for _ in range(max(ITERATIONS // 4, 100))]
    for block in blocks:
        t = time.perf_counter()
        try:
            events = [e for e in [parse_evtx_xml(block)] if e]
            run_rules(RULES, events)
        except Exception as exc:                      # noqa: BLE001
            pytest.fail(f"graine {SEED + 2} : Python a levé {exc!r} sur {block[:300]!r}")
        assert time.perf_counter() - t < TIME_LIMIT
    if NODE:
        script = (f"const S = require({json.dumps(str(ROOT / 'web/minisiem.js'))});"
                  f"const R = require({json.dumps(str(ROOT / 'web/rules.data.js'))});"
                  "const B = JSON.parse(require('fs').readFileSync(0, 'utf8')); const bad = [];"
                  "for (const b of B) { const t = Date.now();"
                  "  try { S.runRules(R, S.parseText(b, 2026)); } catch (e) { bad.push([b.slice(0, 300), String(e)]); }"
                  "  if (Date.now() - t > 2000) bad.push([b.slice(0, 300), 'lent']); }"
                  "console.log(JSON.stringify(bad));")
        out = subprocess.run([NODE, "-e", script], input=json.dumps(blocks), capture_output=True,
                             text=True, check=True).stdout
        assert json.loads(out) == [], f"graine {SEED + 2} : JavaScript a échoué : {out[:600]}"
