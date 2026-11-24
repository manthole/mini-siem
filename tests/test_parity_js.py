"""Parité Python / JavaScript : la console web annonce un moteur identique à la
version Python. Ce test le vérifie : mêmes journaux d'exemple, mêmes alertes
(règle, nombre d'occurrences, IP, compte), même table GeoIP de démo.
Ignoré si Node.js n'est pas installé.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from minisiem.cti import ThreatIntel, detect_threat_contacts  # noqa: E402
from minisiem.parsers import parse_file  # noqa: E402
from minisiem.rules import load_rules, run_rules  # noqa: E402

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js absent")

SAMPLES = ["auth.log", "access.log", "ufw.log", "windows_events.xml", "sysmon_events.xml"]

_JS = r"""
const fs = require("fs"), path = require("path");
const root = process.argv[1];
const S = require(path.join(root, "web/minisiem.js"));
const RULES = require(path.join(root, "web/rules.data.js"));
const cti = S.ctiIndex(require(path.join(root, "web/threat_feed.js")));
function run(text) {
  const events = S.parseText(text, 2026);
  let alerts = S.runRules(RULES, events);
  alerts = alerts.concat(S.ctiDetectContacts(cti, events, alerts));
  return {events: events.length,
          alerts: alerts.map(a => [a.rule_id, a.count, a.source_ip || "", a.user || ""]).sort()};
}
const files = process.argv.slice(2);
const texts = files.map(f => fs.readFileSync(path.join(root, "samples", f), "utf8"));
const out = {geo: S.GEO, all: run(texts.join("\n"))};
files.forEach((f, i) => { out[f] = run(texts[i]); });
console.log(JSON.stringify(out));
"""


def _python(paths):
    rules = load_rules(str(ROOT / "rules"))
    events = [e for p in paths for e in parse_file(str(ROOT / "samples" / p), year=2026)]
    alerts = run_rules(rules, events)
    alerts += detect_threat_contacts(ThreatIntel(), events, alerts)
    return {"events": len(events),
            "alerts": sorted([a.rule_id, a.count, a.source_ip or "", a.user or ""]
                             for a in alerts)}


@pytest.fixture(scope="module")
def js():
    env = dict(os.environ, TZ="UTC")
    out = subprocess.run([NODE, "-e", _JS, str(ROOT), *SAMPLES], env=env,
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


@pytest.mark.parametrize("sample", SAMPLES)
def test_same_alerts_per_source(js, sample):
    assert js[sample] == _python([sample])


def test_same_alerts_all_sources_together(js):
    # « Tout charger » dans la console : journaux texte et XML mélangés
    assert js["all"] == _python(SAMPLES)


def test_same_geo_demo_table(js):
    data = json.loads((ROOT / "minisiem/data/geo_demo.json").read_text(encoding="utf-8"))
    data.pop("_comment", None)
    assert js["geo"] == data
