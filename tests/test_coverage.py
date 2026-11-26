"""attack_coverage.py : verdicts, artefact de capture et rendu, sans le vrai jeu de données.

Le jeu EVTX-ATTACK-SAMPLES n'est pas dans le dépôt ; ces tests reconstituent sa
structure (un dossier par tactique) avec les journaux d'exemple de mini-SIEM.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import attack_coverage as cov  # noqa: E402
from minisiem.evtx import write_evtx  # noqa: E402
from minisiem.rules import load_rules  # noqa: E402

RULES = load_rules(str(ROOT / "rules"))
SAMPLES = ROOT / "samples"

_CLEARED = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            '<Provider Name="Microsoft-Windows-Eventlog"/><EventID>1102</EventID>'
            '<TimeCreated SystemTime="2019-03-17T19:00:00.000000Z"/><EventRecordID>1</EventRecordID>'
            '<Channel>Security</Channel><Computer>LAB-PC</Computer></System>'
            '<UserData><LogFileCleared><SubjectUserName>admin</SubjectUserName></LogFileCleared>'
            '</UserData></Event>')
_QUIET = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
          '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID>'
          '<TimeCreated SystemTime="2019-03-17T19:00:05.000000Z"/><EventRecordID>2</EventRecordID>'
          '<Channel>Security</Channel><Computer>LAB-PC</Computer></System><EventData>'
          '<Data Name="TargetUserName">alice</Data><Data Name="LogonType">2</Data></EventData></Event>')
_UNREAD = _QUIET.replace("<EventID>4624</EventID>", "<EventID>5145</EventID>")


@pytest.fixture()
def dataset(tmp_path):
    def put(rel, data):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    put("Credential Access/lsass.evtx", (SAMPLES / "sysmon_events.evtx").read_bytes())
    put("Discovery/lsass_aussi.evtx", (SAMPLES / "sysmon_events.evtx").read_bytes())
    put("Lateral Movement/capture.evtx", write_evtx([_CLEARED, _QUIET]))
    put("Defense Evasion/DE_1102_security_log_cleared.evtx", write_evtx([_CLEARED, _QUIET]))
    put("Persistence/inconnu.evtx", write_evtx([_UNREAD]))
    put("Other/abime.evtx", b"pas un journal")
    put("racine.evtx", write_evtx([_QUIET]))
    return tmp_path


def _by_path(results):
    return {r.path: r for r in results}


def test_verdicts(dataset):
    r = _by_path(cov.measure(dataset, RULES))
    assert r["Credential Access/lsass.evtx"].verdict == cov.DETECTED
    assert "SYSMON_LSASS_ACCESS" in r["Credential Access/lsass.evtx"].rules
    # mêmes alertes, mais aucune de la tactique Discovery : signalée, pas détectée
    assert r["Discovery/lsass_aussi.evtx"].verdict == cov.FLAGGED
    assert r["Persistence/inconnu.evtx"].verdict == cov.OUT
    assert r["Persistence/inconnu.evtx"].sources == {("Security", 5145)}
    assert r["racine.evtx"].folder == cov.NO_TACTIC and r["racine.evtx"].verdict == cov.MISSED
    assert r["Other/abime.evtx"].error and r["Other/abime.evtx"].verdict == cov.OUT


def test_capture_artifact_is_removed_unless_it_is_the_attack(dataset):
    r = _by_path(cov.measure(dataset, RULES))
    capture = r["Lateral Movement/capture.evtx"]
    assert capture.artifact_removed and capture.verdict == cov.MISSED and not capture.rules
    cleared = r["Defense Evasion/DE_1102_security_log_cleared.evtx"]
    assert not cleared.artifact_removed
    assert cleared.rules == ["WIN_LOG_CLEARED"] and cleared.verdict == cov.DETECTED  # Defense Impairment


def test_markdown_and_readme_block(dataset, tmp_path_factory):
    results = cov.measure(dataset, RULES)
    md = cov.render_markdown(results, len(RULES))
    s = cov.summary(results)
    assert s["total"] == 7 and s[cov.DETECTED] == 2 and s[cov.FLAGGED] == 1
    assert "| **Total** | **7** | **2** | **1** |" in md
    assert "`SYSMON_LSASS_ACCESS` | 2 | 1 |" in md
    assert cov.SAMPLES_COMMIT in md
    assert md == cov.render_markdown(cov.measure(dataset, RULES), len(RULES))   # déterministe
    readme = tmp_path_factory.mktemp("r") / "README.md"
    readme.write_text(f"avant\n{cov.README_START}\nvieux\n{cov.README_END}\naprès\n", encoding="utf-8")
    cov.update_readme(readme, cov.render_readme_block(results))
    text = readme.read_text(encoding="utf-8")
    assert text.startswith("avant\n") and text.endswith("après\n") and "vieux" not in text
    assert "**3 sur 5" in text


def test_readme_and_coverage_files_are_consistent():
    """Les chiffres du README sont ceux de COVERAGE.md (les deux viennent du même calcul)."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    coverage = (ROOT / "COVERAGE.md").read_text(encoding="utf-8")
    assert cov.README_START in readme and cov.README_END in readme
    block = readme.split(cov.README_START)[1].split(cov.README_END)[0]
    total = coverage.split("| **Total** | **")[1].split("**")[0]
    assert f"\n| {total} |" in block
    assert f"Règles évaluées : {len(RULES)}." in coverage, "COVERAGE.md à régénérer : le nombre de règles a changé"
