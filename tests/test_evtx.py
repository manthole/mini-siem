"""Lecture directe des fichiers .evtx (format binaire natif de Windows).

Le lecteur a aussi été vérifié, hors de ce dépôt, sur de vrais journaux Windows : les
fichiers de test de python-evtx et des enregistrements d'attaques publics
(EVTX-ATTACK-SAMPLES), soit plus de 6 600 enregistrements, tous rendus en XML valide et
identiques entre les versions Python et JavaScript. Ici, on teste sur des .evtx produits
par l'écrivain du module, au format que Windows utilise (modèles partagés, XML binaire
imbriqué pour EventData comme Sysmon, sommes de contrôle CRC32).
"""
import re
import struct
import sys
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from minisiem import evtx  # noqa: E402
from minisiem.evtx import EvtxError, read_evtx, write_evtx  # noqa: E402
from minisiem.parsers import parse_evtx_xml, parse_file  # noqa: E402
from minisiem.rules import load_rules, run_rules  # noqa: E402

RULES = load_rules(str(ROOT / "rules"))
SAMPLES = ROOT / "samples"


def _blocks(name):
    return re.findall(r"<Event\b.*?</Event>", (SAMPLES / name).read_text(encoding="utf-8"), re.S)


def _key(e):
    return (e.timestamp, e.source, e.event_id, e.event_type, e.user, e.source_ip, e.dest_ip,
            e.dest_port, e.process, e.parent_process, e.command_line, e.target,
            e.granted_access, e.detail, e.host)


@pytest.mark.parametrize("name", ["windows_events", "sysmon_events"])
def test_evtx_sample_gives_same_events_as_xml(name):
    from_xml = [_key(e) for e in parse_file(str(SAMPLES / f"{name}.xml"))]
    from_evtx = [_key(e) for e in parse_file(str(SAMPLES / f"{name}.evtx"))]
    assert from_xml and from_evtx == from_xml


def test_evtx_sample_is_up_to_date():
    # l'échantillon binaire est bien celui que produit l'écrivain à partir du XML
    assert (SAMPLES / "sysmon_events.evtx").read_bytes() == write_evtx(_blocks("sysmon_events.xml"))


def _check_crcs(data):
    assert data[:8] == b"ElfFile\x00"
    assert zlib.crc32(data[:0x78]) == struct.unpack_from("<I", data, 0x7C)[0]
    chunks = struct.unpack_from("<H", data, 0x2A)[0]
    assert len(data) == 0x1000 + chunks * 0x10000
    for i in range(chunks):
        c = data[0x1000 + i * 0x10000:0x1000 + (i + 1) * 0x10000]
        free = struct.unpack_from("<I", c, 0x30)[0]
        assert c[:8] == b"ElfChnk\x00"
        assert zlib.crc32(c[0x200:free]) == struct.unpack_from("<I", c, 0x34)[0]
        assert zlib.crc32(c[:0x78] + c[0x80:0x200]) == struct.unpack_from("<I", c, 0x7C)[0]
    return chunks


def test_written_files_have_valid_checksums():
    for name in ("windows_events.evtx", "sysmon_events.evtx"):
        assert _check_crcs((SAMPLES / name).read_bytes()) == 1


def test_many_events_span_several_chunks():
    blocks = _blocks("sysmon_events.xml")
    many = []
    for i in range(12):          # 480 événements : plusieurs blocs de 64 Ko
        for b in blocks:
            many.append(re.sub(r"<EventRecordID>(\d+)</EventRecordID>",
                               lambda m: f"<EventRecordID>{int(m.group(1)) + 1000 * i}</EventRecordID>", b))
    data = write_evtx(many)
    assert _check_crcs(data) > 1
    events = [parse_evtx_xml(x) for x in read_evtx(data)]
    assert len(events) == len(many) and all(events)


def test_damaged_record_is_skipped_not_fatal():
    data = bytearray((SAMPLES / "sysmon_events.evtx").read_bytes())
    first = bytes(data)
    total = len(list(read_evtx(first)))
    # on abîme le XML binaire du deuxième enregistrement (jeton invalide)
    chunk = 0x1000
    size1 = struct.unpack_from("<I", data, chunk + 0x200 + 4)[0]
    second = chunk + 0x200 + size1
    data[second + 24] = 0xEE
    assert len(list(read_evtx(bytes(data)))) == total - 1


def test_not_an_evtx_file():
    with pytest.raises(EvtxError):
        list(read_evtx(b"Nov  8 10:00:01 web01 sshd[1]: ..."))


def test_value_types_render_like_windows():
    s = evtx._scalar
    sid = bytes([1, 5, 0, 0, 0, 0, 0, 5]) + struct.pack("<5I", 21, 1, 2, 3, 1104)
    assert s(evtx.T_SID, sid) == "S-1-5-21-1-2-3-1104"
    guid = struct.pack("<IHH", 0x5770385F, 0xC22A, 0x43E0) + bytes.fromhex("BF4C06F5698FFBD9")
    assert s(evtx.T_GUID, guid) == "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
    assert s(evtx.T_HEX32, struct.pack("<I", 0x1010)) == "0x1010"
    assert s(evtx.T_HEX64, struct.pack("<Q", 0x19D3AF)) == "0x000000000019d3af"
    ticks = (13_412_000_000 * 10_000_000) + 1234567
    assert s(evtx.T_FILETIME, struct.pack("<Q", ticks)).endswith(".1234567Z")
    assert s(evtx.T_BOOL, struct.pack("<I", 1)) == "true"
    assert s(evtx.T_SYSTIME, struct.pack("<8H", 2026, 11, 0, 8, 14, 5, 31, 123)) == "2026-11-08T14:05:31.123Z"


def test_granted_access_is_normalized():
    # python-evtx écrit 0x00001410, Windows 0x1410 : la règle LSASS doit voir la même chose
    xml = ('<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>10</EventID>'
           '<TimeCreated SystemTime="2026-11-08T14:09:12Z"/><Computer>PC01</Computer></System>'
           '<EventData><Data Name="SourceImage">C:\\x.exe</Data>'
           '<Data Name="TargetImage">C:\\Windows\\system32\\lsass.exe</Data>'
           '<Data Name="GrantedAccess">0x00001010</Data></EventData></Event>')
    ev = parse_evtx_xml(xml)
    assert ev.granted_access == "0x1010"
    assert "SYSMON_LSASS_ACCESS" in {a.rule_id for a in run_rules(RULES, [ev])}


def test_evtx_sample_triggers_the_infection_chain():
    events = list(parse_file(str(SAMPLES / "sysmon_events.evtx")))
    alerts = run_rules(RULES, events)
    assert [a.count for a in alerts if a.rule_id == "SYSMON_INFECTION_CHAIN"] == [6]
