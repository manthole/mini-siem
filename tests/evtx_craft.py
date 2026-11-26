"""Fabrication de fichiers .evtx de test, jeton par jeton.

L'écrivain de minisiem/evtx.py ne produit que ce dont les échantillons ont besoin. Pour
fuzzer le lecteur, il faut aussi des fichiers qui empruntent tous les chemins du format :
références de caractère et d'entité (valides ou non), CDATA, instructions de traitement,
tableaux, SID, GUID, réels, chaînes Latin-1, fragments imbriqués, attributs optionnels
vides… et des fichiers hostiles (fragments qui se référencent en cascade).
"""
import struct

T_WSTRING, T_STRING, T_INT8, T_UINT16, T_INT64, T_REAL32, T_REAL64 = 0x01, 0x02, 0x03, 0x06, 0x09, 0x0B, 0x0C
T_BOOL, T_BINARY, T_GUID, T_SIZET, T_FILETIME, T_SYSTIME = 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12
T_SID, T_HEX32, T_HEX64, T_BINXML, T_UINT32 = 0x13, 0x14, 0x15, 0x21, 0x08


def _utf16(s):
    return s.encode("utf-16-le")


class Asm:
    """Assembleur de XML binaire. `base` : position absolue (dans le bloc) du premier octet."""

    def __init__(self, base):
        self.base = base
        self.b = bytearray()
        self.names = {}

    def pos(self):
        return self.base + len(self.b)

    def name(self, name):
        if name in self.names:
            self.b += struct.pack("<I", self.names[name])
            return
        here = self.pos() + 4
        self.b += struct.pack("<I", here) + struct.pack("<IHH", 0, 0, len(name)) + _utf16(name) + b"\0\0"
        self.names[name] = here

    def header(self):
        self.b += b"\x0f\x01\x01\x00"

    def open(self, name, attrs=()):
        """attrs : (nom, contenu) où contenu est une liste de jetons (voir content)."""
        self.b += bytes([0x41 if attrs else 0x01]) + b"\xff\xff" + b"\0\0\0\0"
        self.name(name)
        if attrs:
            at = len(self.b)
            self.b += b"\0\0\0\0"
            for i, (aname, content) in enumerate(attrs):
                self.b += bytes([0x46 if i < len(attrs) - 1 else 0x06])
                self.name(aname)
                self.content(content)
            struct.pack_into("<I", self.b, at, len(self.b) - at - 4)

    def close_start(self):
        self.b += b"\x02"

    def close_empty(self):
        self.b += b"\x03"

    def end(self):
        self.b += b"\x04"

    def eos(self):
        self.b += b"\x00"

    def content(self, tokens):
        for tok in tokens:
            kind = tok[0]
            if kind == "text":
                self.b += b"\x05\x01" + struct.pack("<H", len(tok[1])) + _utf16(tok[1])
            elif kind == "subst":                     # ("subst", index, type, optionnelle)
                self.b += bytes([0x0E if tok[3] else 0x0D]) + struct.pack("<H", tok[1]) + bytes([tok[2]])
            elif kind == "charref":
                self.b += b"\x08" + struct.pack("<H", tok[1])
            elif kind == "entity":
                self.b += b"\x09"
                self.name(tok[1])
            elif kind == "cdata":
                self.b += b"\x07" + struct.pack("<H", len(tok[1])) + _utf16(tok[1])
            elif kind == "pi":
                self.b += b"\x0a"
                self.name(tok[1])
                self.b += b"\x0b" + struct.pack("<H", len(tok[2])) + _utf16(tok[2])

    def leaf(self, name, tokens, attrs=()):
        self.open(name, attrs)
        self.close_start()
        self.content(tokens)
        self.end()


def _sid(rev, auth, subs):
    return bytes([rev, len(subs)]) + auth.to_bytes(6, "big") + struct.pack(f"<{len(subs)}I", *subs)


def rich_record(base):
    """Un enregistrement qui emprunte (presque) tous les chemins du lecteur."""
    a = Asm(base)
    a.header()
    inst = a.pos()
    tmpl_at = inst + 10
    body = Asm(tmpl_at + 24)
    body.names = a.names                              # même table de noms dans le bloc
    body.header()
    body.open("Event", [("xmlns", [("text", "http://schemas.microsoft.com/win/2004/08/events/event")])])
    body.close_start()
    body.open("System")
    body.close_start()
    body.open("Provider", [("Name", [("text", "Microsoft-Windows-Sysmon")]),
                           ("Guid", [("subst", 0, T_GUID, True)]),
                           ("Vide", [("subst", 15, 0x00, True)])])   # optionnel nul : omis
    body.close_empty()
    body.leaf("EventID", [("subst", 1, T_UINT16, False)])
    body.open("TimeCreated", [("SystemTime", [("subst", 2, T_FILETIME, False)])])
    body.close_empty()
    body.leaf("Channel", [("text", "Microsoft-Windows-Sysmon/Operational")])
    body.leaf("Computer", [("subst", 3, T_WSTRING, False)])
    body.end()
    body.open("EventData")
    body.close_start()
    fields = [("UserSid", 4, T_SID), ("UtcTime", 5, T_SYSTIME), ("Keywords", 6, T_HEX64),
              ("Delta", 7, T_INT8), ("Ratio", 8, T_REAL32), ("Big", 9, T_REAL64),
              ("Flag", 10, T_BOOL), ("Blob", 11, T_BINARY), ("Names", 12, 0x81),
              ("Ids", 13, 0x88), ("Ansi", 14, T_STRING), ("Size", 16, T_SIZET),
              ("Neg", 17, T_INT64), ("Access", 18, T_HEX32), ("Inner", 19, T_BINXML)]
    for name, idx, vtype in fields:
        body.leaf("Data", [("subst", idx, vtype, True)], attrs=[("Name", [("text", name)])])
    body.open("Misc")
    body.close_start()
    body.content([("charref", 65), ("charref", 0), ("charref", 0xD800), ("entity", "amp"),
                  ("entity", "bogus"), ("cdata", "x<y&z"), ("pi", "cible", "données ?>"),
                  ("text", "fin")])
    body.end()
    body.end()
    body.end()
    body.eos()
    a.b += b"\x0c\x01" + struct.pack("<II", 0x1234, tmpl_at)
    a.b += struct.pack("<I", 0) + bytes(range(16)) + struct.pack("<I", len(body.b)) + body.b
    values = [
        (T_GUID, struct.pack("<IHH", 0x5770385F, 0xC22A, 0x43E0) + bytes.fromhex("BF4C06F5698FFBD9")),
        (T_UINT16, struct.pack("<H", 10)),
        (T_FILETIME, struct.pack("<Q", 134_073_123_311_234_567)),
        (T_WSTRING, _utf16("PC01")),
        (T_SID, _sid(1, 5, [21, 1, 2, 3, 1104])),
        (T_SYSTIME, struct.pack("<8H", 2026, 11, 0, 8, 14, 5, 31, 123)),
        (T_HEX64, struct.pack("<Q", 0x8020000000000000)),
        (T_INT8, struct.pack("<b", -5)),
        (T_REAL32, struct.pack("<f", 0.1)),
        (T_REAL64, struct.pack("<d", 1.5e20)),
        (T_BOOL, struct.pack("<I", 1)),
        (T_BINARY, bytes([0, 1, 0xAB, 0xFF])),
        (0x81, _utf16("alpha\0beta\0")),
        (0x88, struct.pack("<3I", 1, 2, 3)),
        (T_STRING, bytes([0x41, 0x80, 0xE9, 0x00])),
        (0x00, b""),
        (T_SIZET, struct.pack("<Q", 0x1000)),
        (T_INT64, struct.pack("<q", -1)),
        (T_HEX32, struct.pack("<I", 0x00001010)),
    ]
    a.b += struct.pack("<I", len(values) + 1)
    desc_at = len(a.b)
    a.b += b"\0" * 4 * (len(values) + 1)
    for i, (vtype, raw) in enumerate(values):
        a.b += raw
        struct.pack_into("<HBB", a.b, desc_at + 4 * i, len(raw), vtype, 0)
    inner = Asm(a.pos())                               # XML binaire imbriqué, sans modèle
    inner.names = a.names
    inner.header()
    inner.leaf("Inner", [("text", "imbriqué & <ok>")], attrs=[("k", [("text", 'v"1')])])
    inner.eos()
    a.b += inner.b
    struct.pack_into("<HBB", a.b, desc_at + 4 * len(values), len(inner.b), T_BINXML, 0)
    a.eos()
    return bytes(a.b)


def hostile_record(base, n=60):
    """Fragments imbriqués en cascade : le fragment k rend k+1 et k+2 (suite de Fibonacci).
    Sans garde-fou, le temps de lecture et la mémoire explosent avec n."""
    a = Asm(base)
    a.header()
    tmpl_at = a.pos() + 10
    body = Asm(tmpl_at + 24)
    body.header()
    body.open("A")
    body.close_start()
    body.content([("subst", 0, T_BINXML, True), ("subst", 1, T_BINXML, True)])
    body.end()
    body.eos()
    a.b += b"\x0c\x01" + struct.pack("<II", 1, tmpl_at)
    a.b += struct.pack("<I", 0) + b"\x11" * 16 + struct.pack("<I", len(body.b)) + body.b
    pair = struct.pack("<I", 2) + struct.pack("<HBB", 26, T_BINXML, 0) * 2
    a.b += pair
    for _ in range(1, n):
        a.b += b"\x0f\x01\x01\x00\x0c\x01" + struct.pack("<II", 1, tmpl_at) + pair
    for _ in range(2):
        frag = b"\x0f\x01\x01\x00\x0c\x01" + struct.pack("<II", 1, tmpl_at) + struct.pack("<I", 0)
        a.b += frag + b"\0" * (26 - len(frag))
    a.eos()
    return bytes(a.b)


def evtx_file(builders):
    """Fichier .evtx d'un seul bloc, un enregistrement par fabrique (base -> octets)."""
    chunk = bytearray(0x10000)
    pos = 0x200
    last = pos
    for i, build in enumerate(builders, 1):
        binxml = build(pos + 24)
        size = 24 + len(binxml) + 4
        size += (-size) % 8
        rec = struct.pack("<IIQQ", 0x2A2A, size, i, 0) + binxml
        rec += b"\0" * (size - 4 - len(rec)) + struct.pack("<I", size)
        chunk[pos:pos + size] = rec
        last = pos
        pos += size
    n = len(builders)
    struct.pack_into("<8sQQQQIII", chunk, 0, b"ElfChnk\x00", 1, n, 1, n, 0x80, last, pos)
    header = bytearray(0x1000)
    struct.pack_into("<8sQQQIHHHH", header, 0, b"ElfFile\x00", 0, 0, n + 1, 0x80, 1, 3, 0x1000, 1)
    return bytes(header + chunk)
