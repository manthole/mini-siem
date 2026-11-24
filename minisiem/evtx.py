"""Lecture directe des journaux Windows .evtx, sans aucune dépendance.

Un fichier .evtx est binaire : un en-tête de 4 Ko, puis des blocs (« chunks ») de
64 Ko qui contiennent les enregistrements. Chaque événement y est stocké en « XML
binaire » (BinXML) : des jetons (ouverture d'élément, attribut, valeur…) et, pour
gagner de la place, des modèles (templates) partagés par les événements de même forme,
complétés par une liste de valeurs typées (entiers, dates FILETIME, SID, GUID…).

Ce module relit ce format et rend chaque événement en XML texte, sous la même forme
que `Get-WinEvent … | ForEach-Object { $_.ToXml() }`. Le reste du mini-SIEM (parser
XML, règles, Sysmon) n'a donc rien à changer.

Il sait aussi écrire des .evtx (`write_evtx`), pour produire des jeux d'exemple et des
tests sans redistribuer de journaux tiers. Les sommes de contrôle CRC32 de l'en-tête,
des blocs et des enregistrements sont calculées comme le fait Windows.

Référence du format : documentation de libevtx (Joachim Metz), « Windows XML Event
Log (EVTX) format ».
"""
from __future__ import annotations

import hashlib
import re
import struct
import zlib
from datetime import datetime, timedelta, timezone
from typing import Iterator
from xml.etree import ElementTree as ET

FILE_MAGIC = b"ElfFile\x00"
CHUNK_MAGIC = b"ElfChnk\x00"
RECORD_MAGIC = 0x00002A2A
HEADER_BLOCK = 0x1000
CHUNK_SIZE = 0x10000
CHUNK_HEADER = 0x200

# Types de valeurs des substitutions
T_NULL, T_WSTRING, T_STRING = 0x00, 0x01, 0x02
T_INT8, T_UINT8, T_INT16, T_UINT16 = 0x03, 0x04, 0x05, 0x06
T_INT32, T_UINT32, T_INT64, T_UINT64 = 0x07, 0x08, 0x09, 0x0A
T_REAL32, T_REAL64, T_BOOL, T_BINARY = 0x0B, 0x0C, 0x0D, 0x0E
T_GUID, T_SIZET, T_FILETIME, T_SYSTIME = 0x0F, 0x10, 0x11, 0x12
T_SID, T_HEX32, T_HEX64, T_BINXML = 0x13, 0x14, 0x15, 0x21

_INTS = {T_INT8: "<b", T_UINT8: "<B", T_INT16: "<h", T_UINT16: "<H",
         T_INT32: "<i", T_UINT32: "<I", T_INT64: "<q", T_UINT64: "<Q"}
_FIXED = {T_INT8: 1, T_UINT8: 1, T_INT16: 2, T_UINT16: 2, T_INT32: 4, T_UINT32: 4,
          T_INT64: 8, T_UINT64: 8, T_REAL32: 4, T_REAL64: 8, T_BOOL: 4, T_GUID: 16,
          T_FILETIME: 8, T_SYSTIME: 16, T_HEX32: 4, T_HEX64: 8}

_EPOCH = datetime(1601, 1, 1)
# caractères interdits en XML 1.0 (un journal corrompu ne doit pas casser l'analyse)
_BAD_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")


class EvtxError(ValueError):
    """Fichier ou enregistrement .evtx illisible."""


def is_evtx(head: bytes) -> bool:
    return head[:8] == FILE_MAGIC


def _xml_text(s: str) -> str:
    return _BAD_XML.sub("", s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _xml_attr(s: str) -> str:
    return _xml_text(s).replace('"', "&quot;")


def filetime(ticks: int) -> str:
    """FILETIME (centaines de ns depuis 1601) -> « 2026-11-08T14:05:31.1234567Z »."""
    dt = _EPOCH + timedelta(seconds=ticks // 10_000_000)
    return f"{dt:%Y-%m-%dT%H:%M:%S}.{ticks % 10_000_000:07d}Z"


# ===========================================================================
# Lecture
# ===========================================================================

class _Chunk:
    """Un bloc de 64 Ko. Les noms et les modèles y sont désignés par leur position dans
    le bloc ; ils sont mis en cache à la première lecture."""

    def __init__(self, buf: bytes):
        self.b = buf
        self.names: dict[int, tuple[str, int]] = {}
        self.templates: dict[int, list] = {}

    # --- primitives
    def u16(self, p: int) -> int:
        return struct.unpack_from("<H", self.b, p)[0]

    def u32(self, p: int) -> int:
        return struct.unpack_from("<I", self.b, p)[0]

    def utf16(self, p: int, n_chars: int) -> str:
        return self.b[p:p + 2 * n_chars].decode("utf-16-le", "replace")

    def name(self, off: int, pos: int) -> tuple[str, int]:
        """Nom d'élément ou d'attribut. S'il est défini ici (off == pos), on le saute."""
        if off not in self.names:
            n = self.u16(off + 6)
            self.names[off] = (self.utf16(off + 8, n), 8 + 2 * n + 2)
        text, length = self.names[off]
        return text, (pos + length if off == pos else pos)

    # --- enregistrements
    def records(self) -> Iterator[str]:
        free = min(self.u32(0x30) or len(self.b), len(self.b))
        pos = CHUNK_HEADER
        while pos + 28 <= free:
            magic, size = struct.unpack_from("<II", self.b, pos)
            if magic != RECORD_MAGIC or size < 28 or pos + size > len(self.b):
                break
            try:
                yield self.render_fragment(pos + 24)
            except (EvtxError, struct.error, IndexError, RecursionError):
                pass  # enregistrement abîmé : on passe au suivant
            pos += size

    def render_fragment(self, pos: int) -> str:
        nodes, _ = self.fragment(pos)
        out: list[str] = []
        self.render(nodes, [], out)
        return "".join(out)

    # --- analyse du XML binaire
    def fragment(self, pos: int) -> tuple[list, int]:
        nodes: list = []
        while True:
            tok = self.b[pos]
            if tok == 0x00:                          # fin du flux
                return nodes, pos + 1
            if tok == 0x0F:                          # en-tête de fragment
                pos += 4
            elif tok == 0x0C:                        # instance de modèle : fin du fragment
                node, pos = self.template_instance(pos)
                nodes.append(node)
                return nodes, pos
            elif tok & 0x0F == 0x01:
                node, pos = self.element(pos)
                nodes.append(node)
            else:
                raise EvtxError(f"jeton inattendu {tok:#04x} à {pos:#x}")

    def element(self, pos: int) -> tuple[tuple, int]:
        has_attrs = self.b[pos] & 0x40
        pos += 3                                     # jeton + identifiant de dépendance
        pos += 4                                     # taille des données (non nécessaire)
        name, pos = self.name(self.u32(pos), pos + 4)
        attrs = []
        if has_attrs:
            end = pos + 4 + self.u32(pos)
            pos += 4
            while pos < end:
                tok = self.b[pos]
                if tok & 0x0F != 0x06:
                    raise EvtxError(f"attribut attendu à {pos:#x}")
                aname, pos = self.name(self.u32(pos + 1), pos + 5)
                content, pos = self.content(pos)
                attrs.append((aname, content))
                if not tok & 0x40:                   # dernier attribut
                    break
        tok = self.b[pos]
        if tok == 0x03:                              # élément vide
            return ("elem", name, attrs, None), pos + 1
        if tok != 0x02:
            raise EvtxError(f"fin de balise attendue à {pos:#x}")
        pos += 1
        children: list = []
        while True:
            tok = self.b[pos]
            if tok == 0x04:                          # balise fermante
                return ("elem", name, attrs, children), pos + 1
            if tok & 0x0F == 0x01:
                node, pos = self.element(pos)
                children.append(node)
            else:
                nodes, pos = self.content(pos, single=True)
                children.extend(nodes)

    def content(self, pos: int, single: bool = False) -> tuple[list, int]:
        """Valeurs textuelles : texte, substitution, référence de caractère ou d'entité."""
        out: list = []
        while True:
            tok = self.b[pos]
            base = tok & 0x0F
            if base == 0x05:                         # texte
                if self.b[pos + 1] != T_WSTRING:
                    raise EvtxError("valeur non textuelle")
                n = self.u16(pos + 2)
                out.append(("text", self.utf16(pos + 4, n)))
                pos += 4 + 2 * n
            elif tok in (0x0D, 0x0E):                # substitution (normale / optionnelle)
                out.append(("subst", self.u16(pos + 1), tok == 0x0E))
                pos += 4
            elif base == 0x08:                       # &#N;
                out.append(("raw", f"&#{self.u16(pos + 1)};"))
                pos += 3
            elif base == 0x09:                       # &nom;
                ename, pos = self.name(self.u32(pos + 1), pos + 5)
                out.append(("raw", f"&{ename};"))
            elif base == 0x07:                       # CDATA
                n = self.u16(pos + 1)
                out.append(("text", self.utf16(pos + 3, n)))
                pos += 3 + 2 * n
            elif tok == 0x0A:                        # instruction de traitement
                target, pos = self.name(self.u32(pos + 1), pos + 5)
                data = ""
                if self.b[pos] == 0x0B:
                    n = self.u16(pos + 1)
                    data = self.utf16(pos + 3, n)
                    pos += 3 + 2 * n
                out.append(("raw", f"<?{target} {data}?>"))
            else:
                if not out:
                    raise EvtxError(f"valeur attendue à {pos:#x} (jeton {tok:#04x})")
                return out, pos
            if single:
                return out, pos

    def template_instance(self, pos: int) -> tuple[tuple, int]:
        def_off = self.u32(pos + 6)
        pos += 10
        if def_off not in self.templates:
            self.templates[def_off], _ = self.fragment(def_off + 24)
        if def_off == pos:                           # modèle défini ici : on le saute
            pos = def_off + 24 + self.u32(def_off + 20)
        count = self.u32(pos)
        pos += 4
        descs = [struct.unpack_from("<HB", self.b, pos + 4 * i) for i in range(count)]
        pos += 4 * count
        values = []
        for size, vtype in descs:
            values.append((vtype, pos, size))
            pos += size
        return ("tmpl", self.templates[def_off], values), pos

    # --- rendu en XML texte
    def render(self, nodes: list, values: list, out: list[str]) -> None:
        for node in nodes:
            kind = node[0]
            if kind == "tmpl":
                self.render(node[1], node[2], out)
            elif kind == "elem":
                _, name, attrs, children = node
                out.append("<" + name)
                for aname, content in attrs:
                    text = self.text_of(content, values)
                    if text is not None:
                        out.append(f' {aname}="{_xml_attr(text)}"')
                if children is None:
                    out.append("/>")
                    continue
                out.append(">")
                for child in children:
                    if child[0] in ("elem", "tmpl"):
                        self.render([child], values, out)
                    elif child[0] == "subst":
                        out.append(self.value_xml(values, child[1]))
                    elif child[0] == "raw":
                        out.append(child[1])
                    else:
                        out.append(_xml_text(child[1]))
                out.append(f"</{name}>")

    def text_of(self, content: list, values: list) -> str | None:
        """Texte d'un attribut. None si sa seule valeur est une substitution optionnelle
        vide : Windows omet alors l'attribut."""
        parts = []
        for c in content:
            if c[0] == "subst":
                v = self.value(values, c[1])
                if v is None and c[2] and len(content) == 1:
                    return None
                parts.append(v or "")
            elif c[0] == "raw":
                parts.append(c[1])
            else:
                parts.append(c[1])
        return "".join(parts)

    def value_xml(self, values: list, index: int) -> str:
        if index >= len(values):
            return ""
        vtype, pos, size = values[index]
        if vtype == T_BINXML:                        # XML binaire imbriqué (EventData Sysmon)
            return self.render_fragment(pos) if size else ""
        return _xml_text(self.value(values, index) or "")

    def value(self, values: list, index: int) -> str | None:
        if index >= len(values):
            return None
        vtype, pos, size = values[index]
        if vtype == T_NULL or size == 0:
            return None
        raw = self.b[pos:pos + size]
        if vtype & 0x80:                             # tableau de valeurs
            return ", ".join(_scalar(vtype & 0x7F, part) for part in _split_array(vtype & 0x7F, raw))
        return _scalar(vtype, raw)


def _split_array(vtype: int, raw: bytes) -> list[bytes]:
    if vtype == T_WSTRING:
        return [s.encode("utf-16-le") for s in raw.decode("utf-16-le", "replace").split("\x00") if s]
    if vtype == T_STRING:
        return [s for s in raw.split(b"\x00") if s]
    width = _FIXED.get(vtype)
    if not width:
        return [raw]
    return [raw[i:i + width] for i in range(0, len(raw) - width + 1, width)]


def _scalar(vtype: int, raw: bytes) -> str:
    if vtype == T_WSTRING:
        return raw.decode("utf-16-le", "replace").rstrip("\x00")
    if vtype == T_STRING:
        return raw.decode("latin-1").rstrip("\x00")
    if vtype in _INTS:
        return str(struct.unpack(_INTS[vtype], raw[:struct.calcsize(_INTS[vtype])])[0])
    if vtype == T_HEX32:
        return f"0x{struct.unpack('<I', raw[:4])[0]:x}"
    if vtype == T_HEX64:
        return f"0x{struct.unpack('<Q', raw[:8])[0]:016x}"
    if vtype == T_SIZET:
        return f"0x{int.from_bytes(raw, 'little'):0{2 * len(raw)}x}"
    if vtype == T_BOOL:
        return "true" if struct.unpack("<I", raw[:4])[0] else "false"
    if vtype == T_REAL32:
        return repr(struct.unpack("<f", raw[:4])[0])
    if vtype == T_REAL64:
        return repr(struct.unpack("<d", raw[:8])[0])
    if vtype == T_FILETIME:
        return filetime(struct.unpack("<Q", raw[:8])[0])
    if vtype == T_SYSTIME:
        y, mo, _, d, h, mi, s, ms = struct.unpack("<8H", raw[:16])
        return f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}.{ms:03d}Z"
    if vtype == T_GUID:
        d1, d2, d3 = struct.unpack("<IHH", raw[:8])
        return f"{{{d1:08X}-{d2:04X}-{d3:04X}-{raw[8:10].hex().upper()}-{raw[10:16].hex().upper()}}}"
    if vtype == T_SID:
        rev, count = raw[0], raw[1]
        auth = int.from_bytes(raw[2:8], "big")
        subs = struct.unpack(f"<{count}I", raw[8:8 + 4 * count])
        return "S-" + "-".join(str(x) for x in (rev, auth, *subs))
    if vtype == T_BINARY:
        return raw.hex().upper()
    return ""


def read_evtx(data: bytes) -> Iterator[str]:
    """Rend chaque événement d'un fichier .evtx en XML texte."""
    if not is_evtx(data):
        raise EvtxError("ce n'est pas un fichier .evtx (signature ElfFile absente)")
    start = struct.unpack_from("<H", data, 0x28)[0] or HEADER_BLOCK
    for off in range(start, len(data) - CHUNK_HEADER + 1, CHUNK_SIZE):
        chunk = data[off:off + CHUNK_SIZE]
        if chunk[:8] == CHUNK_MAGIC:
            yield from _Chunk(chunk).records()


def read_evtx_file(path: str) -> Iterator[str]:
    with open(path, "rb") as fh:
        yield from read_evtx(fh.read())


# ===========================================================================
# Écriture (jeux d'exemple et tests)
# ===========================================================================

# Typage des valeurs, à la manière des manifestes Windows et Sysmon
_TYPED_DATA = {
    "GrantedAccess": T_HEX32, "Status": T_HEX32, "SubStatus": T_HEX32,
    "ProcessId": T_UINT32, "ParentProcessId": T_UINT32, "SourceProcessId": T_UINT32,
    "TargetProcessId": T_UINT32, "LogonType": T_UINT32,
    "SourcePort": T_UINT16, "DestinationPort": T_UINT16, "Initiated": T_BOOL,
}


def _name_hash(name: str) -> int:
    h = 0
    for ch in name:
        h = (h * 65599 + ord(ch)) & 0xFFFFFFFF
    return h & 0xFFFF


def _encode(vtype: int, text: str) -> tuple[int, bytes]:
    """Valeur texte -> (type, octets). Repli en chaîne si la conversion échoue."""
    try:
        if vtype == T_UINT16:
            return vtype, struct.pack("<H", int(text))
        if vtype == T_UINT32:
            return vtype, struct.pack("<I", int(text))
        if vtype == T_UINT64:
            return vtype, struct.pack("<Q", int(text))
        if vtype == T_HEX32:
            return vtype, struct.pack("<I", int(text, 16))
        if vtype == T_BOOL:
            return vtype, struct.pack("<I", {"true": 1, "false": 0}[text.lower()])
        if vtype == T_FILETIME:
            m = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,7}))?Z?", text.strip())
            dt = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
            ticks = int((dt - _EPOCH).total_seconds()) * 10_000_000
            ticks += int((m.group(2) or "0").ljust(7, "0"))
            return vtype, struct.pack("<Q", ticks)
        if vtype == T_GUID:
            g = text.strip("{}").replace("-", "")
            raw = bytes.fromhex(g)
            return vtype, struct.pack("<IHH", int(g[:8], 16), int(g[8:12], 16), int(g[12:16], 16)) + raw[8:]
    except (ValueError, KeyError, AttributeError, struct.error):
        pass
    return T_WSTRING, text.encode("utf-16-le")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class _ChunkWriter:
    def __init__(self, first_number: int):
        self.b = bytearray(CHUNK_SIZE)
        self.pos = CHUNK_HEADER
        self.names: dict[str, int] = {}
        self.templates: dict[bytes, int] = {}
        self.first_number = first_number
        self.records: list[tuple[int, int]] = []     # (identifiant, position)

    def put(self, data: bytes) -> int:
        p = self.pos
        if p + len(data) > CHUNK_SIZE:
            raise OverflowError
        self.b[p:p + len(data)] = data
        self.pos += len(data)
        return p

    def put_u32_at(self, p: int, v: int) -> None:
        struct.pack_into("<I", self.b, p, v)

    def name_ref(self, name: str) -> None:
        """Décalage du nom ; à sa première apparition dans le bloc, le nom suit en ligne."""
        if name in self.names:
            self.put(struct.pack("<I", self.names[name]))
            return
        here = self.pos + 4
        self.put(struct.pack("<I", here))
        h = _name_hash(name)
        bucket = 0x80 + 4 * (h % 64)
        prev = struct.unpack_from("<I", self.b, bucket)[0]
        self.put(struct.pack("<IHH", prev, h, len(name)) + name.encode("utf-16-le") + b"\x00\x00")
        struct.pack_into("<I", self.b, bucket, here)
        self.names[name] = here

    # --- modèle : l'arbre XML où chaque valeur variable devient une substitution
    def element(self, el: ET.Element, subs: list) -> None:
        tag = _local(el.tag)
        attrs = []
        for k, v in el.attrib.items():
            if k == "Name" and tag == "Data":
                attrs.append((k, ("text", v)))       # nom du champ : fixe, dans le modèle
            else:
                attrs.append((k, ("subst", len(subs))))
                subs.append(_encode(T_FILETIME if k == "SystemTime" else
                                    T_GUID if k == "Guid" else T_WSTRING, v))
        if tag == "Event" and el.get("xmlns") is None:
            attrs.insert(0, ("xmlns", ("text", "http://schemas.microsoft.com/win/2004/08/events/event")))
        self.put(bytes([0x41 if attrs else 0x01]) + b"\xff\xff")
        size_at = self.put(b"\0\0\0\0")
        self.name_ref(tag)
        if attrs:
            list_at = self.put(b"\0\0\0\0")
            for i, (k, (kind, v)) in enumerate(attrs):
                self.put(bytes([0x46 if i < len(attrs) - 1 else 0x06]))
                self.name_ref(k)
                if kind == "text":
                    self.put(b"\x05\x01" + struct.pack("<H", len(v)) + v.encode("utf-16-le"))
                else:
                    self.put(bytes([0x0E]) + struct.pack("<H", v) + bytes([subs[v][0]]))
            self.put_u32_at(list_at, self.pos - list_at - 4)
        children = list(el)
        text = (el.text or "").strip()
        if not children and not text and tag not in ("Data", "EventID", "EventRecordID",
                                                      "Channel", "Computer"):
            self.put(b"\x03")
        else:
            self.put(b"\x02")
            if children:
                for c in children:
                    if _local(c.tag) == "EventData" and tag == "Event":
                        # comme Sysmon : les données de l'événement forment un XML binaire
                        # imbriqué, avec son propre modèle
                        self.put(bytes([0x0E]) + struct.pack("<H", len(subs)) + bytes([T_BINXML]))
                        subs.append(("binxml", c))
                    else:
                        self.element(c, subs)
            else:
                vtype = T_UINT16 if tag == "EventID" else T_UINT64 if tag == "EventRecordID" else \
                    _TYPED_DATA.get(el.get("Name", ""), T_WSTRING)
                self.put(bytes([0x0E]) + struct.pack("<H", len(subs)) + bytes([_encode(vtype, text)[0]]))
                subs.append(_encode(vtype, text))
            self.put(b"\x04")
        self.put_u32_at(size_at, self.pos - size_at - 4)

    def fragment(self, el: ET.Element) -> None:
        """Fragment complet : en-tête + instance de modèle (défini au premier usage) + valeurs."""
        self.put(b"\x0f\x01\x01\x00")
        shape = _shape(el)
        guid = hashlib.blake2s(shape, digest_size=16).digest()
        tid = struct.unpack("<I", guid[:4])[0]
        subs: list = []
        self.put(b"\x0c\x01" + struct.pack("<I", tid))
        if shape in self.templates:
            self.put(struct.pack("<I", self.templates[shape]))
            # on recalcule les valeurs sans réécrire le modèle
            scratch = _ChunkWriter(0)
            scratch.names = dict(self.names)
            scratch.element(el, subs)
        else:
            def_at = self.pos + 4
            self.put(struct.pack("<I", def_at))
            bucket = 0x180 + 4 * (tid % 32)
            prev = struct.unpack_from("<I", self.b, bucket)[0]
            self.put(struct.pack("<I", prev) + guid + b"\0\0\0\0")
            body = self.pos
            self.put(b"\x0f\x01\x01\x00")
            self.element(el, subs)
            self.put(b"\x00")
            self.put_u32_at(def_at + 20, self.pos - body)
            struct.pack_into("<I", self.b, bucket, def_at)
            self.templates[shape] = def_at
        self.put(struct.pack("<I", len(subs)))
        desc_at = self.put(b"\0" * 4 * len(subs))
        for i, sub in enumerate(subs):
            vstart = self.pos
            if sub[0] == "binxml":
                self.fragment(sub[1])
                vtype = T_BINXML
            else:
                vtype, raw = sub
                self.put(raw)
            struct.pack_into("<HBB", self.b, desc_at + 4 * i, self.pos - vstart, vtype, 0)

    def record(self, record_id: int, written: int, el: ET.Element) -> None:
        snapshot = (self.pos, dict(self.names), dict(self.templates), bytes(self.b[0x80:0x200]))
        try:
            start = self.put(struct.pack("<IIQQ", RECORD_MAGIC, 0, record_id, written))
            self.fragment(el)
            self.put(b"\x00")
            self.put(b"\x00" * ((-(self.pos - start + 4)) % 8))
            size = self.pos - start + 4
            self.put(struct.pack("<I", size))
            self.put_u32_at(start + 4, size)
            self.records.append((record_id, start))
        except OverflowError:
            self.pos, self.names, self.templates, table = snapshot
            self.b[0x80:0x200] = table
            self.b[self.pos:] = bytes(CHUNK_SIZE - self.pos)
            raise

    def finish(self) -> bytes:
        first_id, last_id = self.records[0][0], self.records[-1][0]
        n = len(self.records)
        struct.pack_into("<8sQQQQIII", self.b, 0, CHUNK_MAGIC, self.first_number,
                         self.first_number + n - 1, first_id, last_id, 0x80,
                         self.records[-1][1], self.pos)
        struct.pack_into("<I", self.b, 0x34, zlib.crc32(self.b[CHUNK_HEADER:self.pos]))
        struct.pack_into("<I", self.b, 0x7C, zlib.crc32(bytes(self.b[:0x78]) + bytes(self.b[0x80:0x200])))
        return bytes(self.b)


def _shape(el: ET.Element) -> bytes:
    """Empreinte de la forme d'un événement : deux événements de même forme partagent un modèle."""
    def walk(e, parent):
        tag = _local(e.tag)
        if tag == "EventData" and parent == "Event":
            return "EventData*"                      # valeur imbriquée : modèle à part
        attrs = sorted(k + ("=" + v if (k == "Name" and tag == "Data") else "") for k, v in e.attrib.items())
        kids = ",".join(walk(c, tag) for c in e)
        return f"{tag}[{'|'.join(attrs)}]({kids})"
    return walk(el, "").encode()


def write_evtx(xml_events: list[str]) -> bytes:
    """Écrit un fichier .evtx à partir d'événements XML (un bloc <Event> chacun)."""
    chunks: list[bytes] = []
    cw = _ChunkWriter(1)
    number = 1
    last_id = 0
    for xml in xml_events:
        el = ET.fromstring(xml)
        rid_el = next((e for e in el.iter() if _local(e.tag) == "EventRecordID"), None)
        rid = int(rid_el.text) if rid_el is not None and (rid_el.text or "").isdigit() else number
        tc = next((e for e in el.iter() if _local(e.tag) == "TimeCreated"), None)
        written = 0
        if tc is not None:
            vtype, raw = _encode(T_FILETIME, tc.get("SystemTime", ""))
            if vtype == T_FILETIME:
                written = struct.unpack("<Q", raw)[0]
        try:
            cw.record(rid, written, el)
        except OverflowError:
            chunks.append(cw.finish())
            cw = _ChunkWriter(number)
            cw.record(rid, written, el)
        number += 1
        last_id = rid
    if cw.records:
        chunks.append(cw.finish())
    header = bytearray(HEADER_BLOCK)
    struct.pack_into("<8sQQQIHHHH", header, 0, FILE_MAGIC, 0, max(len(chunks) - 1, 0),
                     last_id + 1, 0x80, 1, 3, HEADER_BLOCK, len(chunks))
    struct.pack_into("<I", header, 0x7C, zlib.crc32(bytes(header[:0x78])))
    return bytes(header) + b"".join(chunks)


__all__ = ["EvtxError", "is_evtx", "read_evtx", "read_evtx_file", "write_evtx", "filetime"]
