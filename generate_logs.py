#!/usr/bin/env python3
"""Générateur de logs SYNTHÉTIQUES pour tester le mini-SIEM.

Ce script n'attaque rien : il écrit de fausses lignes de log dans des fichiers,
afin de fournir un jeu de données reproductible. Il produit trois sources :
  - auth.log   (SSH / sudo)      : brute force, brute force réussi, escalade sudo
  - access.log (Apache combined) : scan web + injection SQL
  - ufw.log    (pare-feu)        : scan de ports
Chaque scénario est conçu pour déclencher une règle, plus du trafic normal.

Usage :
    python generate_logs.py --outdir samples
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
