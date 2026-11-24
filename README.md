# mini-SIEM

[![tests](https://github.com/manthole/mini-siem/actions/workflows/tests.yml/badge.svg)](https://github.com/manthole/mini-siem/actions/workflows/tests.yml)

Analyseur de logs défensif en ligne de commande. Il ingère des logs (SSH, web,
pare-feu, journal de sécurité Windows, Sysmon), applique
des règles de détection (format proche de [Sigma](https://github.com/SigmaHQ/sigma))
et produit un rapport HTML autonome avec les alertes, leurs preuves et la
technique [MITRE ATT&CK](https://attack.mitre.org/) associée.

C'est un projet d'apprentissage : une version miniature de ce que font Splunk,
Elastic ou Wazuh, pensée pour montrer la logique de détection SOC brique par
brique.

## Démo rapide

```bash
python generate_logs.py --outdir samples                 # jeu de données synthétique
python analyze.py samples/auth.log samples/access.log samples/ufw.log \
                  samples/windows_events.xml samples/sysmon_events.xml --out rapport.html
```

Ouvre ensuite `rapport.html` dans un navigateur : KPIs par sévérité, graphique,
carte des IP sources, matrice MITRE ATT&CK et tableau des alertes avec preuves.

```
[+] 273 événements analysés, 20 règles chargées.
[+] GeoIP : mode demo.
[+] CTI : flux « CTI démo », 7 indicateurs, 10 alerte(s) enrichie(s).
[+] 20 alerte(s) :
    - [CRITICAL] Brute force SSH réussi               ip=198.51.100.23  x9   T1110
    - [CRITICAL] Brute force Windows réussi           ip=198.51.100.23  x7   T1110
    - [CRITICAL] Accès mémoire suspect à LSASS        user=mmartin      x1   T1003.001
    - [CRITICAL] Contact avec une IP C2 connue        ip=203.0.113.200  x9   T1071
    - [HIGH    ] Brute force SSH                      ip=203.0.113.66   x10  T1110.001
    - [HIGH    ] Outil d'attaque web (user-agent)     ip=203.0.113.9    x31  T1595.002
    - [HIGH    ] Injection web (SQLi/XSS/traversée)   ip=203.0.113.9    x1   T1190
    - [HIGH    ] Brute force Windows (RDP/SMB)        ip=203.0.113.66   x10  T1110.001
    - [HIGH    ] Journal de sécurité effacé           user=administr.   x1   T1685.005
    - [HIGH    ] Ajout à un groupe privilégié         user=svc_backup   x1   T1098
    - [HIGH    ] Office lance un interpréteur         user=mmartin      x1   T1204.002
    - [HIGH    ] PowerShell avec commande encodée     user=mmartin      x1   T1059.001
    - [HIGH    ] Téléchargement par certutil          user=mmartin      x1   T1105
    - [HIGH    ] Connexion réseau de rundll32         user=mmartin      x5   T1218
    - [MEDIUM  ] Escalade de privilèges via sudo      user=www-data     x1   T1548.003
    - [MEDIUM  ] Scan web (énumération)               ip=203.0.113.9    x20  T1595.003
    - [MEDIUM  ] Scan de ports                        ip=198.51.100.77  x20  T1046
    - [MEDIUM  ] Connexion à une heure inhabituelle   user=jdupont      x1   T1078
    - [MEDIUM  ] Création de compte utilisateur       user=svc_backup   x1   T1136.001
    - [MEDIUM  ] Persistance par clé de registre Run  user=mmartin      x1   T1547.001
```

## Architecture

```
auth.log      ┐
access.log    │
ufw.log       ├▶ parsers.py ─▶ Event normalisé ─▶ rules.py ─▶ Alertes ─▶ geo.py + cti.py ─▶ report.py ─▶ rapport.html
windows.xml   │  (auto-détect)  (schéma type ECS)  (règles YAML)        (GeoIP, CTI)      (Chart.js+Leaflet+ATT&CK)
sysmon.xml    ┘
```

- `minisiem/events.py` — schéma d'événement et d'alerte normalisé (inspiré d'ECS).
- `minisiem/parsers.py` — ligne brute → `Event`. Sources : auth.log, Apache/Nginx, pare-feu UFW, journal de sécurité Windows et Sysmon (XML).
- `minisiem/rules.py` — moteur de détection (types `match`, `threshold`, `sequence`, `baseline_hour`, avec filtres d'exclusion).
- `minisiem/geo.py` — enrichissement GeoIP branchable (MaxMind, sinon table de démo).
- `minisiem/cti.py` — renseignement sur les menaces (flux d'indicateurs branchable).
- `minisiem/config.py` — listes blanches et règles désactivées.
- `minisiem/export.py` — exports JSON et Sigma (règles et corrélations).
- `minisiem/report.py` — rapport HTML (Jinja2 + Chart.js + carte Leaflet).
- `rules/*.yml` — une règle = un fichier, sans toucher au code.

## Détections

| Règle | Source | Logique | ATT&CK |
|---|---|---|---|
| `SSH_BRUTEFORCE` | auth | ≥ 10 échecs SSH depuis une IP en 5 min | T1110.001 |
| `SSH_BRUTEFORCE_SUCCESS` | auth | ≥ 5 échecs suivis d'un succès, même IP | T1110 |
| `SUDO_NOT_IN_SUDOERS` | auth | sudo refusé (« user NOT in sudoers ») | T1548.003 |
| `WEB_SCAN` | web | ≥ 20 erreurs 404 depuis une IP en 1 min | T1595.003 |
| `WEB_ATTACK_TOOL` | web | user-agent de scanner (sqlmap, nikto…) | T1595.002 |
| `WEB_INJECTION` | web | motif SQLi / XSS / traversée dans l'URL | T1190 |
| `WEB_LOG4SHELL` | web | motif JNDI (Log4Shell, CVE-2021-44228) | T1190 |
| `PORT_SCAN` | pare-feu | ≥ 20 ports distincts bloqués, même IP, 1 min | T1046 |
| `WIN_BRUTEFORCE` | Windows | ≥ 10 échecs de connexion (4625), même IP | T1110.001 |
| `WIN_BRUTEFORCE_SUCCESS` | Windows | ≥ 5 échecs (4625) puis un succès (4624) | T1110 |
| `WIN_LOG_CLEARED` | Windows | journal de sécurité effacé (1102) | T1685.005 |
| `WIN_GROUP_ADD` | Windows | ajout à un groupe privilégié (4732) | T1098 |
| `WIN_ACCOUNT_CREATED` | Windows | compte utilisateur créé (4720) | T1136.001 |
| `WIN_UNUSUAL_HOUR` | Windows | connexion hors des heures habituelles du compte | T1078 |
| `SYSMON_OFFICE_SHELL` | Sysmon | Word, Excel ou Outlook lance un shell ou PowerShell (1) | T1204.002 |
| `SYSMON_PS_ENCODED` | Sysmon | PowerShell avec commande encodée en Base64 (1) | T1059.001 |
| `SYSMON_LOLBIN_DOWNLOAD` | Sysmon | téléchargement par certutil ou bitsadmin (1) | T1105 |
| `SYSMON_LSASS_ACCESS` | Sysmon | accès mémoire à LSASS, antivirus écarté (10) | T1003.001 |
| `SYSMON_RUN_KEY` | Sysmon | écriture sous une clé de registre Run (13) | T1547.001 |
| `SYSMON_LOLBIN_NETWORK` | Sysmon | connexion réseau de rundll32, regsvr32 ou mshta (3) | T1218 |

Les techniques suivent ATT&CK v19 (avril 2026) : la tactique Defense Evasion y
est scindée en Stealth et Defense Impairment, et l'effacement des journaux
Windows est devenu T1685.005. Le validateur Sigma de l'intégration continue
signale toute référence devenue obsolète.

### Écrire une règle

Quatre types de règles, et des opérateurs sur les champs (`contains`,
`endswith`, `regex`, `in`, `gte`, `lte`) :

```yaml
id: WEB_ATTACK_TOOL
title: Outil d'attaque web détecté
type: match              # match | threshold | sequence | baseline_hour
level: high              # low | medium | high | critical
attack: T1595.002
selection:
  event_type: web_request
  user_agent:
    contains: [sqlmap, nikto, nmap]   # sous-chaîne, insensible à la casse
```

Un `threshold` peut compter des valeurs distinctes (`distinct: dest_port` pour
le scan de ports) plutôt que des événements bruts.

Un `filter` écarte les faux positifs connus, comme `selection and not filter`
en Sigma. Exemple de la règle LSASS, qui ignore l'antivirus :

```yaml
selection:
  event_type: process_access
  target:
    endswith: '\lsass.exe'
  granted_access:
    in: ['0x1010', '0x1410', '0x1fffff']
filter:
  process:
    endswith: ['\MsMpEng.exe', '\MsSense.exe']
```

## GeoIP

L'enrichissement est branchable. En production, installe la lib `geoip2`, pose
la base gratuite MaxMind GeoLite2 (`GeoLite2-City.mmdb`) et pointe-la :

```bash
export MINISIEM_GEOIP_DB=/chemin/GeoLite2-City.mmdb
```

Sans base, le mini-SIEM retombe sur une petite table de démo (`data/geo_demo.json`)
pour que la carte s'affiche quand même. Les IP privées ne sont jamais géolocalisées.

## Journaux Windows (EVTX)

Le mini-SIEM lit les événements Windows **au format XML**, celui que produisent
`wevtutil qe` ou `Get-WinEvent`. Un fichier `.evtx` binaire se convertit en ce
même XML en amont :

```bash
pip install python-evtx
evtx_dump Security.evtx > security.xml      # .evtx binaire -> XML
python analyze.py security.xml --out rapport.html
```

Event IDs reconnus : 4625 (échec), 4624 (succès), 4672 (privilèges spéciaux),
4720 (compte créé), 4732 (ajout à un groupe), 1102 (journal effacé).

### Baseline des heures de connexion

La règle `WIN_UNUSUAL_HOUR` (type `baseline_hour`) construit, pour chaque
utilisateur, l'ensemble de ses heures de connexion habituelles, puis signale
toute connexion à une heure où il ne se connecte jamais. C'est de la détection
comportementale : aucun seuil fixe, le « normal » est propre à chaque compte.

## Sysmon (poste de travail Windows)

[Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) est le
journal le plus utilisé en SOC Windows : il trace les créations de processus
avec leur ligne de commande, les connexions réseau, les accès à la mémoire des
processus, le registre… Le mini-SIEM lit le canal
`Microsoft-Windows-Sysmon/Operational` exporté en XML (même enveloppe que le
journal de sécurité, reconnue par son fournisseur) :

```powershell
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5000 |
  ForEach-Object { $_.ToXml() } | Out-File -Encoding utf8 sysmon.xml
```

| Event ID | Type normalisé | Champs utilisés |
|---|---|---|
| 1 | `process_creation` | `process`, `parent_process`, `command_line`, `user` |
| 3 | `network_connection` | `process`, `source_ip`, `dest_ip`, `dest_port` |
| 10 | `process_access` | `process` (source), `target`, `granted_access` |
| 11 | `file_event` | `process`, `target` (fichier créé) |
| 13 | `registry_set` | `process`, `target` (clé), `detail` (valeur) |
| 22 | `dns_query` | `process`, `target` (nom demandé), `detail` (réponse) |

Les types reprennent les catégories de journaux Sigma, et les champs suivent sa
taxonomie (`Image`, `CommandLine`, `TargetImage`…) à l'export. Le compte est
ramené à son nom court (`CORP\mmartin` → `mmartin`) pour pivoter avec les
autres sources.

Le jeu d'exemple `samples/sysmon_events.xml` raconte une journée sur le poste
`PC-COMPTA01` : une matinée normale (navigateur, messagerie, impression, script
d'inventaire, antivirus), qui ne doit déclencher **aucune** alerte, puis une
chaîne d'infection : pièce jointe `.docm` → macro qui lance PowerShell encodé →
téléchargement par certutil → `rundll32` qui contacte son C2 toutes les minutes
→ clé Run → lecture de la mémoire de LSASS. L'IP du C2 est la même que celle
qui tentait des connexions SSH dans `auth.log` : la CTI relie les deux sources.
La charge PowerShell est factice : décodée, elle ne fait que décrire l'étape
suivante, vers une IP de documentation.

## Matrice MITRE ATT&CK

Le rapport affiche une matrice des tactiques ATT&CK couvertes par les détections,
avec les techniques repérées et leur nombre d'alertes. Chaque règle porte son
champ `tactic`, ce qui alimente la matrice automatiquement.

## Renseignement sur les menaces (CTI)

Le mini-SIEM enrichit les alertes avec un flux d'indicateurs (threat intel) :

- **Enrichissement** — une alerte dont l'IP source est déjà connue d'un flux
  reçoit le contexte (flux, catégorie, score de confiance) et, pour une IP C2 à
  haute confiance, voit sa sévérité relevée en critique.
- **Détection** — une IP référencée comme malveillante est signalée *même sans
  seuil de volume*, qu'elle soit la source d'un événement ou sa destination
  (connexion sortante d'un poste, vue par Sysmon). Exemple dans la démo :
  `203.0.113.200` ne fait que 3 échecs SSH (sous le seuil de brute force), mais
  la CTI la remonte en critique car elle est connue comme C2 ; le poste
  `PC-COMPTA01` la contacte ensuite depuis `rundll32`.

Branchable comme le GeoIP : un flux de démo est embarqué (`data/threat_feed.json`),
remplaçable par un vrai feed (JSON ou CSV) :

```bash
export MINISIEM_CTI_FEED=/chemin/feed.csv
```

Formats réels compatibles après conversion : abuse.ch Feodo Tracker, blocklist.de,
AbuseIPDB, listes de nœuds de sortie Tor, exports MISP/OTX. Le rapport affiche un
panneau CTI et un badge « connu » sur chaque alerte concernée.

## Listes blanches et faux positifs

Un `config.yml` optionnel (voir `config.example.yml`) supprime les alertes des IP
de confiance (plages CIDR), des comptes de supervision, et permet de désactiver
des règles :

```bash
python analyze.py samples/*.log --config config.yml
```

## Exports

```bash
python analyze.py samples/*.log --json alerts.json   # alertes machine-readable
python analyze.py --export-sigma sigma/              # règles au format Sigma
python analyze.py --list-rules                       # inventaire des règles
python analyze.py samples/*.log --min-severity high  # ne garder que high + critical
```

L'export Sigma rend les règles rejouables dans Splunk, Elastic, Sentinel ou un
autre SIEM, via les convertisseurs du projet Sigma. La conversion est fidèle :

- une règle `match` devient une règle Sigma, `filter` compris
  (`selection and not filter`) ;
- un `threshold` devient une règle de base et une **corrélation Sigma**
  `event_count` (ou `value_count` pour un comptage de valeurs distinctes, comme
  les ports du scan) ;
- une `sequence` devient une corrélation `event_count` sur la condition
  préalable, enchaînée à une corrélation `temporal_ordered` avec le déclencheur ;
- seule la baseline horaire, propre à chaque compte, n'a pas d'équivalent :
  sa règle de base est exportée avec une note.

Chaque règle reçoit un identifiant UUID stable, et les champs normalisés sont
renommés selon la taxonomie Sigma de la source (`EventID`, `Image`,
`cs-uri-query`…). L'intégration continue passe tout l'export au validateur
officiel (`sigma check --fail-on-issues`) : zéro erreur, zéro avertissement.

## Console SOC dans le navigateur (`web/`)

Le moteur de détection est porté en JavaScript (`web/minisiem.js`), généré à
partir des mêmes règles YAML. Deux pages, **entièrement côté client** (aucun
serveur, aucune donnée envoyée) :

- `web/demo.html` — démo simple : déposer un log, voir les alertes. Exemples
  intégrés pour les cinq sources (SSH, web, pare-feu, Windows, Sysmon).
- `web/console.html` — **console SOC complète**, avec quatre capacités :
  - **Détection** : KPIs, filtres par sévérité et recherche, tableau d'alertes.
  - **Investigation** : clic sur une alerte → pivot sur l'IP/compte, activité
    liée (tous les événements de l'entité), chaîne ATT&CK, géo et contexte CTI.
  - **Réponse à incident** : statut (Nouveau → En cours → Contenu → Résolu /
    Faux positif), assignation, notes, actions de remédiation, et export du
    rapport d'incident en JSON. Les statuts sont conservés localement.
  - **Éditeur de règles** : créer, modifier, supprimer une règle et **relancer
    la détection en direct** pour voir l'effet ; export du jeu de règles.

`web/console.standalone.html` est la même console en **un seul fichier** (tous
les scripts intégrés) : pratique à ouvrir en double-clic ou à héberger tel quel.

### Sécurité de la console

La console affiche des journaux chargés par l'utilisateur : c'est exactement le
genre de donnée qu'un attaquant contrôle (un nom d'utilisateur, une URL ou un
user-agent piégé dans un log). Elle est donc durcie comme le site qui l'héberge :

- **CSP stricte** : `default-src 'none'; script-src 'self'; style-src 'self'`.
  Aucun script ni style en ligne, aucun `onclick` : les clics passent par des
  attributs `data-action` et un écouteur unique. Une injection HTML qui
  passerait malgré tout ne pourrait rien exécuter.
- **Échappement complet** de tout ce qui entre dans le DOM (`& < > " '`), y
  compris les règles et statuts relus depuis `localStorage`, et les valeurs
  d'attributs ; les classes CSS ne prennent que des valeurs connues.
- **Version autonome** : la CSP y autorise chaque bloc intégré par son
  empreinte SHA-256, calculée par `build_web_rules.py`, sans `'unsafe-inline'`.
- Aucune requête réseau (`connect-src` non autorisé) : les journaux ne quittent
  jamais le navigateur.

```bash
python build_web_rules.py        # régénère rules.data.js, samples.js, threat_feed.js et la version autonome
node web/demo.test.js            # teste le moteur JS (mêmes scénarios que Python)
python -m http.server -d web     # puis ouvrir http://localhost:8000/console.html
```

Règles, logs d'exemple et flux CTI de la démo sont **générés** depuis `rules/`,
`samples/` et `data/` : aucune duplication, une seule source de vérité.

## Tests

```bash
pip install -r requirements.txt pytest
python -m pytest -q          # 57 tests : parsers, règles, CTI, exports, parité Python/JS
node web/demo.test.js        # 25 tests du moteur JavaScript
```

Chaque règle est testée sur son scénario, et des tests vérifient que le trafic
normal ne génère **aucune** alerte (contrôle des faux positifs : impression
depuis Word, script d'administration PowerShell, antivirus qui lit LSASS…).
Un test de **parité** fait tourner les deux moteurs, Python et JavaScript, sur
les cinq journaux d'exemple et exige exactement les mêmes alertes.

L'intégration continue (GitHub Actions, actions épinglées par empreinte) lance
à chaque envoi les tests Python et JavaScript, vérifie que les fichiers générés
(journaux d'exemple, données de la console) sont à jour, et passe les règles
exportées au validateur Sigma officiel.

## Limites et faux positifs

- Le seuil de 10 échecs/5 min est un compromis : un utilisateur qui se trompe
  plusieurs fois ne déclenche rien, mais une attaque lente et distribuée
  (« low and slow ») passe sous le radar. Ajuster selon le contexte.
- Les détections par seuil ne tiennent pas compte des listes blanches
  (IP internes, scanners de supervision légitimes). À ajouter en V2.
- `SSH_BRUTEFORCE_SUCCESS` suppose que l'IP de l'attaquant ne change pas entre
  les échecs et le succès ; un attaquant qui pivote d'IP y échappe.
- `WEB_INJECTION` repose sur des motifs d'URL : un payload encodé autrement ou
  envoyé en POST (corps non journalisé par défaut) passe sous le radar. C'est de
  la détection par signature, pas un WAF.
- La détection de scan de ports dépend d'avoir des logs de pare-feu en mode
  journalisation ; un scan « furtif » lent sur peu de ports n'atteint pas le seuil.
- `WIN_UNUSUAL_HOUR` a besoin d'un historique suffisant par compte : un nouvel
  utilisateur sans baseline, ou un compte de service irrégulier, génère du bruit
  ou des silences. Une vraie baseline se calcule sur plusieurs semaines, pas sur
  un seul fichier de logs.
- Les règles Sysmon dépendent de la configuration de Sysmon : sans
  journalisation des accès à LSASS (Event ID 10) ou du registre (13), elles
  restent muettes. Une configuration de référence (SwiftOnSecurity, Olaf
  Hartong) couvre ces événements.
- `SYSMON_PS_ENCODED` et `SYSMON_LOLBIN_DOWNLOAD` lisent la ligne de commande :
  un binaire renommé ou une commande découpée en variables y échappe. Un
  installeur légitime écrit aussi des clés Run, d'où la sévérité moyenne de
  `SYSMON_RUN_KEY`, et la liste d'exclusion de `SYSMON_LSASS_ACCESS` est à
  compléter avec les outils de sécurité du parc (EDR, sauvegarde).

## Feuille de route

- Mode « live » qui suit les logs en continu (tail) avec notifications.
- Enrichissement réputation d'IP (AbuseIPDB) et corrélation inter-règles.
- Davantage de sources : journaux cloud (CloudTrail, Entra ID), et d'autres
  événements Sysmon (WMI, canaux nommés, chargement de pilotes).

## Avertissement

Projet à but pédagogique et défensif. Les données d'exemple sont **synthétiques**
(générées par `generate_logs.py`). N'analysez que des logs qui vous appartiennent.

## Licence

Code et documentation sous [licence MIT](LICENSE) © 2026 Manthole : libre réutilisation, y compris commerciale, à condition de conserver la mention de copyright.
