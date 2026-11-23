# mini-SIEM

Analyseur de logs défensif en ligne de commande. Il ingère des logs, applique
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
                  samples/windows_events.xml --out rapport.html
```

Ouvre ensuite `rapport.html` dans un navigateur : KPIs par sévérité, graphique,
carte des IP sources, matrice MITRE ATT&CK et tableau des alertes avec preuves.

```
[+] 230 événements analysés, 13 règles chargées.
[+] GeoIP : mode demo.
[+] 13 alerte(s) :
    - [CRITICAL] Brute force SSH réussi            ip=198.51.100.23  x9   T1110
    - [CRITICAL] Brute force Windows réussi        ip=198.51.100.23  x7   T1110
    - [HIGH    ] Brute force SSH                    ip=203.0.113.66   x10  T1110.001
    - [HIGH    ] Outil d'attaque web (user-agent)   ip=203.0.113.9    x31  T1595.002
    - [HIGH    ] Injection web (SQLi/XSS/traversée) ip=203.0.113.9    x1   T1190
    - [HIGH    ] Brute force Windows (RDP/SMB)      ip=203.0.113.66   x10  T1110.001
    - [HIGH    ] Journal de sécurité effacé         user=administr.   x1   T1070.001
    - [HIGH    ] Ajout à un groupe privilégié       user=svc_backup   x1   T1098
    - [MEDIUM  ] Escalade de privilèges via sudo    user=www-data     x1   T1548.003
    - [MEDIUM  ] Scan web (énumération)             ip=203.0.113.9    x20  T1595.003
    - [MEDIUM  ] Scan de ports                      ip=198.51.100.77  x20  T1046
    - [MEDIUM  ] Connexion à une heure inhabituelle user=jdupont      x1   T1078
    - [MEDIUM  ] Création de compte utilisateur     user=svc_backup   x1   T1136.001
```

## Architecture

```
auth.log      ┐
access.log    ├▶ parsers.py ─▶ Event normalisé ─▶ rules.py ─▶ Alertes ─▶ geo.py ─▶ report.py ─▶ rapport.html
ufw.log       │  (auto-détect)  (schéma type ECS)  (règles YAML)        (GeoIP)   (Chart.js+Leaflet+ATT&CK)
windows.xml   ┘
```

- `minisiem/events.py` — schéma d'événement et d'alerte normalisé (inspiré d'ECS).
- `minisiem/parsers.py` — ligne brute → `Event`. Sources : auth.log, Apache/Nginx, pare-feu UFW, Windows (EVTX en XML).
- `minisiem/rules.py` — moteur de détection (types `match`, `threshold`, `sequence`).
- `minisiem/geo.py` — enrichissement GeoIP branchable (MaxMind, sinon table de démo).
- `minisiem/cti.py` — renseignement sur les menaces (flux d'indicateurs branchable).
- `minisiem/config.py` — listes blanches et règles désactivées.
- `minisiem/export.py` — exports JSON et Sigma.
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
| `WIN_LOG_CLEARED` | Windows | journal de sécurité effacé (1102) | T1070.001 |
| `WIN_GROUP_ADD` | Windows | ajout à un groupe privilégié (4732) | T1098 |
| `WIN_ACCOUNT_CREATED` | Windows | compte utilisateur créé (4720) | T1136.001 |
| `WIN_UNUSUAL_HOUR` | Windows | connexion hors des heures habituelles du compte | T1078 |

### Écrire une règle

Trois types de règles, et des opérateurs sur les champs (`contains`, `regex`,
`in`, `gte`, `lte`) :

```yaml
id: WEB_ATTACK_TOOL
title: Outil d'attaque web détecté
type: match              # match | threshold | sequence
level: high              # low | medium | high | critical
attack: T1595.002
selection:
  event_type: web_request
  user_agent:
    contains: [sqlmap, nikto, nmap]   # sous-chaîne, insensible à la casse
```

Un `threshold` peut compter des valeurs distinctes (`distinct: dest_port` pour
le scan de ports) plutôt que des événements bruts.

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
  seuil de volume*. Exemple dans la démo : `203.0.113.200` ne fait que 3 échecs
  SSH (sous le seuil de brute force), mais la CTI la remonte en critique car
  elle est connue comme C2.

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

L'export Sigma prouve la compatibilité avec le standard de l'industrie : les
règles peuvent être rejouées dans Splunk, Elastic ou un autre SIEM.

## Console SOC dans le navigateur (`web/`)

Le moteur de détection est porté en JavaScript (`web/minisiem.js`), généré à
partir des mêmes règles YAML. Deux pages, **entièrement côté client** (aucun
serveur, aucune donnée envoyée) :

- `web/demo.html` — démo simple : déposer un log, voir les alertes.
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

```bash
python build_web_rules.py        # régénère rules.data.js, samples.js, threat_feed.js et la version autonome
node web/demo.test.js            # teste le moteur JS (mêmes scénarios que Python)
python -m http.server -d web     # puis ouvrir http://localhost:8000/console.html
```

Règles, logs d'exemple et flux CTI de la démo sont **générés** depuis `rules/`,
`samples/` et `data/` : aucune duplication, une seule source de vérité.

## Tests

```bash
python -m pytest tests/ -q
```

Chaque règle est testée sur son scénario, et un test vérifie que le trafic
normal ne génère **aucune** alerte (contrôle des faux positifs).

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

## Feuille de route

- Mode « live » qui suit les logs en continu (tail) avec notifications.
- Enrichissement réputation d'IP (AbuseIPDB) et corrélation inter-règles.
- Davantage de sources : Sysmon, journaux cloud (CloudTrail, journaux d'accès).

## Avertissement

Projet à but pédagogique et défensif. Les données d'exemple sont **synthétiques**
(générées par `generate_logs.py`). N'analysez que des logs qui vous appartiennent.

## Licence

Code et documentation sous [licence MIT](LICENSE) © 2026 Manthole : libre réutilisation, y compris commerciale, à condition de conserver la mention de copyright.
