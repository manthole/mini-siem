/* Généré par build_web_rules.py — ne pas éditer à la main. */
(function (root) {
  root.MINISIEM_RULES = [
  {
    "id": "SSH_BRUTEFORCE",
    "title": "Brute force SSH",
    "type": "threshold",
    "level": "high",
    "attack": "T1110.001",
    "tactic": "Credential Access",
    "description": "Un grand nombre d'échecs d'authentification SSH proviennent d'une même adresse IP sur une courte période, signe d'une attaque par force brute.\n",
    "selection": {
      "event_type": "ssh_login",
      "outcome": "failure"
    },
    "group_by": [
      "source_ip"
    ],
    "window_seconds": 300,
    "count": 10
  },
  {
    "id": "SSH_BRUTEFORCE_SUCCESS",
    "title": "Brute force SSH réussi",
    "type": "sequence",
    "level": "critical",
    "attack": "T1110",
    "tactic": "Credential Access",
    "description": "Plusieurs échecs SSH depuis une IP, suivis d'une connexion réussie depuis la même IP. Forte présomption de compromission d'un compte : à traiter en priorité.\n",
    "precondition": {
      "event_type": "ssh_login",
      "outcome": "failure"
    },
    "trigger": {
      "event_type": "ssh_login",
      "outcome": "success"
    },
    "group_by": [
      "source_ip"
    ],
    "window_seconds": 600,
    "min_preconditions": 5
  },
  {
    "id": "SUDO_NOT_IN_SUDOERS",
    "title": "Tentative d'escalade de privilèges via sudo",
    "type": "match",
    "level": "medium",
    "attack": "T1548.003",
    "tactic": "Privilege Escalation",
    "description": "Un utilisateur a tenté d'exécuter une commande via sudo sans y être autorisé (« user NOT in sudoers »). Peut indiquer une tentative d'escalade de privilèges depuis un compte déjà compromis.\n",
    "selection": {
      "event_type": "sudo",
      "outcome": "failure"
    }
  },
  {
    "id": "WEB_SCAN",
    "title": "Scan web (énumération de ressources)",
    "type": "threshold",
    "level": "medium",
    "attack": "T1595.003",
    "tactic": "Reconnaissance",
    "description": "Une même IP génère un grand nombre d'erreurs 404 en peu de temps : signe d'un outil qui énumère des chemins (fichiers de config, pages d'admin).\n",
    "selection": {
      "event_type": "web_request",
      "status": 404
    },
    "group_by": [
      "source_ip"
    ],
    "window_seconds": 60,
    "count": 20
  },
  {
    "id": "WEB_ATTACK_TOOL",
    "title": "Outil d'attaque web détecté (user-agent)",
    "type": "match",
    "level": "high",
    "attack": "T1595.002",
    "tactic": "Reconnaissance",
    "description": "Le user-agent correspond à un scanner de vulnérabilités connu (sqlmap, nikto, nmap, dirbuster...). Reconnaissance active ciblant le site.\n",
    "selection": {
      "event_type": "web_request",
      "user_agent": {
        "contains": [
          "sqlmap",
          "nikto",
          "nmap",
          "masscan",
          "dirbuster",
          "gobuster",
          "wpscan"
        ]
      }
    }
  },
  {
    "id": "WEB_INJECTION",
    "title": "Tentative d'injection web (SQLi / XSS / traversée)",
    "type": "match",
    "level": "high",
    "attack": "T1190",
    "tactic": "Initial Access",
    "description": "L'URL contient un motif caractéristique d'injection SQL, de cross-site scripting ou de traversée de répertoire (exploitation d'une application web).\n",
    "selection": {
      "event_type": "web_request",
      "url": {
        "regex": "(?:union(?:\\s|\\+|%20)+select|or(?:\\s|\\+|%20)+1=1|<script|%3Cscript|\\.\\./|%2e%2e%2f|/etc/passwd|' or '|information_schema)"
      }
    }
  },
  {
    "id": "PORT_SCAN",
    "title": "Scan de ports",
    "type": "threshold",
    "level": "medium",
    "attack": "T1046",
    "tactic": "Discovery",
    "description": "Une même IP a été bloquée par le pare-feu sur un grand nombre de ports distincts en peu de temps : balayage de ports à la recherche de services.\n",
    "selection": {
      "event_type": "fw_block"
    },
    "group_by": [
      "source_ip"
    ],
    "window_seconds": 60,
    "distinct": "dest_port",
    "count": 20
  },
  {
    "id": "WIN_BRUTEFORCE",
    "title": "Brute force de connexion Windows",
    "type": "threshold",
    "level": "high",
    "attack": "T1110.001",
    "tactic": "Credential Access",
    "description": "Nombreux échecs d'ouverture de session Windows (Event ID 4625) depuis une même IP : tentative de brute force, souvent via RDP ou SMB.\n",
    "selection": {
      "event_id": 4625
    },
    "group_by": [
      "source_ip"
    ],
    "window_seconds": 300,
    "count": 10
  },
  {
    "id": "WIN_BRUTEFORCE_SUCCESS",
    "title": "Brute force Windows réussi",
    "type": "sequence",
    "level": "critical",
    "attack": "T1110",
    "tactic": "Credential Access",
    "description": "Plusieurs échecs (4625) suivis d'une ouverture de session réussie (4624) depuis la même IP. Forte présomption de compromission de compte.\n",
    "precondition": {
      "event_id": 4625
    },
    "trigger": {
      "event_id": 4624
    },
    "group_by": [
      "source_ip"
    ],
    "window_seconds": 600,
    "min_preconditions": 5
  },
  {
    "id": "WIN_LOG_CLEARED",
    "title": "Journal de sécurité Windows effacé",
    "type": "match",
    "level": "high",
    "attack": "T1685.005",
    "tactic": "Defense Impairment",
    "description": "Le journal de sécurité a été effacé (Event ID 1102). Technique anti-forensic classique pour masquer une activité malveillante après coup.\n",
    "selection": {
      "event_id": 1102
    },
    "group_by": [
      "host"
    ]
  },
  {
    "id": "WIN_GROUP_ADD",
    "title": "Ajout à un groupe privilégié",
    "type": "match",
    "level": "high",
    "attack": "T1098",
    "tactic": "Persistence",
    "description": "Un compte a été ajouté à un groupe local (Event ID 4732). Vers un groupe d'administration (Administrators), c'est une technique de persistance et d'escalade fréquente après compromission.\n",
    "selection": {
      "event_id": 4732
    },
    "group_by": [
      "user",
      "detail"
    ]
  },
  {
    "id": "WIN_UNUSUAL_HOUR",
    "title": "Connexion à une heure inhabituelle",
    "type": "baseline_hour",
    "level": "medium",
    "attack": "T1078",
    "tactic": "Initial Access",
    "description": "Ouverture de session réussie à une heure où l'utilisateur ne se connecte habituellement jamais (comparé à sa propre baseline). Peut signaler l'usage d'un compte valide volé.\n",
    "selection": {
      "event_id": 4624
    },
    "group_by": [
      "user"
    ],
    "min_support": 2
  },
  {
    "id": "WIN_ACCOUNT_CREATED",
    "title": "Création de compte utilisateur",
    "type": "match",
    "level": "medium",
    "attack": "T1136.001",
    "tactic": "Persistence",
    "description": "Un compte utilisateur a été créé (Event ID 4720). Légitime en administration, mais à corréler : un compte créé juste après une compromission est un moyen de persistance.\n",
    "selection": {
      "event_id": 4720
    },
    "group_by": [
      "user"
    ]
  },
  {
    "id": "WEB_LOG4SHELL",
    "title": "Tentative d'exploitation Log4Shell (CVE-2021-44228)",
    "type": "match",
    "level": "critical",
    "attack": "T1190",
    "tactic": "Initial Access",
    "description": "Motif d'injection JNDI caractéristique de Log4Shell dans l'URL ou l'en-tête. Vise l'exécution de code à distance via Log4j. À traiter en priorité.\n",
    "selection": {
      "event_type": "web_request",
      "url": {
        "regex": "(?:\\$\\{jndi:(?:ldap|ldaps|rmi|dns)|%24%7bjndi)"
      }
    }
  },
  {
    "id": "SYSMON_OFFICE_SHELL",
    "title": "Application Office qui lance un interpréteur de commandes",
    "type": "match",
    "level": "high",
    "attack": "T1204.002",
    "tactic": "Execution",
    "description": "Word, Excel, PowerPoint ou Outlook démarre un shell, PowerShell ou un binaire système détourné (Sysmon 1). C'est la signature d'un document piégé : la macro lance la suite de l'attaque. Un processus enfant légitime d'Office (impression avec splwow64.exe, par exemple) ne déclenche rien.\n",
    "selection": {
      "event_type": "process_creation",
      "parent_process": {
        "endswith": [
          "\\winword.exe",
          "\\excel.exe",
          "\\powerpnt.exe",
          "\\outlook.exe",
          "\\msaccess.exe",
          "\\mspub.exe"
        ]
      },
      "process": {
        "endswith": [
          "\\cmd.exe",
          "\\powershell.exe",
          "\\pwsh.exe",
          "\\wscript.exe",
          "\\cscript.exe",
          "\\mshta.exe",
          "\\rundll32.exe",
          "\\regsvr32.exe",
          "\\certutil.exe",
          "\\bitsadmin.exe"
        ]
      }
    },
    "group_by": [
      "host",
      "user"
    ]
  },
  {
    "id": "SYSMON_PS_ENCODED",
    "title": "PowerShell lancé avec une commande encodée",
    "type": "match",
    "level": "high",
    "attack": "T1059.001",
    "tactic": "Execution",
    "description": "PowerShell reçoit son script en Base64 (-EncodedCommand ou l'une de ses abréviations : -enc, -ec, -e…), suivi d'un bloc encodé (Sysmon 1). Les administrateurs l'utilisent rarement ; les chargeurs malveillants, très souvent, pour masquer la commande aux regards et aux filtres simples.\n",
    "selection": {
      "event_type": "process_creation",
      "process": {
        "endswith": [
          "\\powershell.exe",
          "\\pwsh.exe"
        ]
      },
      "command_line": {
        "regex": "\\s[-/]e(?:c|n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?\\s+[A-Za-z0-9+/=]{20,}"
      }
    },
    "group_by": [
      "host",
      "user"
    ]
  },
  {
    "id": "SYSMON_LOLBIN_DOWNLOAD",
    "title": "Téléchargement par un binaire Windows détourné",
    "type": "match",
    "level": "high",
    "attack": "T1105",
    "tactic": "Command and Control",
    "description": "certutil (-urlcache) ou bitsadmin (/transfer) sert à télécharger un fichier (Sysmon 1). Ces outils sont signés par Microsoft et présents partout, d'où leur usage pour récupérer une charge sans apporter son propre outil (« living off the land »). Le simple calcul d'empreinte (certutil -hashfile) ne déclenche rien.\n",
    "selection": {
      "event_type": "process_creation",
      "command_line": {
        "regex": "(?:certutil(?:\\.exe)?\\s.*[-/](?:urlcache|verifyctl)|bitsadmin(?:\\.exe)?\\s.*/transfer)"
      }
    },
    "group_by": [
      "host",
      "user"
    ]
  },
  {
    "id": "SYSMON_LSASS_ACCESS",
    "title": "Accès mémoire suspect au processus LSASS",
    "type": "match",
    "level": "critical",
    "attack": "T1003.001",
    "tactic": "Credential Access",
    "description": "Un processus ouvre lsass.exe avec des droits de lecture mémoire (Sysmon 10, GrantedAccess 0x1010, 0x1410, 0x1fffff…). LSASS garde les secrets des sessions ouvertes : c'est ce que fait un outil de vol d'identifiants (type Mimikatz) ou un dump mémoire. L'antivirus et les processus système qui y accèdent légitimement sont écartés par le filtre.\n",
    "selection": {
      "event_type": "process_access",
      "target": {
        "endswith": "\\lsass.exe"
      },
      "granted_access": {
        "in": [
          "0x1010",
          "0x1410",
          "0x1438",
          "0x143a",
          "0x1f0fff",
          "0x1f1fff",
          "0x1f3fff",
          "0x1fffff"
        ]
      }
    },
    "filter": {
      "process": {
        "endswith": [
          "\\MsMpEng.exe",
          "\\MsSense.exe",
          "\\wininit.exe",
          "\\csrss.exe"
        ]
      }
    },
    "group_by": [
      "host",
      "process"
    ]
  },
  {
    "id": "SYSMON_RUN_KEY",
    "title": "Persistance par une clé de registre Run",
    "type": "match",
    "level": "medium",
    "attack": "T1547.001",
    "tactic": "Persistence",
    "description": "Une valeur est écrite sous une clé Run ou RunOnce (Sysmon 13) : le programme indiqué se relancera à chaque ouverture de session. C'est la persistance la plus courante sous Windows ; un installeur légitime le fait aussi, d'où une sévérité moyenne et le contrôle de la valeur écrite.\n",
    "selection": {
      "event_type": "registry_set",
      "target": {
        "contains": "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      }
    },
    "group_by": [
      "host",
      "process"
    ]
  },
  {
    "id": "SYSMON_LOLBIN_NETWORK",
    "title": "Connexion réseau d'un binaire système détourné",
    "type": "match",
    "level": "high",
    "attack": "T1218",
    "tactic": "Stealth",
    "description": "rundll32, regsvr32 ou mshta ouvre une connexion réseau (Sysmon 3). Ces binaires servent à exécuter du code sous couvert d'un programme signé ; qu'ils parlent au réseau évoque une charge chargée en mémoire qui contacte son serveur de commande (C2). Des connexions répétées vers la même adresse ressemblent à une balise.\n",
    "selection": {
      "event_type": "network_connection",
      "process": {
        "endswith": [
          "\\rundll32.exe",
          "\\regsvr32.exe",
          "\\mshta.exe"
        ]
      }
    },
    "group_by": [
      "host",
      "process",
      "dest_ip"
    ]
  }
];
  if (typeof module !== 'undefined' && module.exports) module.exports = root.MINISIEM_RULES;
})(typeof window !== 'undefined' ? window : globalThis);
