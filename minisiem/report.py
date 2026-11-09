"""Génère un rapport HTML autonome à partir des alertes.

Un seul fichier, CSS en ligne, un graphique Chart.js (CDN) pour la
répartition par sévérité. Lisible hors ligne même si le CDN est bloqué
(le graphique disparaît, le reste du rapport reste intact).
"""
from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime

from jinja2 import Template

from .events import Alert, Event, SEVERITY_ORDER

_TEMPLATE = Template(r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport mini-SIEM</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css">
<style>
  :root { --bg:#0f1116; --card:#171a21; --line:#272b36; --txt:#e6e8ee;
          --muted:#9aa0ad; --crit:#e24b4a; --high:#ef9f27; --medium:#378add; --low:#5dcaa5; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--txt);
         font:15px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  .wrap { max-width:1000px; margin:0 auto; padding:32px 20px 64px; }
  h1 { font-size:24px; margin:0 0 4px; font-weight:600; }
  h2 { font-size:18px; margin:32px 0 12px; font-weight:600; }
  .sub { color:var(--muted); margin:0 0 24px; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; }
  .kpi { background:var(--card); border:1px solid var(--line); border-radius:12px;
         padding:16px 20px; min-width:120px; flex:1; }
  .kpi .n { font-size:28px; font-weight:600; }
  .kpi .l { color:var(--muted); font-size:13px; text-transform:uppercase; letter-spacing:.04em; }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; align-items:start; }
  .panel { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px 20px; }
  table { width:100%; border-collapse:collapse; }
  th,td { text-align:left; padding:10px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
  .sev { display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; font-weight:600; }
  .sev.critical{ background:rgba(226,75,74,.15); color:var(--crit); }
  .sev.high{ background:rgba(239,159,39,.15); color:var(--high); }
  .sev.medium{ background:rgba(55,138,221,.15); color:var(--medium); }
  .sev.low{ background:rgba(93,202,165,.15); color:var(--low); }
  code { background:#0b0d12; border:1px solid var(--line); border-radius:6px;
         padding:1px 6px; font-size:12.5px; color:#cdd3e0; }
  details { margin-top:6px; }
  summary { cursor:pointer; color:var(--muted); font-size:13px; }
  pre { background:#0b0d12; border:1px solid var(--line); border-radius:8px;
        padding:10px 12px; overflow:auto; font-size:12.5px; color:#b9c0d0; margin:8px 0 0; }
  .att { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; color:var(--medium); }
  #map { height:300px; border-radius:12px; margin-top:4px; background:var(--card); }
  .leaflet-popup-content { font:13px/1.5 system-ui,sans-serif; }
  .matrix { display:flex; gap:10px; overflow-x:auto; padding:4px 0; }
  .col { flex:0 0 150px; }
  .col .hd { font-size:12px; color:var(--muted); text-transform:uppercase;
             letter-spacing:.03em; padding-bottom:8px; border-bottom:1px solid var(--line);
             margin-bottom:8px; min-height:30px; }
  .tech { background:var(--card); border:1px solid var(--line); border-radius:8px;
          padding:8px 10px; margin-bottom:6px; }
  .tech .id { font-family:ui-monospace,Menlo,monospace; color:var(--medium); font-size:12.5px; }
  .tech .n { font-size:12.5px; color:var(--txt); }
  .tech .c { float:right; font-size:11px; color:var(--muted); }
  .cti { display:inline-block; margin-top:4px; padding:2px 8px; border-radius:6px;
         font-size:11.5px; background:rgba(226,75,74,.12); color:#e24b4a;
         border:1px solid rgba(226,75,74,.3); }
  .foot { color:var(--muted); font-size:12.5px; margin-top:40px; border-top:1px solid var(--line); padding-top:16px; }
  a { color:var(--medium); }
</style>
</head>
<body>
<div class="wrap">
  <h1>Rapport d'analyse — mini-SIEM</h1>
  <p class="sub">Généré le {{ generated_at }} · {{ events_total }} événements analysés ·
     {{ sources|join(", ") }}</p>

  <div class="cards">
    <div class="kpi"><div class="n">{{ alerts|length }}</div><div class="l">Alertes</div></div>
    {% for sev in ["critical","high","medium","low"] %}
    <div class="kpi"><div class="n" style="color:var(--{{ sev }})">{{ sev_counts.get(sev,0) }}</div>
      <div class="l">{{ sev }}</div></div>
    {% endfor %}
  </div>

  <div class="grid" style="margin-top:24px">
    <div class="panel">
      <h2 style="margin-top:0">Répartition par sévérité</h2>
      <canvas id="sevChart" height="180"></canvas>
    </div>
    <div class="panel">
      <h2 style="margin-top:0">Top IP sources (par risque)</h2>
      <table>
        <tr><th>IP</th><th>Origine</th><th>Alertes</th><th>Risque</th></tr>
        {% for ip, country, n, risk in top_ips %}
        <tr><td><code>{{ ip }}</code></td><td>{{ country or "-" }}</td><td>{{ n }}</td>
            <td><b>{{ risk }}</b></td></tr>
        {% endfor %}
      </table>
    </div>
  </div>

  {% if matrix %}
  <h2>Couverture MITRE ATT&amp;CK</h2>
  <div class="panel">
    <div class="matrix">
      {% for tactic, techs in matrix %}
      <div class="col">
        <div class="hd">{{ tactic }}</div>
        {% for tid, tname, n in techs %}
        <div class="tech"><span class="c">×{{ n }}</span>
          <span class="id">{{ tid }}</span><br><span class="n">{{ tname }}</span></div>
        {% endfor %}
      </div>
      {% endfor %}
    </div>
  </div>
  {% endif %}

  {% if cti_hits %}
  <h2>Renseignement sur les menaces (CTI)</h2>
  <div class="panel" style="padding:4px 20px">
    <table>
      <tr><th>IP</th><th>Catégorie</th><th>Source du flux</th><th>Confiance</th><th>Alertes</th></tr>
      {% for ip, cat, source, conf, n in cti_hits %}
      <tr><td><code>{{ ip }}</code></td><td>{{ cat }}</td><td>{{ source }}</td>
          <td>{{ conf }}%</td><td>{{ n }}</td></tr>
      {% endfor %}
    </table>
  </div>
  {% endif %}

  {% if has_timeline %}
  <h2>Timeline des événements</h2>
  <div class="panel">
    <canvas id="tlChart" height="90"></canvas>
  </div>
  {% endif %}

  {% if map_points %}
  <h2>Origine géographique des sources</h2>
  <div class="panel">
    <div id="map"></div>
  </div>
  {% endif %}

  <h2>Alertes</h2>
  <div class="panel" style="padding:4px 20px">
  <table>
    <tr><th>Sévérité</th><th>Règle</th><th>Source IP</th><th>Compte</th>
        <th>Occur.</th><th>Fenêtre</th><th>ATT&amp;CK</th></tr>
    {% for a in alerts %}
    <tr>
      <td><span class="sev {{ a.severity }}">{{ a.severity }}</span></td>
      <td>{{ a.title }}
        {% if a.threat %}<br><span class="cti"><i>⚠</i> connu — {{ a.threat.source }}
          ({{ a.threat.category }}, {{ a.threat.confidence }}%)</span>{% endif %}
        <details><summary>{{ a.count }} preuve(s)</summary>
          <pre>{{ a.evidence_html }}</pre></details>
      </td>
      <td><code>{{ a.source_ip or "-" }}</code>{% if a.country %}<br><span style="color:var(--muted);font-size:12.5px">{{ a.country }}{% if a.city %} · {{ a.city }}{% endif %}</span>{% endif %}</td>
      <td>{{ a.user or "-" }}</td>
      <td>{{ a.count }}</td>
      <td>{{ a.window }}</td>
      <td><span class="att">{{ a.attack }}</span></td>
    </tr>
    {% endfor %}
  </table>
  </div>

  <div class="foot">
    mini-SIEM V1 · analyseur de logs défensif. Les détections reposent sur des
    seuils simples et peuvent produire des faux positifs ; voir la section
    « Limites » du dépôt.
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<script src="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const SEV = {{ sev_chart_json|safe }};
const el = document.getElementById('sevChart');
if (window.Chart && el) {
  new Chart(el, { type:'bar',
    data:{ labels:Object.keys(SEV),
      datasets:[{ data:Object.values(SEV),
        backgroundColor:['#e24b4a','#ef9f27','#378add','#5dcaa5'] }] },
    options:{ plugins:{legend:{display:false}},
      scales:{ x:{ticks:{color:'#9aa0ad'},grid:{display:false}},
               y:{ticks:{color:'#9aa0ad'},grid:{color:'#272b36'},beginAtZero:true} } } });
}
const TL_L = {{ timeline_labels_json|safe }};
const TL_V = {{ timeline_values_json|safe }};
const tlEl = document.getElementById('tlChart');
if (window.Chart && tlEl && TL_L.length) {
  new Chart(tlEl, { type:'line',
    data:{ labels:TL_L, datasets:[{ data:TL_V, borderColor:'#378add',
      backgroundColor:'rgba(55,138,221,.15)', fill:true, tension:.3,
      pointRadius:2, borderWidth:1.5 }] },
    options:{ plugins:{legend:{display:false}},
      scales:{ x:{ticks:{color:'#9aa0ad',maxTicksLimit:12},grid:{display:false}},
               y:{ticks:{color:'#9aa0ad'},grid:{color:'#272b36'},beginAtZero:true} } } });
}
const PTS = {{ map_points_json|safe }};
const mapEl = document.getElementById('map');
if (window.L && mapEl && PTS.length) {
  const map = L.map('map', {scrollWheelZoom:false}).setView([25, 10], 2);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    {attribution:'&copy; OpenStreetMap, &copy; CARTO', subdomains:'abcd', maxZoom:19}).addTo(map);
  const colors = {critical:'#e24b4a',high:'#ef9f27',medium:'#378add',low:'#5dcaa5'};
  PTS.forEach(p => {
    L.circleMarker([p.lat, p.lon], {radius:7, color:colors[p.severity]||'#888',
      fillColor:colors[p.severity]||'#888', fillOpacity:0.7, weight:2})
     .addTo(map)
     .bindPopup(`<b>${p.ip}</b><br>${p.country}${p.city? ' · '+p.city:''}<br>${p.title}`);
  });
}
</script>
</body>
</html>""")


def _window(a: Alert) -> str:
    if a.first_seen == a.last_seen:
        return a.first_seen.strftime("%H:%M:%S")
    secs = int((a.last_seen - a.first_seen).total_seconds())
    return f"{secs}s ({a.first_seen.strftime('%H:%M:%S')}→{a.last_seen.strftime('%H:%M:%S')})"


def render_report(alerts: list[Alert], events: list[Event]) -> str:
    alerts = sorted(alerts, key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), a.first_seen))
    sev_counts = Counter(a.severity for a in alerts)

    # Score de risque par IP source : pondération par sévérité
    risk_weight = {"critical": 10, "high": 5, "medium": 2, "low": 1}
    ip_risk: Counter = Counter()
    ip_alerts: Counter = Counter()
    ip_country: dict = {}
    for a in alerts:
        if a.source_ip:
            ip_risk[a.source_ip] += risk_weight.get(a.severity, 1)
            ip_alerts[a.source_ip] += 1
            ip_country[a.source_ip] = a.country
    top_ips = [(ip, ip_country.get(ip), ip_alerts[ip], risk)
               for ip, risk in ip_risk.most_common(6)]

    # Timeline : nombre d'événements par tranche de 15 min
    timeline = Counter()
    for e in events:
        bucket = e.timestamp.replace(minute=(e.timestamp.minute // 15) * 15,
                                     second=0, microsecond=0)
        timeline[bucket] += 1
    timeline_sorted = sorted(timeline.items())
    timeline_labels = [b.strftime("%H:%M") for b, _ in timeline_sorted]
    timeline_values = [n for _, n in timeline_sorted]

    # Matrice ATT&CK : tactiques (ordre canonique) -> techniques détectées
    tactic_order = ["Reconnaissance", "Initial Access", "Execution", "Persistence",
                    "Privilege Escalation", "Defense Evasion", "Credential Access",
                    "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact"]
    by_tactic: dict = {}
    for a in alerts:
        tech = by_tactic.setdefault(a.tactic, {})
        tech.setdefault(a.attack, {"title": a.title, "n": 0})["n"] += 1
    matrix = []
    for tactic in tactic_order:
        if tactic in by_tactic:
            techs = sorted(((tid, d["title"], d["n"])
                            for tid, d in by_tactic[tactic].items()), key=lambda x: x[0])
            matrix.append((tactic, techs))

    view = []
    for a in alerts:
        d = a.to_dict()
        d["window"] = _window(a)
        d["evidence_html"] = html.escape("\n".join(a.evidence))
        view.append(d)

    sev_chart = {s: sev_counts.get(s, 0) for s in ["critical", "high", "medium", "low"]}

    map_points = [
        {"lat": a.lat, "lon": a.lon, "ip": a.source_ip, "country": a.country or "",
         "city": a.city or "", "title": a.title, "severity": a.severity}
        for a in alerts if a.lat is not None and a.lon is not None
    ]

    # Indicateurs CTI touchés (dédupliqués par IP)
    cti_map: dict = {}
    for a in alerts:
        if a.threat and a.source_ip:
            k = a.source_ip
            if k not in cti_map:
                cti_map[k] = [a.source_ip, a.threat["category"], a.threat["source"],
                              a.threat["confidence"], 0]
            cti_map[k][4] += 1
    cti_hits = sorted(cti_map.values(), key=lambda r: -r[3])

    return _TEMPLATE.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        events_total=len(events),
        sources=sorted({e.source for e in events}) or ["-"],
        alerts=view,
        sev_counts=sev_counts,
        top_ips=top_ips,
        matrix=matrix,
        sev_chart_json=json.dumps(sev_chart),
        map_points=map_points,
        map_points_json=json.dumps(map_points),
        cti_hits=cti_hits,
        timeline_labels_json=json.dumps(timeline_labels),
        timeline_values_json=json.dumps(timeline_values),
        has_timeline=len(timeline_sorted) > 1,
    )
