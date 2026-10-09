"""Self-contained scan dashboard generator (no browser-side network access)."""
from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any


def _embedded(identifier: str, value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    payload = re.sub(r"</script", r"<\\/script", payload, flags=re.I)
    payload = payload.replace("<!--", "<\\u0021--")
    return f'<script type="application/json" id="{identifier}">{payload}</script>'


def build_dashboard(trace: dict[str, Any], report: dict[str, Any], sbom: dict[str, Any],
                    vex: dict[str, Any], project_path: str, run_time: str) -> str:
    summary = report.get("summary", {})
    total = int(summary.get("total_vulnerabilities", 0) or 0)
    dismissed = int(summary.get("dismissed_unreachable", 0) or 0)
    actionable = int(summary.get("actionable", 0) or 0)
    suspicious = int(summary.get("suspicious_packages", 0) or 0)
    alerts = total + suspicious
    actionable_alerts = actionable
    stages = trace.get("stages", [])
    stage_names = ["parse", "sbom", "osv_lookup", "reachability", "slopsquat", "vex_output"]
    stage_lookup = {stage.get("stage"): stage for stage in stages}
    # Nodes laid out as a fork: SBOM/OSV and slopsquat proceed independently.
    nodes = {
        "parse": (88, 115), "sbom": (284, 66), "osv_lookup": (480, 66),
        "reachability": (676, 66), "slopsquat": (480, 220), "vex_output": (872, 115),
    }
    edges = [("parse", "sbom"), ("sbom", "osv_lookup"), ("osv_lookup", "reachability"),
             ("reachability", "vex_output"), ("parse", "slopsquat"), ("slopsquat", "vex_output")]
    lines = []
    for source, target in edges:
        x1, y1 = nodes[source]
        x2, y2 = nodes[target]
        lines.append(f'<line class="pipe-line" data-from="{source}" data-to="{target}" x1="{x1+58}" y1="{y1+28}" x2="{x2-58}" y2="{y2+28}"/>')
    node_html = []
    for name in stage_names:
        x, y = nodes[name]
        stage = stage_lookup.get(name, {})
        stage_id = html.escape(name)
        node_html.append(
            f'<g class="pipe-node" tabindex="0" role="button" aria-label="Open {stage_id} stage" '
            f'data-stage="{stage_id}" transform="translate({x},{y})">'
            f'<rect width="116" height="62" rx="10"/><text class="node-title" x="58" y="22">{stage_id.replace("_", " ")}</text>'
            f'<text class="node-count" x="58" y="40">{stage.get("items_in", 0)} → {stage.get("items_out", 0)}</text>'
            f'<text class="node-time" x="58" y="54">{stage.get("duration_ms", 0)} ms</text></g>')
    svg = ('<svg class="pipeline-svg" viewBox="0 0 1000 310" role="img" aria-label="Scan pipeline">'
           + "".join(lines) + '<g id="packet-layer"></g>' + "".join(node_html)
           + '<g id="bins"><rect x="750" y="238" width="126" height="48" rx="8" class="bin-clear"/>'
             '<text x="813" y="267" text-anchor="middle">Not affected: '
           + str(dismissed) + '</text><rect x="884" y="238" width="104" height="48" rx="8" class="bin-risk"/>'
             '<text x="936" y="267" text-anchor="middle">Actionable: '
           + str(actionable) + '</text></g></svg>')

    safe_path = html.escape(project_path)
    safe_time = html.escape(run_time)
    # Keep stage names as data rather than HTML interpolation in JS.
    html_doc = rf'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ChainGuard scan dashboard</title>
<style>
:root{{--bg:#0B1220;--panel:#111C2D;--panel2:#152338;--line:#26364d;--text:#e5edf5;--muted:#98a9bc;--cyan:#22D3EE;--red:#EF4444;--green:#22C55E;--amber:#F59E0B;--mono:ui-monospace,SFMono-Regular,Consolas,monospace}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 Inter,system-ui,-apple-system,"Segoe UI",sans-serif}}button,input,select{{font:inherit;color:inherit}}button{{background:#1a2a40;border:1px solid #30445d;border-radius:7px;padding:.5rem .75rem;cursor:pointer}}button:hover,button:focus-visible{{border-color:var(--cyan);outline:2px solid transparent}}:focus-visible{{outline:2px solid var(--cyan);outline-offset:2px}}.shell{{max-width:1460px;margin:auto;padding:24px}}header{{display:flex;flex-wrap:wrap;align-items:center;gap:20px;border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:20px}}h1{{font-size:1.45rem;margin:0}}h2{{font-size:1.05rem;margin:0 0 14px}}h3{{font-size:.95rem;margin:.25rem 0 .6rem}}p{{margin:.35rem 0}}.project-meta{{color:var(--muted);font-size:.85rem;overflow-wrap:anywhere}}.totals{{margin-left:auto;display:flex;gap:9px;flex-wrap:wrap}}.metric{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:9px 13px;min-width:100px}}.metric strong{{display:block;font-size:1.35rem;color:var(--cyan)}}.metric small{{color:var(--muted)}}.toggle{{display:flex;align-items:center;gap:8px;color:var(--muted)}}.toggle button[aria-pressed="true"]{{border-color:var(--cyan);color:var(--cyan)}}main{{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:16px}}.panel{{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:17px;min-width:0}}.pipeline,.funnel,.threats,.artifacts{{grid-column:span 12}}.journey,.evidence{{grid-column:span 6}}.findings{{grid-column:span 12}}.panel-head{{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}}.pipeline-svg{{width:100%;height:auto;max-height:350px;display:block}}.pipe-line{{stroke:#42617e;stroke-width:2;stroke-dasharray:5 6}}.pipe-node{{cursor:pointer}}.pipe-node rect{{fill:#14243a;stroke:#39536e;stroke-width:1.5}}.pipe-node:hover rect,.pipe-node:focus rect,.pipe-node.active rect{{stroke:var(--cyan);stroke-width:2.5}}.node-title{{fill:var(--text);font-size:12px;text-anchor:middle;text-transform:capitalize}}.node-count{{fill:var(--cyan);font:11px var(--mono);text-anchor:middle}}.node-time{{fill:var(--muted);font:9px var(--mono);text-anchor:middle}}.packet{{fill:var(--cyan);filter:drop-shadow(0 0 5px var(--cyan))}}.packet.cleared{{fill:var(--green)}}.packet.actionable{{fill:var(--red);filter:drop-shadow(0 0 5px var(--red))}}.bin-clear{{fill:#102b27;stroke:var(--green)}}.bin-risk{{fill:#351c25;stroke:var(--red)}}#bins text{{fill:var(--text);font-size:11px}}.controls{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}}.controls label{{font-size:.8rem;color:var(--muted)}}select,input{{background:#0d1828;border:1px solid #30445d;border-radius:6px;padding:.45rem}}.drawer{{margin-top:10px;padding:12px;background:#0d1828;border:1px solid var(--line);border-radius:8px;max-height:220px;overflow:auto;display:none}}.drawer.open{{display:block}}pre,code,.mono{{font-family:var(--mono)}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}.funnel-row{{display:grid;grid-template-columns:130px 1fr 60px;align-items:center;gap:10px;margin:11px 0;cursor:pointer}}.bar-track{{height:14px;background:#0b1422;border-radius:8px;overflow:hidden}}.bar-fill{{height:100%;background:var(--cyan);min-width:0}}.bar-fill.dismissed{{background:var(--green)}}.bar-fill.actionable{{background:var(--red)}}.bar-value{{font:12px var(--mono);text-align:right}}.journey-layout{{display:grid;grid-template-columns:minmax(130px,.8fr) 1.2fr;gap:12px}}.package-list{{max-height:420px;overflow:auto;display:grid;align-content:start;gap:5px}}.package-choice{{text-align:left;overflow-wrap:anywhere}}.package-choice.selected{{border-color:var(--cyan);color:var(--cyan)}}.timeline{{border-left:2px solid #39536e;margin:.5rem 0 0 10px;padding-left:16px}}.event{{position:relative;padding:0 0 13px;color:var(--muted)}}.event:before{{content:"";position:absolute;left:-22px;top:6px;width:9px;height:9px;background:var(--cyan);border-radius:50%}}.event.good:before{{background:var(--green)}}.event.bad:before{{background:var(--red)}}.event b{{color:var(--text)}}.chain{{display:flex;gap:5px;align-items:stretch;flex-wrap:wrap;margin:12px 0}}.chain-step{{background:#0d1828;border:1px solid var(--line);border-radius:7px;padding:8px;min-width:80px;flex:1;text-align:center;font-size:.78rem;overflow-wrap:anywhere}}.chain-arrow{{color:var(--muted);align-self:center}}.columns{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}}.threat-column{{background:#0d1828;border-radius:8px;padding:10px;min-height:90px}}.threat-column h3{{font-size:.78rem;letter-spacing:.04em;color:var(--muted)}}.threat-card{{border-left:3px solid var(--red);background:#172337;padding:9px;margin:7px 0;border-radius:5px;font-size:.82rem}}.threat-card.clear{{border-color:var(--green)}}.threat-card.warn{{border-color:var(--amber)}}.badge{{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:1px 7px;font-size:.72rem;color:var(--amber)}}.badge.red{{color:var(--red)}}.badge.green{{color:var(--green)}}.badge.cyan{{color:var(--cyan)}}.tabbar{{display:flex;gap:7px;margin:12px 0}}.tabbar button.active{{border-color:var(--cyan);color:var(--cyan)}}.artifact-body{{background:#0a1321;border:1px solid var(--line);border-radius:8px;padding:12px;max-height:400px;overflow:auto}}.artifact-body pre{{margin:0;font-size:.8rem}}.json-key{{color:#7dd3fc}}.json-string{{color:#86efac}}.json-number{{color:#fbbf24}}.json-bool{{color:#c4b5fd}}.findings-table{{width:100%;border-collapse:collapse;font-size:.86rem}}.findings-table th,.findings-table td{{border-bottom:1px solid var(--line);padding:9px;text-align:left;vertical-align:top}}.findings-table th{{color:var(--muted)}}.findings-table tr{{cursor:pointer}}.findings-table tr:hover{{background:#172337}}.finding-title{{color:var(--cyan);font-weight:600}}.reason{{color:var(--muted);font-size:.8rem}}.empty{{color:var(--muted);padding:14px;text-align:center}}.source-pair{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}.source-box{{background:#0d1828;border-radius:8px;padding:10px;min-width:0;overflow-wrap:anywhere}}.source-box ul{{padding-left:18px;margin:.3rem 0}}.error{{color:var(--red)}}@keyframes pulse{{50%{{opacity:.35;transform:scale(1.5)}}}}.pulse{{animation:pulse 1.3s ease-in-out infinite}}@media(prefers-reduced-motion:reduce){{*,*:before,*:after{{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important}}}}@media(max-width:850px){{.journey,.evidence{{grid-column:span 12}}.columns{{grid-template-columns:repeat(2,minmax(0,1fr))}}.totals{{margin-left:0}}}}@media(max-width:540px){{.shell{{padding:13px}}.journey-layout{{grid-template-columns:1fr}}.package-list{{max-height:150px}}.source-pair{{grid-template-columns:1fr}}.columns{{grid-template-columns:1fr 1fr}}.funnel-row{{grid-template-columns:90px 1fr 45px}}.findings-table{{font-size:.76rem}}.findings-table th,.findings-table td{{padding:6px}}}}
</style></head><body><div class="shell">
<header><div><h1>ChainGuard / Scan trace</h1><div class="project-meta">{safe_path} · {safe_time}</div></div>
<div class="totals"><div class="metric"><strong id="metric-alerts">{alerts}</strong><small id="metric-mode">Normal scanner · alerts</small></div><div class="metric"><strong>{dismissed}</strong><small>cleared</small></div><div class="metric"><strong>{actionable_alerts}</strong><small>actionable only</small></div><div class="metric"><strong>{suspicious}</strong><small>suspicious packages</small></div></div>
<div class="toggle"><span>View:</span><button id="mode-toggle" aria-pressed="true">Normal scanner</button><span>vs</span><button id="chain-toggle" aria-pressed="false">ChainGuard</button></div></header>
<main>
<section class="panel pipeline"><div class="panel-head"><h2>Live pipeline</h2><div class="controls"><button id="play">▶ Play</button><button id="pause">Ⅱ Pause</button><button id="step">Step</button><button id="restart">↺ Restart</button><label>Speed <select id="speed"><option value="0.5">0.5×</option><option value="1" selected>1×</option><option value="2">2×</option></select></label></div></div>
{svg}<div id="stage-drawer" class="drawer" aria-live="polite"></div></section>
<section class="panel funnel"><h2>Noise funnel <span class="reason">select a bar to filter findings</span></h2>
<div class="funnel-row" data-filter="all"><span>Total vulnerabilities</span><div class="bar-track"><div class="bar-fill" style="width:{100 if total else 0}%"></div></div><span class="bar-value">{total}</span></div>
<div class="funnel-row" data-filter="dismissed"><span>Dismissed · {round((dismissed/total*100),1) if total else 0}%</span><div class="bar-track"><div class="bar-fill dismissed" style="width:{(dismissed/total*100) if total else 0}%"></div></div><span class="bar-value">{dismissed}</span></div>
<div class="funnel-row" data-filter="actionable"><span>Actionable</span><div class="bar-track"><div class="bar-fill actionable" style="width:{(actionable/total*100) if total else 0}%"></div></div><span class="bar-value">{actionable}</span></div>
<div class="reason">Noise reduced by {summary.get('noise_reduced_percent',0)}% · {suspicious} suspicious package(s)</div></section>
<section class="panel journey"><h2>Package journey</h2><div class="journey-layout"><div><input id="package-search" type="search" placeholder="Find package" aria-label="Search packages"><div id="package-list" class="package-list"></div></div><div id="journey-detail" class="empty">Select a package to inspect its scan events.</div></div></section>
<section class="panel evidence"><h2>Evidence chain</h2><div id="evidence-content" class="empty">Select a vulnerability finding.</div></section>
<section class="panel findings"><div class="panel-head"><h2>Findings</h2><button id="clear-filter">Clear filter</button></div><div style="overflow:auto"><table class="findings-table"><thead><tr><th>Vulnerability</th><th>Package</th><th>Status</th><th>Reason</th></tr></thead><tbody id="findings-body"></tbody></table></div></section>
<section class="panel threats"><h2>Threat board</h2><div class="columns"><div class="threat-column"><h3>CRITICAL</h3><div id="critical"></div></div><div class="threat-column"><h3>HIGH</h3><div id="high"></div></div><div class="threat-column"><h3>MEDIUM</h3><div id="medium"></div></div><div class="threat-column"><h3>CLEARED</h3><div id="cleared"></div></div></div></section>
<section class="panel artifacts"><div class="panel-head"><h2>Artifacts</h2><button id="copy-artifact">Copy</button></div><div class="tabbar"><button class="artifact-tab active" data-artifact="sbom">SBOM</button><button class="artifact-tab" data-artifact="vex">OpenVEX</button><button class="artifact-tab" data-artifact="summary">CLI summary</button></div><div id="artifact-content" class="artifact-body"></div></section>
</main></div>
{_embedded('trace-data', trace)}{_embedded('report-data', report)}{_embedded('sbom-data', sbom)}{_embedded('vex-data', vex)}
<script>
(()=>{{'use strict';
const data=id=>{{try{{return JSON.parse(document.getElementById(id).textContent)}}catch{{return {{}}}}}};
const trace=data('trace-data'), report=data('report-data'), sbom=data('sbom-data'), vex=data('vex-data');
const stages=trace.stages||[], findings=report.vulnerabilities||[], packages=report.packages||[], journeys=trace.journeys||[], chains=trace.evidence_chains||[];
const $=id=>document.getElementById(id), esc=s=>String(s??'n/a').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;').replace(/'/g,'&#39;'), sourceLine=e=>typeof e==='string'?e:(e.file?`${{e.file}}:${{e.line??'n/a'}}`:'n/a');
let filter='all', selectedFinding=null, selectedPurl=null, currentArtifact='sbom', frame=0, playing=false, speed=1, timer=null;
function artifactValue(k){{if(k==='sbom')return sbom;if(k==='vex')return vex;return {{summary:report.summary||{{}},project:report.target||'n/a',text:`Total vulnerabilities: ${{report.summary?.total_vulnerabilities??0}}\nDismissed as unreachable: ${{report.summary?.dismissed_unreachable??0}}\nActionable: ${{report.summary?.actionable??0}}\nSuspicious packages: ${{report.summary?.suspicious_packages??0}}\nNoise reduced by ${{report.summary?.noise_reduced_percent??0}}%`}}}}
function syntaxJSON(obj){{let s=JSON.stringify(obj,null,2);return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/("(?:\\\\.|[^"\\\\])*")(\\s*:)?|\\b(true|false|null)\\b|\\b-?\\d+(?:\\.\\d+)?\\b/g,(m,str,key)=>str?`<span class="${{key?'json-key':'json-string'}}">${{str}}</span>`:`<span class="${{m==='true'||m==='false'||m==='null'?'json-bool':'json-number'}}">${{m}}</span>`)}}
function renderArtifact(){{const value=artifactValue(currentArtifact);$('artifact-content').innerHTML=currentArtifact==='summary'?`<pre>${{esc(value.text)}}</pre>`:`<pre>${{syntaxJSON(value)}}</pre>`}}
function renderEvidence(f){{const chain=chains.find(c=>c.vuln_id===f.id&&c.package===f.package?.name)||chains.find(c=>c.vuln_id===f.id);const evidence=chain?.evidence||[];const stages=['CVE / advisory','Package','Advisory functions','Imported?','Function called?','File:line','Verdict'];const values=[`${{chain?.aliases?.[0]||f.id}}`,`${{f.package?.name}}@${{f.package?.version}}`,(chain?.advisory_functions||[]).join(', ')||'n/a',chain?.imported===undefined?'n/a':String(chain.imported),(chain?.called_functions_found||[]).join(', ')||'n/a',evidence.join(', ')||'n/a',chain?.verdict||f.status];$('evidence-content').className='';$('evidence-content').innerHTML=`<div class="chain">${{stages.map((s,i)=>`${{i?'<span class="chain-arrow">›</span>':''}}<div class="chain-step"><small>${{esc(s)}}</small><br>${{esc(values[i])}}</div>`).join('')}}</div><div class="source-pair"><div class="source-box"><b>Advisory lists these functions</b><ul>${{(chain?.advisory_functions||[]).map(x=>`<li><code>${{esc(x)}}</code></li>`).join('')||'<li>n/a</li>'}}</ul></div><div class="source-box"><b>Your code calls these</b><ul>${{(chain?.called_functions_found||[]).map(x=>`<li><code>${{esc(x)}}</code></li>`).join('')||'<li>n/a</li>'}}</ul></div></div><p>Confidence: <b>${{chain?.confidence??'n/a'}}</b> · Decision source: <span class="badge cyan">${{esc(chain?.decision_source)}}</span>${{chain?.decision_source==='conservative-default'?' <span class="badge">conservative default</span>':''}}</p><p class="reason">${{esc(f.impact_statement||f.justification||'n/a')}}</p>`}}
function renderPackages(){{let q=$('package-search').value.toLowerCase();$('package-list').innerHTML='';journeys.filter(j=>`${{j.package}} ${{j.purl}}`.toLowerCase().includes(q)).forEach(j=>{{let b=document.createElement('button');b.className='package-choice'+(selectedPurl===j.purl?' selected':'');b.textContent=`${{j.package}} · ${{j.purl}}`;b.onclick=()=>selectPackage(j.purl);$('package-list').appendChild(b)}});if(!$('package-list').children.length)$('package-list').innerHTML='<div class="empty">No packages match.</div>'}}
function selectPackage(purl){{selectedPurl=purl;renderPackages();const j=journeys.find(x=>x.purl===purl);if(!j)return;let detail=$('journey-detail');detail.className='';detail.innerHTML=`<div class="mono">${{esc(j.package)}}</div><div class="timeline">${{(j.events||[]).map(e=>`<div class="event ${{/affected|suspicious|failed/i.test(e.result)?'bad':/not_affected|ok|found|written|parsed/i.test(e.result)?'good':''}}"><b>${{esc(e.stage)}} · ${{esc(e.result)}}</b><div>${{esc(typeof e.detail==='string'?e.detail:JSON.stringify(e.detail))}}</div>${{e.evidence?.length?`<small>${{e.evidence.map(esc).join(', ')}}</small>`:''}}</div>`).join('')}}</div>`;const final=(j.events||[]).filter(e=>e.stage==='reachability'&&e.result!=='skipped_no_vulnerabilities').slice(-1)[0];if(final)detail.innerHTML+=`<p><b>Final verdict:</b> ${{esc(final.result)}} · ${{esc(final.detail?.justification||'n/a')}}</p>`}}
function rows(){{return findings.filter(f=>filter==='all'||(filter==='dismissed'?f.status==='not_affected':f.status==='affected'))}}
function renderFindings(){{let body=$('findings-body');body.innerHTML='';let list=rows();if(!list.length){{body.innerHTML='<tr><td colspan="4" class="empty">No findings for this filter.</td></tr>';return}}list.forEach(f=>{{let tr=document.createElement('tr');tr.innerHTML=`<td><span class="finding-title">${{esc(f.id)}}</span><div class="reason">${{esc(f.summary||f.aliases?.[0]||'n/a')}}</div></td><td class="mono">${{esc(f.package?.name)}}@${{esc(f.package?.version)}}</td><td><span class="badge ${{f.status==='affected'?'red':'green'}}">${{esc(f.status)}}</span>${{f.impact_statement==='function-level data unavailable'?' <span class="badge">conservative default</span>':''}}</td><td class="reason">${{esc(f.justification||f.impact_statement||'n/a')}}</td>`;tr.onclick=()=>{{selectFinding(f);selectPackage(f.package?.purl)}};body.appendChild(tr)}})}}
function selectFinding(f){{selectedFinding=f;renderEvidence(f)}}
function severity(f){{let scores=(f.severity||[]).map(x=>{{let n=Number(String(x.score||'').match(/(?:^|:)(\d+(?:\.\d+)?)/)?.[1]);return Number.isFinite(n)?n:0}});return Math.max(0,...scores)}}
function renderThreats(){{const cols={{critical:[],high:[],medium:[],cleared:[]}};findings.forEach(f=>{{if(f.status==='not_affected'){{cols.cleared.push({{title:f.id,package:f.package?.name,reason:f.justification||f.impact_statement,kind:'clear'}});return}}let s=severity(f),bucket=s>=9?'critical':s>=7?'high':'medium';cols[bucket].push({{title:f.id,package:f.package?.name,reason:f.impact_statement||'Reachability indicates affected',kind:'risk'}})}});(report.suspicious_packages||[]).filter(p=>p.suspicious).forEach(p=>cols.high.push({{title:'Suspicious package',package:p.package?.name,reason:(p.reasons||[]).join('; ')||'n/a',kind:'warn'}}));Object.keys(cols).forEach(k=>{{let el=$(k);el.innerHTML='';if(!cols[k].length)el.innerHTML='<div class="reason">n/a</div>';cols[k].forEach(c=>{{let d=document.createElement('div');d.className='threat-card '+(c.kind==='clear'?'clear':c.kind==='warn'?'warn':'');d.textContent=`${{c.title}} · ${{c.package||'n/a'}} — ${{c.reason||'n/a'}}`;el.appendChild(d)}})}})}}
function showStage(name){{const stage=stages.find(s=>s.stage===name),drawer=$('stage-drawer');document.querySelectorAll('.pipe-node').forEach(n=>n.classList.toggle('active',n.dataset.stage===name));drawer.classList.add('open');drawer.innerHTML=stage?`<b>${{esc(name)}} · ${{stage.items_in??0}} → ${{stage.items_out??0}} · ${{stage.duration_ms??0}} ms</b><pre>${{esc(JSON.stringify(stage.items||[],null,2))}}</pre>`:`<b>${{esc(name)}}:</b> n/a`}}
const stageSeq=['parse','sbom','osv_lookup','reachability','slopsquat','vex_output'];function paintPackets(){{let layer=$('packet-layer');layer.querySelectorAll('.node-packet').forEach(c=>c.remove());if(frame>=stageSeq.length)return;let name=stageSeq[frame],pos={{parse:[88,115],sbom:[284,66],osv_lookup:[480,66],reachability:[676,66],slopsquat:[480,220],vex_output:[872,115]}}[name];let count=Math.min(5,Number(stages.find(s=>s.stage===name)?.items_out||0));if(count===0)return;let greenCount=name==='reachability'&&total?Math.round(count*dismissed/total):0;for(let i=0;i<count;i++){{let c=document.createElementNS('http://www.w3.org/2000/svg','circle');let cleared=name==='reachability'&&i<greenCount;c.setAttribute('cx',cleared?813:pos[0]+58+(i-count/2)*7);c.setAttribute('cy',cleared?262:pos[1]-7);c.setAttribute('r','3');c.setAttribute('class','packet node-packet '+(cleared?'cleared':name==='reachability'?'actionable pulse':name==='slopsquat'&&suspicious?'actionable':''));layer.appendChild(c)}}}}
function setEdgeMotion(start){{document.querySelectorAll('.animated-packet animateMotion').forEach(node=>{{try{{if(start)node.beginElement();else node.endElement()}}catch{{}}}})}}
function tick(){{if(!playing)return;paintPackets();if(frame<stageSeq.length-1)timer=setTimeout(()=>{{frame++;tick()}},900/speed);else{{playing=false;setEdgeMotion(false)}}}}
function setMode(chain){{$('chain-toggle').setAttribute('aria-pressed',String(chain));$('mode-toggle').setAttribute('aria-pressed',String(!chain));$('metric-alerts').textContent=chain?${actionable_alerts}:${alerts};$('metric-mode').textContent=chain?'ChainGuard · actionable only':'Normal scanner · alerts';}}
$('package-search').addEventListener('input',renderPackages);document.querySelectorAll('.pipe-node').forEach(n=>{{n.addEventListener('click',()=>showStage(n.dataset.stage));n.addEventListener('keydown',e=>{{if(e.key==='Enter'||e.key===' ')showStage(n.dataset.stage)}})}});
document.querySelectorAll('.funnel-row').forEach(row=>row.onclick=()=>{{filter=row.dataset.filter;renderFindings()}});$('clear-filter').onclick=()=>{{filter='all';renderFindings()}};
document.querySelectorAll('.artifact-tab').forEach(tab=>tab.onclick=()=>{{document.querySelectorAll('.artifact-tab').forEach(t=>t.classList.toggle('active',t===tab));currentArtifact=tab.dataset.artifact;renderArtifact()}});
$('copy-artifact').onclick=()=>{{let value=artifactValue(currentArtifact);let text=currentArtifact==='summary'?value.text:JSON.stringify(value,null,2);if(navigator.clipboard?.writeText)navigator.clipboard.writeText(text).catch(()=>{{}})}};
$('play').onclick=()=>{{if(frame>=stageSeq.length-1)frame=0;if(!playing){{playing=true;setEdgeMotion(true);tick()}}}};$('pause').onclick=()=>{{playing=false;clearTimeout(timer);setEdgeMotion(false)}};$('step').onclick=()=>{{playing=false;clearTimeout(timer);setEdgeMotion(false);frame=Math.min(frame+1,stageSeq.length-1);paintPackets();showStage(stageSeq[frame])}};$('restart').onclick=()=>{{playing=false;clearTimeout(timer);setEdgeMotion(false);frame=0;paintPackets();$('stage-drawer').classList.remove('open')}};
$('speed').onchange=e=>speed=Number(e.target.value);
$('mode-toggle').onclick=()=>setMode(false);$('chain-toggle').onclick=()=>setMode(true);
renderPackages();renderFindings();renderThreats();renderArtifact();paintPackets();if(findings.length)selectFinding(findings.find(f=>f.status==='affected')||findings[0]);if(journeys.length)selectPackage(journeys[0].purl);
}})();
</script></body></html>'''
    # Replace the canned straight-line representation with a moving packet
    # path per pipeline edge; animation remains CSS-only and respects reduced motion.
    animated_edges = []
    for index, (source, target) in enumerate(edges):
        x1, y1 = nodes[source]
        x2, y2 = nodes[target]
        animated_edges.append(
            f'<circle r="4" class="packet animated-packet" style="--delay:{index * 0.22}s">'
            f'<animateMotion dur="2.8s" repeatCount="indefinite" begin="{index * 0.22}s" '
            f'path="M {x1+58} {y1+28} L {x2-58} {y2+28}"/></circle>')
    html_doc = html_doc.replace('<g id="packet-layer"></g>',
                                '<g id="packet-layer">' + ''.join(animated_edges) + '</g>')
    html_doc = html_doc.replace("if(frame>=stageSeq.length)return;let name=stageSeq[frame],pos=", "let name=stageSeq[frame],pos=")
    html_doc = html_doc.replace("function paintPackets(){{let layer=$('packet-layer');layer.innerHTML='';let name=stageSeq[frame],pos=", "function paintPackets(){{let layer=$('packet-layer');layer.innerHTML='';let name=stageSeq[frame],pos=")
    html_doc = html_doc.replace("function tick(){{if(!playing)return;frame=(frame+1)%stageSeq.length;paintPackets();timer=setTimeout(tick,900/speed)}}",
                                "function tick(){{if(!playing)return;if(frame<stageSeq.length-1)frame++;paintPackets();if(frame<stageSeq.length-1)timer=setTimeout(tick,900/speed);else playing=false}}")
    html_doc = html_doc.replace("$('step').onclick=()=>{{playing=false;clearTimeout(timer);frame=(frame+1)%stageSeq.length;paintPackets();showStage(stageSeq[frame])}}",
                                "$('step').onclick=()=>{{playing=false;clearTimeout(timer);frame=Math.min(frame+1,stageSeq.length-1);paintPackets();showStage(stageSeq[frame])}}")
    html_doc = html_doc.replace(".packet.actionable{{fill:var(--red);filter:drop-shadow(0 0 5px var(--red))}}",
                                ".packet.actionable{{fill:var(--red);filter:drop-shadow(0 0 5px var(--red))}}.animated-packet{{animation:packetHue 2s infinite alternate}}@keyframes packetHue{{to{{fill:var(--cyan)}}}}")
    html_doc = html_doc.replace(".bin-risk{{fill:#351c25;stroke:var(--red)}}",
                                ".bin-risk{{fill:#351c25;stroke:var(--red)}}#bins .bin-clear,#bins .bin-risk{{transition:transform .35s ease}}#bins .bin-clear{{transform:translateY(var(--drop-clear,0px))}}.packet.cleared{{transform:translateY(8px)}}")
    html_doc = html_doc.replace("@media(prefers-reduced-motion:reduce){{*,*:before,*:after{{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important}}}}",
                                "@media(prefers-reduced-motion:reduce){{*,*:before,*:after{{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important}}animateMotion{{display:none}}}}")
    html_doc = html_doc.replace("@media(prefers-reduced-motion:reduce){{*,*:before,*:after{{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important}}}}",
                                "@media(prefers-reduced-motion:reduce){{*,*:before,*:after{{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important}}animateMotion{{display:none}}}}")
    html_doc = html_doc.replace("let count=Math.min(5,Number(stages.find(s=>s.stage===name)?.items_out||0));for(let i=0;i<count;i++)",
                                "let count=Math.min(5,Number(stages.find(s=>s.stage===name)?.items_out||0));if(count===0)return;for(let i=0;i<count;i++)")
    return html_doc


def write_dashboard(trace: dict[str, Any], report: dict[str, Any], sbom: dict[str, Any], vex: dict[str, Any],
                    project_path: str, run_time: str, path: str | Path) -> str:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    content = build_dashboard(trace, report, sbom, vex, project_path, run_time)
    target.write_text(content, encoding="utf-8")
    return content
