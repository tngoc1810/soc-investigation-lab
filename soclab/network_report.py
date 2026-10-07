"""Static evidence explorer and explicit business-context/response readiness checks."""

import ipaddress
import json


def readiness(result, context):
    assets = []
    if context is not None:
        if not isinstance(context, dict) or context.get('capture_sha256') != result['source']['sha256']:
            raise ValueError('business context must approve the exact capture hash')
        if context.get('kind') not in ('synthetic', 'public_sample', 'private_host'):
            raise ValueError('context kind must explicitly describe the dataset')
        if not isinstance(context.get('assets'), list) or len(context['assets']) > 100:
            raise ValueError('asset inventory must be a bounded list')
        seen = set()
        for asset in context['assets']:
            if not isinstance(asset, dict): raise ValueError('invalid asset entry')
            if not isinstance(asset.get('ip'), str): raise ValueError('asset IP must be an explicit string')
            address = str(ipaddress.ip_address(asset.get('ip', '')))
            if address in seen: raise ValueError('duplicate asset address')
            seen.add(address)
            if asset.get('criticality') not in ('low', 'medium', 'high', 'critical'):
                raise ValueError('asset criticality must be explicit')
            for field in ('name', 'owner', 'business_service', 'data_classification'):
                if not isinstance(asset.get(field), str) or not asset[field].strip() or len(asset[field]) > 500:
                    raise ValueError('asset needs bounded owner/service/classification metadata')
            assets.append({**asset, 'ip': address})
    observed = {ip for flow in result['flows'] for ip in (flow['origin_ip'], flow['peer_ip'])}
    matched = [a for a in assets if a['ip'] in observed]
    checks = [
        {'question': 'Is source integrity anchored?', 'status': 'recorded', 'detail': 'Capture SHA-256, packet numbers, record offsets and frame hashes retained; acquisition authenticity remains unverified.'},
        {'question': 'Is capture coverage complete?', 'status': 'needs_review', 'detail': f"{len(result['diagnostics'])} diagnostics. No sensor uptime/drop counters, VLAN inventory or complete observation-window guarantee."},
        {'question': 'Is business ownership known?', 'status': 'supplied_context' if matched else 'missing', 'detail': 'Inventory is analyst-supplied context, not discovered or authenticated ownership.'},
        {'question': 'Can endpoint identity be investigated?', 'status': 'candidate_pivots' if result.get('endpoint_pivots', {}).get('pivots') else 'missing', 'detail': 'Tuple/time candidates require source approval, clock/NAT checks and process creation evidence.'},
        {'question': 'Is intent/authorization established?', 'status': 'missing', 'detail': 'No remote reputation lookup or inferred authorization. Request change approval, destination ownership and process/file evidence.'},
        {'question': 'Are response permissions established?', 'status': 'missing', 'detail': 'No isolation, firewall block, account disable or other response action is executed.'}
    ]
    priorities = []
    by_id = {f['id']: f for f in result['flows']}
    for index, lead in enumerate(result['leads'], 1):
        flow_ids = lead.get('flow_ids', [lead.get('flow_id')])
        ips = {ip for fid in flow_ids if fid in by_id for ip in (by_id[fid]['origin_ip'], by_id[fid]['peer_ip'])}
        relevant = [a for a in matched if a['ip'] in ips]
        urgent = any(a['criticality'] in ('high', 'critical') for a in relevant)
        priorities.append({'lead_number': index, 'rule': lead['id'], 'priority': 'review_first' if urgent else 'context_needed',
                           'assets': [a['name'] for a in relevant], 'basis': 'Observed heuristic plus declared business criticality; not confidence or incident severity.'})
    actions = [
        {'proposal': 'Preserve capture, endpoint logs and independently retained hashes', 'owner': 'Analyst / evidence custodian', 'approval': 'Confirm retention and data handling policy', 'impact': 'Storage and privacy obligations', 'rollback': 'Do not delete original evidence during investigation', 'verification': 'Reopen original files; verify hashes and collection time coverage'},
        {'proposal': 'Validate destination ownership and expected application behavior', 'owner': 'Asset/application owner', 'approval': 'Confirm authorized contact and change records', 'impact': 'Business-owner review effort', 'rollback': 'Correct unsupported assumptions in an append-only clarification', 'verification': 'Obtain approval identifiers, script/file hashes and endpoint pivots'},
        {'proposal': 'Consider scoped network restriction only after authorization', 'owner': 'Incident lead / network administrator', 'approval': 'Named approver and approved scope required before execution', 'impact': 'Possible backup, monitoring or application outage', 'rollback': 'Record existing configuration and tested restoration procedure', 'verification': 'Confirm approved traffic restriction, retained telemetry and service recovery'}
    ]
    return {'dataset_kind': context['kind'] if context else 'unspecified', 'matched_assets': matched,
            'unmapped_observed_ips': sorted(observed - {a['ip'] for a in matched}), 'checks': checks,
            'priorities': priorities, 'response_proposals': actions, 'verdict': 'unassessed',
            'note': 'Readiness checks and proposed actions are decision aids. No incident classification or response execution is implied.'}


def render_html(result):
    # Embedded evidence is inert JSON. Escape script-closing markup and render only textContent.
    payload = json.dumps(result, ensure_ascii=True).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    return TEMPLATE.replace('DATA_PLACEHOLDER', payload)


TEMPLATE = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>SOC Lab · Network investigation</title><style>
:root{color-scheme:dark;--bg:#0b1220;--panel:#131e30;--line:#2a3952;--muted:#a7b9d2;--accent:#72e3c5}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#edf3fb;font:15px/1.6 system-ui,sans-serif}main{max-width:1400px;margin:auto;padding:30px}h1{font-size:36px;line-height:1.15;margin:10px 0}h2{font-size:20px;margin:0 0 12px}h3{font-size:16px}p{color:var(--muted)}.eyebrow{color:var(--accent);font:12px monospace;letter-spacing:2px}.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:25px 0}.card,section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px}.card strong{display:block;font-size:28px;color:var(--accent)}.card span{color:var(--muted)}nav{display:flex;gap:8px;flex-wrap:wrap;margin:22px 0}button,input{font:inherit;border:1px solid var(--line);background:#192940;color:#edf3fb;border-radius:7px;padding:9px 13px}button{cursor:pointer}button.active{border-color:var(--accent);color:var(--accent)}input{width:100%;margin-bottom:16px}.split{display:grid;grid-template-columns:1fr 1fr;gap:18px}.scroll{overflow:auto;max-height:620px}table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:var(--muted)}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.7 ui-monospace,monospace;background:#0c1524;padding:16px;border-radius:8px}.tag{color:var(--accent);font:12px monospace}.notice{border-left:3px solid #e5b965;padding:12px 18px;background:#1f2530}.item{border-top:1px solid var(--line);padding:14px 0}.small{font-size:12px}a{color:var(--accent)}[hidden]{display:none!important}@media(max-width:850px){main{padding:18px}.stats{grid-template-columns:repeat(2,1fr)}.split{grid-template-columns:1fr}h1{font-size:28px}}@media print{body{background:white;color:black}nav,input{display:none}section,.card{background:white;border-color:#aaa}pre{background:#eee;color:black}.scroll{max-height:none}p,th{color:#333}}
</style></head><body><main>
<div class="eyebrow">SOC INVESTIGATION LAB / NETWORK EVIDENCE</div><h1>Follow the packets. Challenge the conclusion.</h1>
<p>DNS · TCP reconstruction · HTTP · TLS metadata · endpoint candidates · business context</p>
<div class="notice" id="boundary"></div><div class="stats" id="stats"></div>
<p class="small" id="source"></p><nav id="nav"></nav>
<div id="overview" class="view"><div class="split"><section><h2>Review leads</h2><div id="leads"></div></section><section><h2>Evidence readiness</h2><div id="checks"></div></section></div></div>
<div id="flows" class="view" hidden><div class="split"><section><h2>Connection explorer</h2><input id="flowSearch" aria-label="Search connections" placeholder="Filter by IP, port, protocol, host or URI"><div class="scroll" id="flowList"></div></section><section><h2>Selected connection</h2><pre id="flowDetail">Select a connection.</pre></section></div></div>
<div id="dns" class="view" hidden><section><h2>DNS questions and answers</h2><div id="dnsList" class="scroll"></div><h3>Response associations</h3><pre id="transactions"></pre><h3>DNS → connection candidates</h3><pre id="dnsConnections"></pre></section></div>
<div id="packets" class="view" hidden><div class="split"><section><h2>Packet anchors</h2><input id="packetSearch" aria-label="Search packets" placeholder="Packet number, address or flow ID"><div id="packetList" class="scroll"></div><p class="small">First 500 matching anchors shown. Complete inventory remains in network.json. Original bytes require the separately retained PCAP.</p></section><section><h2>Selected original-frame reference</h2><pre id="packetDetail">Select a packet anchor.</pre></section></div></div>
<div id="context" class="view" hidden><section><h2>Declared asset context and endpoint candidates</h2><pre id="assets"></pre><h3>Approved endpoint scope</h3><pre id="pivots"></pre><h3>Review priority</h3><pre id="priorities"></pre><h3>Response proposals — not executed</h3><div id="actions"></div></section></div>
<div id="gaps" class="view" hidden><section><h2>Coverage and parsing gaps</h2><pre id="diagnostics"></pre><h3>Interpretation limits</h3><div id="limits"></div></section></div>
<p class="small">Offline artifact. No external resources, IOC resolution, endpoint commands or containment. Source integrity is relative to retained hashes.</p>
</main><script id="evidence" type="application/json">DATA_PLACEHOLDER</script><script>
'use strict';const d=JSON.parse(document.getElementById('evidence').textContent);const el=id=>document.getElementById(id);const text=(id,v)=>el(id).textContent=v;const pretty=v=>JSON.stringify(v,null,2);const node=(tag,value,cls)=>{const n=document.createElement(tag);if(value!==undefined)n.textContent=value;if(cls)n.className=cls;return n};
text('boundary',`Dataset: ${d.readiness.dataset_kind}. Verdict: ${d.readiness.verdict}. Every heuristic needs analyst review; expected backups, telemetry and health checks can produce the same observables.`);
text('source',`${d.source.filename} · ${d.source.bytes} bytes · SHA-256 ${d.source.sha256}`);
for(const [label,value] of [['Packets',d.summary.packets],['Connections',d.summary.flows],['DNS messages',d.summary.dns_messages],['HTTP requests',d.summary.http_requests],['Review leads',d.leads.length]]){const c=node('div',undefined,'card');c.append(node('strong',value),node('span',label));el('stats').append(c)}
for(const [id,label] of [['overview','Assessment'],['flows','Connections'],['dns','DNS'],['packets','Packet anchors'],['context','Context & response'],['gaps','Coverage gaps']]){const b=node('button',label,id==='overview'?'active':'');b.onclick=()=>{document.querySelectorAll('.view').forEach(v=>v.hidden=v.id!==id);el('nav').querySelectorAll('button').forEach(x=>x.classList.remove('active'));b.classList.add('active')};el('nav').append(b)}
for(const lead of d.leads){const c=node('div',undefined,'item');c.append(node('div',lead.id,'tag'),node('h3',lead.title),node('pre',pretty(lead)));el('leads').append(c)}if(!d.leads.length)el('leads').append(node('p','No selected heuristic matched. Assess coverage; this is not a benign verdict.'));
for(const check of d.readiness.checks){const c=node('div',undefined,'item');c.append(node('div',check.status,'tag'),node('h3',check.question),node('p',check.detail));el('checks').append(c)}
function table(rows,headers,choose){const t=node('table'),h=node('tr');headers.forEach(x=>h.append(node('th',x)));t.append(h);rows.forEach(([values,data])=>{const tr=node('tr');values.forEach((v,i)=>{const td=node('td');if(i===0&&choose){const b=node('button',v);b.onclick=()=>choose(data);td.append(b)}else td.textContent=v;tr.append(td)});t.append(tr)});return t}
function flowList(){const q=el('flowSearch').value.toLowerCase();const rows=d.flows.filter(f=>pretty(f).toLowerCase().includes(q)).slice(0,200).map(f=>[[f.id.slice(0,8),f.protocol,`${f.origin_ip}:${f.origin_port}`,`${f.peer_ip}:${f.peer_port}`,f.packets.length],f]);el('flowList').replaceChildren(table(rows,['Flow','Protocol','First source','First destination','Packets'],f=>text('flowDetail',pretty(f))))}el('flowSearch').oninput=flowList;flowList();
function packetList(){const q=el('packetSearch').value.toLowerCase();const rows=d.packets.filter(p=>pretty(p).toLowerCase().includes(q)).slice(0,500).map(p=>[[p.packet_number,p.timestamp,p.protocol||'unsupported',p.source_ip||'',p.destination_ip||''],p]);el('packetList').replaceChildren(table(rows,['Packet','UTC time','Protocol','Source','Destination'],p=>text('packetDetail',pretty(p))))}el('packetSearch').oninput=packetList;packetList();
for(const m of d.dns){const details=node('details',undefined,'item');details.append(node('summary',`Packet ${m.packet_number} · ${m.response?'response':'query'} · rcode ${m.rcode} · ${m.questions.map(q=>q.name).join(', ')}`),node('pre',pretty(m)));el('dnsList').append(details)}
text('transactions',pretty(d.dns_transactions));text('dnsConnections',pretty(d.dns_connection_candidates));text('assets',pretty({assets:d.readiness.matched_assets,unmapped_ips:d.readiness.unmapped_observed_ips}));text('pivots',pretty(d.endpoint_pivots||{status:'No endpoint scope supplied; attribution unavailable.'}));text('priorities',pretty(d.readiness.priorities));text('diagnostics',pretty(d.diagnostics));for(const limit of d.limits)el('limits').append(node('p',limit));for(const action of d.readiness.response_proposals){const c=node('div',undefined,'item');c.append(node('h3',action.proposal),node('pre',pretty(action)));el('actions').append(c)}
</script></body></html>'''
