"use strict";
let graphData = null, detailRequest = 0;
const shortImage = image => image.replaceAll('/', '\\').split('\\').pop();
function svgEl(tag, attrs, text) {
  const n = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k,v] of Object.entries(attrs || {})) n.setAttribute(k,String(v));
  if (text !== undefined) n.textContent=text;
  return n;
}
async function inspectOriginal(uid) {
  const id=state.selected.id, request=++detailRequest;
  const record=await api('/api/event?'+new URLSearchParams({case:id,uid}));
  if (id!==state.selected.id || request!==detailRequest) return;
  const box=$('node-detail');box.replaceChildren(el('h3','Original evidence · line '+record.source_line));
  box.append(el('p','SHA-256 '+record.source_sha256),el('pre',JSON.stringify(record.original,null,2)));
}
function evidenceButton(ref) {
  const b=el('button','Record '+ref.record_id+' / line '+ref.source_line,'evidence-button');
  b.addEventListener('click',()=>inspectOriginal(ref.event_uid).catch(error));return b;
}
function inspectNode(node) {
  ++detailRequest; const box=$('node-detail');box.replaceChildren(el('h3',shortImage(node.image)));
  box.append(el('p',node.host+' · '+node.user+' · '+node.timestamp),el('code',node.command,'raw-preview'),el('p','ProcessGuid '+node.guid));
  for (const ref of node.evidence) box.append(evidenceButton(ref));
  if (node.activity.length) {
    box.append(el('h4','Process-linked activity'));
    for(const a of node.activity) {
      const d=el('details');d.append(el('summary','Event '+a.evidence.event_id+' · '+a.evidence.timestamp),el('pre',JSON.stringify(a.fields,null,2)),evidenceButton(a.evidence));box.append(d);
    }
  }
}
function renderGraph(data) {
  ++detailRequest;graphData=data;$('chain-leads').replaceChildren();$('telemetry').replaceChildren();$('diagnostics').replaceChildren();$('process-graph').replaceChildren();
  $('node-detail').replaceChildren(el('p','Select a process node or a stage evidence record.'));
  if (!data) { $('chain-leads').append(el('p','Build advanced artifacts to inspect source-scoped reconstruction.'));return; }
  const description=el('p',data.raw_events.toLocaleString()+' raw events · '+data.unique_observations.toLocaleString()+' unique observations · '+data.duplicate_observations+' duplicate observations retained in original storage.','muted');$('chain-leads').append(description);
  if (!data.chains.length) $('chain-leads').append(el('p','No complete five-stage chain. Missing telemetry or a different pattern can prevent correlation; inspect the evidence and candidates below.','collection-note'));
  for(const chain of data.chains) {
    const card=el('article',undefined,'chain-card');card.append(el('div','CHAIN-001 / NEEDS REVIEW','eyebrow'),el('h3',chain.title),el('p',chain.host+' · '+chain.user));
    const stages=el('div',undefined,'chain-stages');
    chain.stages.forEach((stage,i)=>{const s=el('div',undefined,'chain-stage');s.append(el('small','0'+(i+1)),el('h4',stage.name));for(const ref of stage.evidence)s.append(evidenceButton(ref));stages.append(s);});
    card.append(stages);
    const explain=el('details');explain.append(el('summary','Why these records join / what this does not prove'));
    for(const basis of chain.join_basis)explain.append(el('p',basis));for(const limit of chain.limitations)explain.append(el('p',limit));card.append(explain);$('chain-leads').append(card);
  }
  for(const t of data.telemetry){const b=el('div',undefined,'telemetry-item '+(t.count?'present':'missing'));b.append(el('strong',String(t.count)),el('span',t.name),el('small','Event '+t.event_id));$('telemetry').append(b);}
  const svg=$('process-graph'), nodes=data.nodes.slice(0,100), included=new Set(nodes.map(n=>n.id));
  const parent=new Map(data.edges.map(e=>[e.to,e.from])), positions=new Map(), rows=new Map();
  function depth(id,seen=new Set()){if(seen.has(id)||!parent.has(id))return 0;seen.add(id);return 1+depth(parent.get(id),seen);}
  for(const node of nodes){const col=depth(node.id);const row=rows.get(col)||0;rows.set(col,row+1);positions.set(node.id,{x:24+col*270,y:30+row*110});}
  const width=Math.max(860, ...Array.from(positions.values(),p=>p.x+250)), height=Math.max(190,...Array.from(positions.values(),p=>p.y+125));
  svg.setAttribute('viewBox','0 0 '+width+' '+height);svg.setAttribute('width',String(width));svg.setAttribute('height',String(height));
  const defs=svgEl('defs'),marker=svgEl('marker',{id:'arrow',markerWidth:8,markerHeight:8,refX:7,refY:4,orient:'auto'});marker.append(svgEl('path',{d:'M0,0 L8,4 L0,8',fill:'#8b9caf'}));defs.append(marker);svg.append(defs);
  for(const edge of data.edges){if(!included.has(edge.from)||!included.has(edge.to))continue;const a=positions.get(edge.from),b=positions.get(edge.to);svg.append(svgEl('path',{d:`M${a.x+230},${a.y+42} C${a.x+252},${a.y+42} ${b.x-24},${b.y+42} ${b.x},${b.y+42}`,fill:'none',stroke:'#708395','stroke-width':1.6,'marker-end':'url(#arrow)'}));}
  for(const node of nodes){const p=positions.get(node.id),g=svgEl('g',{role:'button',tabindex:0,'aria-label':'Inspect process '+shortImage(node.image),class:'process-node'});g.append(svgEl('rect',{x:p.x,y:p.y,width:230,height:84,rx:8,fill:node.risk_marker?'#30291e':'#1c242d',stroke:node.risk_marker?'#edbd75':'#536477'}));g.append(svgEl('text',{x:p.x+14,y:p.y+26,fill:'#edf0f3','font-size':14},shortImage(node.image).slice(0,28)));g.append(svgEl('text',{x:p.x+14,y:p.y+46,fill:'#a6b5c3','font-size':10},node.user.slice(0,33)));g.append(svgEl('text',{x:p.x+14,y:p.y+65,fill:node.risk_marker?'#edbd75':'#a6b5c3','font-size':10},node.risk_marker?'RISK MARKER · '+node.activity.length+' activity records':node.activity.length+' process activity records'));g.addEventListener('click',()=>inspectNode(node));g.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();inspectNode(node);}});svg.append(g);}
  if(!nodes.length)svg.append(svgEl('text',{x:24,y:60,fill:'#94a0ad','font-size':13},'No unambiguous Sysmon process-creation nodes in this collection.'));
  $('diagnostic-count').textContent='Collection diagnostics · '+data.diagnostics.length+' · '+data.candidates.filter(c=>!c.complete).length+' incomplete candidates';
  for(const candidate of data.candidates.filter(c=>!c.complete)){const d=el('div',undefined,'candidate');d.append(el('h4',candidate.failure_count+' failures + matching success'),evidenceButton(candidate.success),el('p','Missing: '+candidate.missing.join('; ')));$('diagnostics').append(d);}
  for(const d of data.diagnostics.slice(0,40))$('diagnostics').append(el('pre',JSON.stringify(d,null,2)));
  if(data.diagnostics.length>40)$('diagnostics').append(el('p','First 40 diagnostics shown. Full artifact retains all '+data.diagnostics.length+'.'));
  if(data.nodes.length>100)$('diagnostics').append(el('p','Graph shows the first 100 of '+data.nodes.length+' process nodes; full artifact retains all nodes.'));
}
function renderEvaluation(data) {
  $('evaluation-scope').textContent=data.scope+' '+data.selection+' '+data.baseline_description;
  $('evaluation-metrics').replaceChildren();$('evaluation-rows').replaceChildren();
  const percent=x=>x===null?'undefined':(x*100).toFixed(1)+'%';
  for(const split of ['dev','holdout'])for(const engine of ['identity_graph','temporal_baseline']){
    const m=data.metrics[split][engine],card=el('article',undefined,'evaluation-card');
    card.append(el('div',split.toUpperCase()+' / '+engine.replaceAll('_',' '),'eyebrow'),el('h3','Precision '+percent(m.precision)+' · Recall '+percent(m.recall)),el('p','TP '+m.tp+' · FP '+m.fp+' · TN '+m.tn+' · FN '+m.fn+' · F1 '+percent(m.f1)));$('evaluation-metrics').append(card);
  }
  for(const r of data.rows){const tr=el('tr'),a=el('td',r.id+' / '+r.split);a.append(el('small',r.variant));const result=el('td',r.predicted_review?'REVIEW':'NO FULL CHAIN');result.className=r.expected_review!==r.predicted_review?'evaluation-miss':'evaluation-hit';const why=el('td',r.rationale);why.append(el('small',r.missing.flat().join('; ')));tr.append(a,el('td',r.expected_review?'Requires review':'Known benign / unrelated'),result,el('td',r.temporal_baseline?'REVIEW':'NO MATCH'),why);$('evaluation-rows').append(tr);}
}
