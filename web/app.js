"use strict";
let state = { cases: [], selected: null, view: 'findings' };
let caseRequest = 0, eventRequest = 0;
let selectedEvidence = new Set();
const $ = id => document.getElementById(id);
function el(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
async function api(path) { const response = await fetch(path); const result = await response.json(); if (!response.ok) throw Error(result.error || response.statusText); return result; }
function error(err) { $('error').textContent = err.message; $('error').classList.remove('hidden'); }
function showView(view) { state.view = view; for (const name of ['findings','events','report','graph','evaluation','operations','hunts']) $(name+'-view').classList.toggle('hidden', name !== view); document.querySelectorAll('[data-view]').forEach(b => { b.classList.toggle('active', b.dataset.view === view); b.setAttribute('aria-selected', String(b.dataset.view === view)); }); }
function metric(label, number, hint) { const box = el('div', undefined, 'metric'); box.append(el('small', label), el('strong', number.toLocaleString()), el('span', hint)); return box; }
function renderFindings(findings) {
  $('findings').replaceChildren();
  if (!findings.length) { $('findings').append(el('p', 'No matches. Check telemetry and collection gaps before concluding activity was safe.')); return; }
  for (const f of findings) {
    const card = el('article', undefined, 'finding'), head = el('div', undefined, 'finding-head');
    head.append(el('span', f.rule_id, 'rule-id'), el('h4', f.title), el('span', f.status === 'context_allowlisted' ? 'CONTEXT ALLOWLISTED · RETAINED' : 'NEEDS REVIEW', 'state'));
    card.append(head, el('p', f.reason));
    const first = f.evidence[0], row = el('div', undefined, 'evidence-row');
    row.append(el('span', first.host), el('b', first.timestamp), el('span', f.evidence.length+' evidence record(s)'), el('span', f.attack.join(' · ')));
    card.append(row);
    const selectedKeys = ['Image','CommandLine','ParentImage','User','TargetUserName','IpAddress','LogonType','ScriptBlockText'];
    const preview = Object.fromEntries(selectedKeys.filter(k=>first.event_data[k]).map(k=>[k,first.event_data[k]]));
    const raw = el('code', JSON.stringify(preview, null, 2), 'raw-preview'); card.append(raw);
    const details = el('details'); details.append(el('summary', 'Evidence references & limitations'));
    for (const e of f.evidence) details.append(el('p', 'Record '+e.record_id+' · source line '+e.source_line+' · SHA-256 '+e.source_sha256));
    details.append(el('code',JSON.stringify(first.event_data,null,2),'raw-preview'));
    for (const limit of f.limitations) details.append(el('p', limit));
    if (f.context) details.append(el('p', f.context.reason+' '+f.context.caution));
    card.append(details); $('findings').append(card);
  }
}
async function loadEvents() {
  const id = state.selected.id, request = ++eventRequest;
  const params = new URLSearchParams({case:id,limit:'50'});
  if ($('term').value) params.set('term',$('term').value);
  if ($('event-id').value) params.set('event_id',$('event-id').value);
  const events = await api('/api/events?'+params);
  if (request !== eventRequest || id !== state.selected.id) return;
  $('events').replaceChildren();
  $('event-count').textContent = events.length+' records shown (up to 50) · all timestamps use System/TimeCreated in UTC · search includes non-alerting events';
  for (const e of events) {
    const row = el('tr'), time = el('td', e.timestamp), host = el('td', e.host), kind = el('td', String(e.event_id)), fields = el('td');
    const select=el('td'),check=el('input');check.type='checkbox';check.checked=selectedEvidence.has(e.event_uid);check.setAttribute('aria-label','Select record '+e.record_id+' as case evidence');check.addEventListener('change',()=>{if(check.checked)selectedEvidence.add(e.event_uid);else selectedEvidence.delete(e.event_uid);$('selected-anchor-count').textContent=selectedEvidence.size+' timeline record(s) selected in '+state.selected.id;});select.append(check);
    time.append(el('small','Record '+e.record_id+' · line '+e.source_line)); host.append(el('small',e.channel));
    const d = e.event_data;
    const keys = ['Image','CommandLine','User','TargetUserName','IpAddress','LogonType','SubStatus','TaskName','ScriptBlockText','DestinationIp','DestinationPort'];
    let text = keys.filter(k=>d[k]).map(k=>k+': '+d[k]).join('\n');
    if (!text) text = JSON.stringify(d);
    fields.append(el('code',text)); row.append(select,time,host,kind,fields); $('events').append(row);
  }
}
async function selectCase(id) {
  const request = ++caseRequest; ++eventRequest;
  ++detailRequest;
  state.selected = state.cases.find(c => c.id === id); const c=state.selected;
  selectedEvidence.clear();$('selected-anchor-count').textContent='No timeline records selected in '+id+'.';
  $('findings').replaceChildren(el('p','Loading this case’s evidence…')); $('events').replaceChildren(); $('report').textContent='Loading this case’s report…';
  renderGraph(null);
  document.querySelectorAll('#case-nav button').forEach(b=>b.classList.toggle('selected',b.dataset.case===id));
  $('case-kind').textContent=c.id.toUpperCase()+' / '+c.kind.toUpperCase(); $('case-title').textContent=c.title; $('verdict').textContent=c.verdict;
  $('case-summary').textContent=c.manifest.event_count.toLocaleString()+' events · '+c.manifest.finding_count+' findings · source hashes recorded · analyst assessment separate from detector output';
  $('source-note').textContent='Analysis '+state.runId+' · '+c.kind+' · '+c.manifest.sources.length+' source file(s)';
  $('term').value=''; $('event-id').value='';
  $('hunt-results').replaceChildren(el('p','Running scoped read-only hunts…'));
  const [findings, report, graph, hunts] = await Promise.all([api('/api/findings?case='+id),api('/api/report?case='+id),api('/api/investigation?case='+id).catch(()=>null),api('/api/hunts?case='+id)]);
  if (request !== caseRequest || id !== state.selected.id) return;
  renderFindings(findings);renderGraph(graph); $('report').textContent=report.markdown; await loadEvents();
  if (request === caseRequest && id === state.selected.id) renderHunts(hunts);
}
async function init() {
  const data = await api('/api/cases'); state.cases=data.cases; state.runId=data.run_id;
  $('version').textContent='v'+data.version; $('run-id').textContent=data.run_id;
  const total=state.cases.reduce((a,c)=>a+c.manifest.event_count,0), leads=state.cases.reduce((a,c)=>a+c.manifest.finding_count,0);
  const publicCases=state.cases.filter(c=>c.kind==='Public EVTX').length;
  $('metrics').append(metric('CASE STUDIES',state.cases.length,publicCases+' public cases + '+(state.cases.length-publicCases)+' constructed experiments'),metric('PRIMARY EVENTS',total,'Independent datasets; supplement excluded'),metric('EVENT / AUTH LEADS',leads,'Chain leads shown separately in reconstruction'),metric('HYPOTHESES',13,'9 event + 3 auth + 1 multi-stage chain'));
  for (const [view,label] of [['graph','Reconstruction'],['evaluation','Evaluation'],['hunts','Hunt notebook'],['operations','Case operations']]){const b=el('button',label);b.dataset.view=view;b.setAttribute('role','tab');b.setAttribute('aria-selected','false');document.querySelector('.tabbar').append(b);}
  for(const c of state.cases) { const button=el('button');button.dataset.case=c.id;button.append(el('span',c.id.toUpperCase()),el('div',c.title));button.addEventListener('click',()=>selectCase(c.id).catch(error));$('case-nav').append(button); }
  document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>showView(b.dataset.view)));
  $('filters').addEventListener('submit',event=>{event.preventDefault();loadEvents().catch(error);});
  api('/api/evaluation').then(renderEvaluation).catch(err=>{$('evaluation-scope').textContent=err.message;});
  await selectCase(state.cases[0].id);
  await loadOperations();
}
init().catch(error);
function renderHunts(data) {
  $('hunt-results').replaceChildren(el('p',data.event_count.toLocaleString()+' collected events · '+data.scope,'muted'));
  for (const hunt of data.hunts) {
    const card=el('article',undefined,'finding');card.append(el('div',hunt.id,'eyebrow'),el('h3',hunt.hypothesis),el('p',hunt.returned_rows+' returned row(s) · '+hunt.assessment),el('p',hunt.caution,'muted'));
    const details=el('details');details.append(el('summary','Executed query & results'),el('pre',hunt.query),el('pre',JSON.stringify(hunt.rows,null,2)));card.append(details);$('hunt-results').append(card);
  }
}
