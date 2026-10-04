"use strict";
let operations = {csrf:null, selected:null};
async function opPost(action, data) {
  const response = await fetch('/api/operations/'+action, {method:'POST',headers:{'Content-Type':'application/json','X-SOC-CSRF':operations.csrf},body:JSON.stringify(data)});
  const result = await response.json(); if (!response.ok) throw Error(result.error || response.statusText); return result;
}
async function selectOperation(id) {
  const result = await api('/api/operations/case?'+new URLSearchParams({id})); operations.selected=result.case;
  $('op-selected').textContent=result.case.title+' · '+result.case.status+' · revision '+result.case.revision+' · '+result.case.evidence.length+' anchored records';
  $('op-anchor').textContent='SHA-256 '+result.anchor_sha256+' · '+result.integrity;
  $('op-history').replaceChildren();
  for (const entry of result.audit) {
    const p=entry.payload, box=el('div',undefined,'decision-entry');
    box.append(el('strong',p.sequence+'. '+p.action+' → '+p.snapshot.status),el('small',p.at+' · '+p.actor),el('p',p.rationale)); $('op-history').append(box);
  }
}
async function loadOperations() {
  const data=await api('/api/operations');operations.csrf=data.csrf;
  $('workspace-mode').textContent=data.enabled?'Local decision workspace enabled. Evidence databases stay read-only. Actor labels are self-declared; retain exports independently.':'Read-only mode. Start with --operations-db output/operations/cases.sqlite to record analyst decisions.';
  $('sidebar-mode').textContent=data.enabled?' LOCAL · CASE WORKSPACE':' LOCAL · READ ONLY';
  document.querySelectorAll('#operations-view input, #operations-view textarea, #operations-view button, #operations-view select').forEach(n=>{n.disabled=!data.enabled;});
  $('case-board').replaceChildren();
  for (const status of ['new','triaged','investigating','escalated','closed']) {
    const col=el('div',undefined,'board-column');col.append(el('h4',status.toUpperCase()));
    for (const c of data.cases.filter(c=>c.status===status)) {const button=el('button');button.append(el('strong',c.title),el('small',c.source_case+' · '+c.severity+' · r'+c.revision));button.addEventListener('click',()=>selectOperation(c.id).catch(error));col.append(button);}
    $('case-board').append(col);
  }
  if (operations.selected) await selectOperation(operations.selected.id);
  else if(data.cases.length) await selectOperation(data.cases[0].id);
}
$('open-case').addEventListener('submit', async event=>{
  event.preventDefault();try {
    const chain=graphData?.chains[0];
    const uids=selectedEvidence.size?[...selectedEvidence]:[...new Set(chain?.stages.flatMap(s=>s.evidence.map(e=>e.event_uid))||[])];
    if(!uids.length) throw Error('Select evidence records in Event timeline before opening this case.');
    const result=await opPost('create',{source_case:state.selected.id,uids,title:$('op-title').value,actor:$('op-actor').value,rationale:$('op-create-reason').value});
    operations.selected=result;await loadOperations();
  } catch(err){error(err);}
});
$('update-case').addEventListener('submit',async event=>{
  event.preventDefault();try {
    const c=operations.selected;if(!c) throw Error('Select an operations case first.');
    const action=$('op-action').value;
    await opPost('update',{id:c.id,revision:c.revision,action:['note','attach'].includes(action)?action:'transition',target:['note','attach'].includes(action)?null:action,verdict:action==='closed'?$('op-verdict').value:null,actor:$('op-actor').value,rationale:$('op-reason').value,source_case:state.selected.id,uids:[...selectedEvidence]});
    $('op-reason').value='';await loadOperations();
  } catch(err){error(err);}
});
$('op-export').addEventListener('click',async()=>{try {
  if(!operations.selected) throw Error('Select an operations case first.');
  const result=await opPost('export',{id:operations.selected.id});const a=el('a','Download reviewed bundle');a.href='/api/operations/download?'+new URLSearchParams({file:result.file});a.download=result.file;
  $('op-export-result').replaceChildren(a,el('p','ZIP SHA-256 '+result.sha256,'muted'));
}catch(err){error(err);}});
