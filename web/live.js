"use strict";
let csrf="",selected=null,selectionRequest=0,busy=false;
let lastMetrics="",lastRuns="",lastAlerts="",refreshing=false;
const $=id=>document.getElementById(id);
const node=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;};
const when=value=>new Date(value*1000).toLocaleString();
function message(text,error=false){$("message").textContent=text;$("message").className=error?"error":"";}
async function api(path,data){const response=await fetch(path,data===undefined?{}:{method:"POST",headers:{"Content-Type":"application/json","X-SOC-CSRF":csrf},body:JSON.stringify(data)});const result=await response.json();if(!response.ok)throw new Error(result.error||"Request failed");return result;}
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    const state = await api("/api/status");
    csrf = state.csrf;
    const values = [
      ["RETAINED EVENTS", state.events],
      ["DELIVERY BACKLOG", (state.queue.pending || 0) + (state.queue.sending || 0) + (state.queue.dead_letter || 0)],
      ["PRIVATE / HELD", state.queue.held_private || 0],
      ["OPEN ALERTS", Object.entries(state.alerts).filter(([key]) => key !== "closed").reduce((sum, [, value]) => sum + value, 0)],
      ["PAST REVIEW TARGET", state.overdue_alerts]
    ];
    const metricSignature = JSON.stringify(values);
    if (metricSignature !== lastMetrics) {
      lastMetrics = metricSignature;
      const cards = values.map(([title, value]) => {
        const card = node("div", undefined, "metric");
        card.append(node("small", title), node("strong", String(value)));
        return card;
      });
      $("metrics").replaceChildren(...cards);
    }
    $("health").textContent = `${state.queue.delivered || 0} records delivered · ${state.queue.dead_letter || 0} dead-letter records retained · ${state.duplicates} duplicate observations skipped · oldest pending ${Math.round(state.oldest_pending_seconds)}s · ${Math.round(state.database_bytes / 1024)} KiB database/WAL. Private evidence remains local.`;
    const runSignature = JSON.stringify([state.collectors, state.detection_runs]);
    if (runSignature !== lastRuns) {
      lastRuns = runSignature;
      const rows = [];
      for (const collector of state.collectors) {
        rows.push(node("p", `${collector.scope} · record cursor ${collector.cursor.record_id} · ${collector.gap_count} detected gaps/resets · ${collector.health} · last attempt ${Math.round(collector.seconds_since_attempt)}s ago · ${collector.last_error || "read succeeded"}`, "run"));
      }
      for (const run of state.detection_runs.slice(0, 5)) {
        rows.push(node("p", `${when(run.at)} · ${run.scope} · ${run.inspected} inspected · ${run.inserted} new leads · policy ${run.rule_sha256.slice(0, 12)}`, "run"));
      }
      $("runs").replaceChildren(...rows);
    }
    const filter = $("filter").value;
    const alerts = await api("/api/alerts" + (filter ? "?state=" + encodeURIComponent(filter) : ""));
    if (filter !== $("filter").value) return;
    const alertSignature = JSON.stringify([filter, selected?.id, alerts]);
    if (alertSignature !== lastAlerts) {
      lastAlerts = alertSignature;
      const rows = alerts.map(alert => {
        const button = node("button", undefined, "alert" + (selected?.id === alert.id ? " active" : ""));
        button.append(
          node("span", alert.kind === "synthetic" ? "synthetic exercise" : "private host", "tag " + (alert.kind === "synthetic" ? "synthetic" : "")),
          node("span", alert.severity, "tag"),
          node("strong", alert.finding.title),
          node("small", `${alert.rule_id} · ${alert.state} · ${alert.owner || "unassigned"} · r${alert.revision}`),
          node("small", `Review target ${when(alert.due)}`)
        );
        button.addEventListener("click", () => load(alert.id));
        return button;
      });
      $("alerts").replaceChildren(...rows);
      $("empty").textContent = alerts.length ? "" : "No alerts in this view. Collection health and telemetry coverage still need checking.";
    }
  } catch (error) {
    message(error.message, true);
  } finally {
    refreshing = false;
  }
}
async function load(id){const request=++selectionRequest;selected=null;$("controls").hidden=true;$("download").replaceChildren();$("raw").hidden=true;$("selection").textContent="Loading the selected audited alert…";try{const detail=await api("/api/alert?id="+encodeURIComponent(id));if(request!==selectionRequest)return;selected=detail.alert;const a=selected;$("selection").textContent=`${a.scope} · ${a.kind} · ${a.state} · revision ${a.revision} · ${a.finding.evidence.length} anchored records${a.verdict ? " · verdict " + a.verdict : ""}`;$("finding").replaceChildren(node("h3",a.finding.title),node("p",a.finding.reason),node("p",`ATT&CK: ${a.finding.attack.join(", ")}`,"muted"),node("p",`Alternative explanations: ${a.finding.false_positives.join("; ")}`,"muted"));$("owner").value=a.owner||"";$("verdict").value=a.verdict||"insufficient_evidence";$("verdict").disabled=a.state==="closed";$("target").disabled=a.state==="closed";$("owner").disabled=a.state==="closed";$("review").querySelector("button[type=submit]").disabled=a.state==="closed";$("reason").value="";$("target").value="";$("controls").hidden=false;$("promote").textContent=a.case_id?"Case linked":"Open anchored case";$("promote").disabled=!!a.case_id;$("export").disabled=!a.case_id;$("evidence").replaceChildren();for(const e of a.finding.evidence){const button=node("button",`${e.timestamp} · ${e.host} · ${e.event_id} / record ${e.record_id}\nUID ${e.event_uid}`,"record");button.addEventListener("click",async()=>{try{const original=await api("/api/event?uid="+e.event_uid);if(selected?.id!==id)return;$("raw").hidden=false;$("raw").textContent=JSON.stringify(original,null,2);}catch(err){message(err.message,true);}});$("evidence").append(button);}$("audit").replaceChildren(node("p",`Retain this audit anchor independently: ${detail.anchor_sha256}`,"hash"));for(const entry of detail.audit){const p=entry.payload;const note=node("div",undefined,"note");note.append(node("strong",`${entry.sequence}. ${p.action} → ${p.snapshot.state}`),node("p",p.reason),node("small",`${p.actor} · ${when(p.at)}`));$("audit").append(note);}refresh();}catch(e){message(e.message,true);}}
async function act(path,extra={}){if(!selected||busy)return;const id=selected.id;busy=true;try{const result=await api(path,{id,revision:selected.revision,actor:$("actor").value,reason:$("reason").value,...extra});if(selected?.id!==id)return;await load(id);message("Saved. The audited revision is retained.");return result;}catch(e){message(e.message,true);}finally{busy=false;}}
$("filter").addEventListener("change",refresh);$("reload").addEventListener("click",()=>selected&&load(selected.id));
$("review").addEventListener("submit",e=>{e.preventDefault();act("/api/review",{owner:$("owner").value||null,target:$("target").value||null,verdict:$("verdict").value});});
$("promote").addEventListener("click",()=>act("/api/promote"));
$("export").addEventListener("click",async()=>{if(!selected||busy)return;const id=selected.id;busy=true;try{const result=await api("/api/export",{id});if(selected?.id!==id)return;const link=node("a","Download reviewed case packet");link.href="/api/download?file="+encodeURIComponent(result.file);$("download").replaceChildren(link,node("p",`ZIP SHA-256 ${result.sha256}`,"hash"));message("Complete packet ready. Keep its digest and audit anchor independently.");}catch(e){message(e.message,true);}finally{busy=false;}});
refresh();setInterval(refresh,5000);
