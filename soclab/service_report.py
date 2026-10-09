"""Giao diện và biên bản bàn giao tiếng Việt; nội dung nguồn luôn được giữ như dữ liệu."""

import json

LABELS = {'critical': 'Rất quan trọng', 'high': 'Quan trọng', 'medium': 'Trung bình', 'low': 'Thấp',
          'new': 'Mới', 'triaged': 'Đã phân loại', 'investigating': 'Đang điều tra', 'escalated': 'Đã chuyển cấp', 'closed': 'Đã đóng'}


def safe_text(value):
    # Plain-text paragraphs: prevent supplied owner/host text from creating Markdown links, HTML or headings.
    return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('[', '\\[').replace(']', '\\]').replace('`', '\\`').replace('*', '\\*').replace('_', '\\_').replace('|', '\\|')


def render_markdown(result):
    lines = ['# Biên bản sẵn sàng điều tra và bàn giao dịch vụ', '',
             f"Mốc đánh giá: {result['as_of']}. Cửa sổ event: {result['window_seconds']} giây.", '',
             f"Context SHA-256: `{result['context']['sha256']}`.", f"Snapshot SHA-256: `{result['selected_snapshot_sha256']}`.", '',
             'Kết luận: **chưa kết luận sự cố**. Đây là ảnh chụp chỉ đọc; người nhận/chủ tài sản do context khai báo, không phải người đã được xác thực hay thông báo.', '']
    for row in result['assets']:
        asset, handoff = row['asset'], row['handoff']
        lines += [f"## Tài sản: {safe_text(asset['name'])}", '', f"Dịch vụ: {safe_text(asset['business_service'])}.",
                  f"Chủ sở hữu: {safe_text(asset['owner'])}. Đầu mối điều tra: {safe_text(asset['incident_lead'])}.",
                  f"Mức quan trọng khai báo: {LABELS[asset['criticality']]}. Độ ưu tiên: {row['priority']}.", '', '### Quan sát và khoảng trống', '']
        for check in row['telemetry']:
            lines += [f"- {safe_text(check['id'])}: {check['in_window']} event trong cửa sổ; {check['observed_total']} event đúng policy trong collection."]
            for issue in check['issues']: lines.append('  - ' + issue)
            for anchor in check['anchor_samples']: lines.append(f"  - Anchor: `{anchor['event_uid']}`, source `{anchor['source_sha256']}`, dòng {anchor['source_line']}.")
        lines += ['', f"Event chưa ánh xạ policy: {row['unmatched_policy_events']}. Không tự coi chúng là độc hại hoặc hợp lệ.", '', '### Alert đang lưu', '']
        for alert in row['alerts']:
            lines.append(f"- `{alert['rule_id']}` / `{alert['id']}`: {LABELS.get(alert['state'], alert['state'])}; revision {alert['revision']}; owner {safe_text(alert['owner'] or 'chưa phân công')}; quá hạn review: {'có' if alert['overdue'] else 'không'}.")
        if not row['alerts']: lines.append('Chưa có alert liên quan trong snapshot; không chứng minh tài sản an toàn.')
        lines += ['', '### Đề xuất bàn giao', '', handoff['authority'], '']
        for proposal in handoff['proposals']:
            lines += [f"- {proposal['action']}.", f"  - Người phụ trách dự kiến: {safe_text(proposal['owner'])}.",
                      f"  - Phê duyệt: {proposal['approval']}.", f"  - Ảnh hưởng: {proposal['impact']}.",
                      f"  - Phục hồi: {proposal['rollback']}.", f"  - Xác minh: {proposal['verification']}."]
        lines.append('')
    lines += ['## Phạm vi bàn giao', '', result['scope'], '', 'Không gửi email/ticket, không thay đổi alert, không chặn mạng hoặc cô lập endpoint.']
    return '\n'.join(lines) + '\n'


def render_html(result):
    payload = json.dumps(result, ensure_ascii=True).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    return TEMPLATE.replace('DATA_PLACEHOLDER', payload)


TEMPLATE = '''<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>SOC · Sẵn sàng điều tra dịch vụ</title>
<style>
:root{color-scheme:dark;--bg:#09111e;--panel:#121e30;--line:#2c3c53;--text:#eaf2fb;--muted:#a4b8cf;--accent:#71dfbc;--warn:#f5cd81}*{box-sizing:border-box}body{margin:0;font:15px/1.65 system-ui,sans-serif;background:var(--bg);color:var(--text)}main{max-width:1380px;margin:auto;padding:30px}.eyebrow{font:12px monospace;color:var(--accent);letter-spacing:2px}h1{font-size:35px;line-height:1.25;margin:10px 0}h2{font-size:22px}h3{font-size:17px}p,.muted{color:var(--muted)}.notice{border-left:3px solid var(--warn);padding:14px 20px;background:#212a38}.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:22px 0}.stat,.panel,.asset{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}.stat strong{display:block;font-size:28px;color:var(--accent)}.stat span{color:var(--muted);font-size:13px}nav{display:flex;gap:8px;flex-wrap:wrap;margin:20px 0}button,input{font:inherit;padding:9px 13px;color:var(--text);background:#1a2a40;border:1px solid var(--line);border-radius:7px}button{cursor:pointer}.active{border-color:var(--accent);color:var(--accent)}input{width:100%;margin:12px 0 18px}.grid{display:grid;grid-template-columns:1fr 1.6fr;gap:18px}.asset{margin-bottom:12px;text-align:left;width:100%}.asset strong{display:block;font-size:17px}.tag{display:inline-block;color:var(--accent);font-size:12px;padding:2px 7px;border:1px solid var(--line);border-radius:4px}.warn{color:var(--warn)}table{border-collapse:collapse;width:100%;font-size:13px}td,th{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0a1423;border-radius:8px;padding:14px;font:12px/1.65 ui-monospace,monospace}.item{padding:12px 0;border-bottom:1px solid var(--line)}.small{font-size:12px}.scroll{overflow:auto;max-height:640px}[hidden]{display:none!important}@media(max-width:900px){main{padding:18px}.stats{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}h1{font-size:27px}}@media print{body{background:white;color:black}.panel,.stat,.asset{background:white;border-color:#aaa}nav,input{display:none}.scroll{max-height:none}p,.muted{color:#333}pre{background:#eee;color:black}}
</style></head><body><main>
<div class="eyebrow">SOC INVESTIGATION & OPERATIONS · QUẢN TRỊ TELEMETRY</div>
<h1>Sẵn sàng điều tra theo tài sản và dịch vụ</h1>
<p id="meta"></p><div class="notice">Báo cáo chỉ đọc. Độ ưu tiên dựa trên context khai báo; không phải kết luận tấn công, đánh giá toàn bộ audit policy hoặc quyền thực hiện containment.</div>
<div class="stats" id="stats"></div>
<nav aria-label="Các phần báo cáo"><button data-view="assets" class="active">Tài sản & telemetry</button><button data-view="delivery">Giao nhận & nguồn</button><button data-view="handoff">Bàn giao điều tra</button><button data-view="limits">Phạm vi & giới hạn</button></nav>
<section id="assets"><div class="grid"><div><label for="search">Tìm tài sản, dịch vụ hoặc chủ sở hữu</label><input id="search" placeholder="Tên host, dịch vụ, chủ sở hữu..."><div id="asset-list"></div></div><article class="panel" id="detail"></article></div></section>
<section id="delivery" class="panel" hidden><h2>Giao nhận và source scope đã phê duyệt</h2><div id="queue"></div><h3>Host chưa ánh xạ inventory</h3><div id="unmapped"></div><h3>Tập nguồn được duyệt</h3><pre id="sources"></pre></section>
<section id="handoff" class="panel" hidden><h2>Biên bản bàn giao theo chủ dịch vụ</h2><p>Người nhận do context khai báo. Chưa gửi thông báo hoặc thực hiện action.</p><div id="handoffs"></div></section>
<section id="limits" class="panel" hidden><h2>Tham chiếu và giới hạn kết luận</h2><pre id="boundaries"></pre></section>
<script type="application/json" id="data">DATA_PLACEHOLDER</script>
<script>
const d=JSON.parse(document.getElementById('data').textContent),$=id=>document.getElementById(id);
const label={critical:'Rất quan trọng',high:'Quan trọng',medium:'Trung bình',low:'Thấp',new:'Mới',triaged:'Đã phân loại',investigating:'Đang điều tra',escalated:'Đã chuyển cấp',closed:'Đã đóng',ưu_tiên_review:'Ưu tiên điều tra',cần_bổ_sung_telemetry:'Cần bổ sung telemetry',review_theo_hàng_đợi:'Xem xét theo hàng đợi',chưa_có_lead_đang_mở:'Chưa có lead đang mở',synthetic:'Tự dựng',private_host:'Thu nhận riêng tư',pending:'Chờ giao nhận',sending:'Đang giao nhận',delivered:'Đã giao nhận',dead_letter:'Giữ sau lỗi lặp',held_private:'Giữ riêng tư'};
function el(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n}
function obj(parent,value){parent.append(el('pre',JSON.stringify(value,null,2)))}
function table(parent,headers,rows){const t=el('table'),head=el('tr');headers.forEach(h=>head.append(el('th',h)));t.append(head);rows.forEach(row=>{const tr=el('tr');row.forEach(v=>tr.append(el('td',String(v))));t.append(tr)});parent.append(t)}
$('meta').textContent='Mốc đánh giá: '+d.as_of+' · Loại dữ liệu: '+(label[d.context.kind]||d.context.kind)+' · Context: '+d.context.id;
[['Tài sản',d.summary.assets],['Event được duyệt',d.summary.selected_events],['Yêu cầu cần review',d.summary.checks_needing_review],['Alert đang mở',d.summary.active_alerts],['Host chưa ánh xạ',d.summary.unmapped_hosts]].forEach(([title,count])=>{const c=el('div',undefined,'stat');c.append(el('strong',count),el('span',title));$('stats').append(c)});
function detail(row){const p=$('detail');p.replaceChildren();p.append(el('h2',row.asset.name),el('p',row.asset.business_service+' · Chủ sở hữu: '+row.asset.owner),el('span',label[row.asset.criticality]+' · '+label[row.priority],'tag'));
row.telemetry.forEach(c=>{const item=el('div',undefined,'item');item.append(el('h3',c.id),el('p',c.channel+' · '+c.provider,'small'));table(item,['Trong cửa sổ','Tổng đúng policy','Nhận trễ','Clock tương lai','Trường thiếu'],[[c.in_window,c.observed_total,c.late_records,c.future_records,Object.values(c.missing_fields).reduce((a,b)=>a+b,0)]]);c.issues.forEach(x=>item.append(el('p',x,'warn')));const b=el('details');b.append(el('summary','Xem heartbeat, trường thiếu và anchor gốc'));obj(b,{latest_event_age_seconds:c.latest_event_age_seconds,missing_event_ids_in_window:c.missing_event_ids_in_window,missing_fields:c.missing_fields,collector_checks:c.collector_checks,anchor_samples:c.anchor_samples});item.append(b);p.append(item)});
p.append(el('h3','Alert đang lưu và trạng thái bàn giao'));table(p,['Policy','Trạng thái','Owner','Quá hạn review'],row.alerts.map(a=>[a.rule_id,label[a.state]||a.state,a.owner||'Chưa phân công',a.overdue?'Có':'Không']));p.append(el('p','Event chưa ánh xạ policy: '+row.unmatched_policy_events+'. Không tự kết luận tài sản an toàn hoặc bị xâm nhập.'));}
function list(){const q=$('search').value.toLocaleLowerCase('vi');$('asset-list').replaceChildren();d.assets.filter(r=>JSON.stringify(r.asset).toLocaleLowerCase('vi').includes(q)).forEach(r=>{const b=el('button',undefined,'asset');b.append(el('strong',r.asset.name),el('span',r.asset.business_service),el('p',r.asset.owner+' · '+label[r.priority],'small'));b.addEventListener('click',()=>detail(r));$('asset-list').append(b)})}
$('search').addEventListener('input',list);list();if(d.assets.length)detail(d.assets[0]);
document.querySelectorAll('nav button').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('nav button').forEach(n=>n.classList.toggle('active',n===b));['assets','delivery','handoff','limits'].forEach(id=>$(id).hidden=id!==b.dataset.view)}));
table($('queue'),['Scope','Trạng thái outbox','Số record'],d.delivery_states.map(r=>[r.scope,label[r.state]||r.state,r.count]));table($('unmapped'),['Host','Observation','Alert tham chiếu','Đánh giá'],d.unmapped_hosts.map(r=>[r.host,r.observations,r.alert_ids.join(', ')||'Chưa có',r.assessment]));$('sources').textContent=JSON.stringify(d.source_scopes,null,2);
d.assets.forEach(r=>{const section=el('article',undefined,'item');section.append(el('h3',r.asset.name+' · '+r.asset.business_service),el('p','Chủ dịch vụ: '+r.handoff.owner+' · Đầu mối điều tra: '+r.handoff.incident_lead),el('p',r.handoff.authority,'warn'),el('p','Khoảng trống cần xử lý: '+r.handoff.telemetry_gap_ids.join(', ')),el('p','Alert đang mở: '+r.handoff.open_alert_ids.length+' · Chưa kết luận sự cố.'));r.handoff.proposals.forEach(a=>{const card=el('div',undefined,'panel');card.append(el('h3',a.action));table(card,['Nội dung bàn giao','Yêu cầu'],[['Người phụ trách dự kiến',a.owner],['Phê duyệt',a.approval],['Ảnh hưởng',a.impact],['Phục hồi',a.rollback],['Xác minh',a.verification]]);section.append(card)});$('handoffs').append(section)});
$('boundaries').textContent=JSON.stringify({context:d.context,snapshot_sha256:d.selected_snapshot_sha256,archive_and_database_anchors_verified:d.archive_and_database_anchors_verified,window_seconds:d.window_seconds,limits:d.limits,readonly_boundary:d.readonly_boundary,scope:d.scope,verdict:d.verdict},null,2);
</script></main></body></html>
'''
