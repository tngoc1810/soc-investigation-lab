"""Fixed read-only hunts. Every hit is an observation, not a malicious verdict."""

from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3

HUNTS = [
    ("HUNT-01", "Which process parents deserve review in this collection?", 1,
     "SELECT json_extract(event_data,'$.ParentImage') AS parent, json_extract(event_data,'$.Image') AS child, COUNT(*) AS observations FROM events WHERE event_id=1 AND lower(provider)='microsoft-windows-sysmon' GROUP BY parent,child ORDER BY observations,parent,child LIMIT 100",
     "Rarity is relative to this small collection, not an enterprise baseline."),
    ("HUNT-02", "Do observed process GUIDs link to network activity?", 3,
     "SELECT c.event_uid AS creation_uid,n.event_uid AS network_uid,c.host,json_extract(c.event_data,'$.Image') AS image,json_extract(n.event_data,'$.DestinationIp') AS destination,json_extract(n.event_data,'$.Initiated') AS initiated FROM events c JOIN events n ON lower(c.host)=lower(n.host) AND lower(json_extract(c.event_data,'$.ProcessGuid'))=lower(json_extract(n.event_data,'$.ProcessGuid')) AND n.timestamp>=c.timestamp WHERE c.event_id=1 AND n.event_id=3 AND lower(c.provider)='microsoft-windows-sysmon' AND lower(n.provider)='microsoft-windows-sysmon' AND length(json_extract(c.event_data,'$.ProcessGuid'))=38 AND lower(json_extract(c.event_data,'$.ProcessGuid'))<>'{00000000-0000-0000-0000-000000000000}' LIMIT 100",
     "This hunt proposes exact GUID pivots. The graph engine additionally validates UUID syntax and conflicting creation records."),
    ("HUNT-03", "Which account/IP pairs dominate failed logons?", 4625,
     "SELECT host,json_extract(event_data,'$.TargetDomainName') AS domain,json_extract(event_data,'$.TargetUserName') AS account,json_extract(event_data,'$.IpAddress') AS ip,json_extract(event_data,'$.SubStatus') AS sub_status,COUNT(*) AS failures FROM events WHERE event_id=4625 AND lower(provider)='microsoft-windows-security-auditing' GROUP BY host,domain,account,ip,sub_status ORDER BY failures DESC LIMIT 100",
     "Failed authentication alone does not prove successful access; source scope and failure reasons matter."),
    ("HUNT-04", "Is task registration present as its own observation?", 4698,
     "SELECT event_uid,timestamp,host,json_extract(event_data,'$.TaskName') AS task_name,json_extract(event_data,'$.TaskContent') AS task_xml FROM events WHERE event_id=4698 AND lower(provider)='microsoft-windows-security-auditing' LIMIT 100",
     "Task XML is retained as text. Registration does not prove that a task ran."),
    ("HUNT-05", "Which script-block fragments are actually collected?", 4104,
     "SELECT event_uid,host,json_extract(event_data,'$.ScriptBlockId') AS block_id,json_extract(event_data,'$.MessageNumber') AS part,json_extract(event_data,'$.MessageTotal') AS total,json_extract(event_data,'$.ScriptBlockText') AS text FROM events WHERE event_id=4104 AND lower(provider)='microsoft-windows-powershell' LIMIT 100",
     "Use reconstruction and static AST inspection before interpreting keyword matches as behavior."),
    ("HUNT-06", "Which subjects use explicit credentials for distinct targets?", 4648,
     "SELECT host,json_extract(event_data,'$.SubjectDomainName') AS subject_domain,json_extract(event_data,'$.SubjectUserName') AS subject,json_extract(event_data,'$.TargetServerName') AS target_server,COUNT(DISTINCT lower(COALESCE(json_extract(event_data,'$.TargetDomainName'),'')||'\\'||COALESCE(json_extract(event_data,'$.TargetUserName'),''))) AS distinct_target_users,COUNT(*) AS observations FROM events WHERE event_id=4648 AND lower(provider)='microsoft-windows-security-auditing' GROUP BY host,subject_domain,subject,target_server ORDER BY distinct_target_users DESC LIMIT 100",
     "Explicit credentials can be authorized administration. This aggregate does not establish password spraying."),
    ("HUNT-07", "Was Security logging cleared within the collected file?", 1102,
     "SELECT event_uid,timestamp,host,event_data FROM events WHERE event_id=1102 AND lower(channel)='security' LIMIT 100",
     "Investigate maintenance context. Missing 1102 in a narrow sample is not proof logging remained intact."),
    ("HUNT-08", "Are registry persistence leads present?", 13,
     "SELECT event_uid,timestamp,host,json_extract(event_data,'$.Image') AS image,json_extract(event_data,'$.TargetObject') AS target,json_extract(event_data,'$.Details') AS details FROM events WHERE event_id=13 AND lower(provider)='microsoft-windows-sysmon' LIMIT 100",
     "Registry writes require key/value and authorization review. Zero hits may reflect missing telemetry.")
]


def run_hunts(db):
    db=Path(db).resolve()
    with closing(sqlite3.connect(db.as_uri()+"?mode=ro",uri=True)) as conn:
        conn.row_factory=sqlite3.Row
        total=conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        source_hashes=[r[0] for r in conn.execute("SELECT sha256 FROM sources ORDER BY sha256")]
        result=[]
        for identifier,hypothesis,eid,sql,caution in HUNTS:
            rows=[dict(row) for row in conn.execute(sql)]
            result.append({"id":identifier,"hypothesis":hypothesis,"query":sql,"query_sha256":hashlib.sha256(sql.encode()).hexdigest(),
                           "rows":rows,"returned_rows":len(rows),"row_limit":100,"assessment":"review observations" if rows else "no returned observations; assess collection coverage", "caution":caution})
    return {"event_count":total,"source_sha256":source_hashes,"hunts":result,"scope":"Independent case collection; all SQL executed read-only; results capped at 100 rows per hunt"}
