"""Local analyst decisions with optimistic revisions and a per-case audit chain.

The hash chain detects edits against an independently retained export anchor. It
is not a signature, access control, or protection against rewriting the whole DB.
"""

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid
import zipfile

TRANSITIONS = {"new":{"triaged"}, "triaged":{"investigating"}, "investigating":{"escalated", "closed"}, "escalated":{"investigating", "closed"}, "closed":set()}
VERDICTS = {"confirmed_in_lab", "expected_activity", "insufficient_evidence"}
ZERO = "0" * 64


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def text(value, name, maximum=5000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{name} must contain 1..{maximum} characters")
    return value.strip()


def connect(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, source_case TEXT NOT NULL,
          title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL, revision INTEGER NOT NULL,
          verdict TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, evidence TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit (case_id TEXT NOT NULL, sequence INTEGER NOT NULL,
          payload TEXT NOT NULL, previous_sha256 TEXT NOT NULL, sha256 TEXT NOT NULL,
          PRIMARY KEY(case_id, sequence));
    """)
    return conn


def anchors(evidence_db, uids):
    if not isinstance(uids, list) or not 1 <= len(uids) <= 30 or len(uids) != len(set(uids)):
        raise ValueError("choose 1..30 distinct evidence UIDs")
    if any(not isinstance(uid, str) or len(uid) != 64 or any(c not in "0123456789abcdef" for c in uid) for uid in uids):
        raise ValueError("invalid evidence UID")
    db = Path(evidence_db).resolve()
    records = []
    with closing(sqlite3.connect(db.as_uri()+"?mode=ro", uri=True)) as conn:
        for uid in uids:
            row = conn.execute("SELECT event_uid,source_sha256,source_line,original_json FROM events WHERE event_uid=?", (uid,)).fetchone()
            if row is None:
                raise ValueError("evidence does not belong to the selected source case")
            records.append({"event_uid":row[0], "source_sha256":row[1], "source_line":row[2], "original":json.loads(row[3])})
    return records


def _case(conn, case_id):
    row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if row is None:
        raise ValueError("unknown operations case")
    result = dict(row)
    result["evidence"] = json.loads(result["evidence"])
    return result


def _audit(conn, case_id):
    rows = conn.execute("SELECT * FROM audit WHERE case_id=? ORDER BY sequence", (case_id,)).fetchall()
    previous, entries = ZERO, []
    for number, row in enumerate(rows, 1):
        payload = json.loads(row["payload"])
        digest = hashlib.sha256(previous.encode() + canonical(payload)).hexdigest()
        if row["sequence"] != number or row["previous_sha256"] != previous or row["sha256"] != digest or payload.get("case_id") != case_id or payload.get("sequence") != number:
            raise ValueError("audit integrity check failed")
        entries.append({"payload":payload, "previous_sha256":previous, "sha256":digest})
        previous = digest
    case = _case(conn, case_id)
    if not entries or len(entries) != case["revision"] or entries[-1]["payload"]["snapshot"] != case:
        raise ValueError("case state does not match its audit chain")
    return entries


def _append(conn, case, action, actor, rationale):
    previous_row = conn.execute("SELECT sha256 FROM audit WHERE case_id=? ORDER BY sequence DESC LIMIT 1", (case["id"],)).fetchone()
    previous = previous_row[0] if previous_row else ZERO
    payload = {"case_id":case["id"], "sequence":case["revision"], "action":action,
               "actor":actor, "rationale":rationale, "at":case["updated_at"], "snapshot":case}
    digest = hashlib.sha256(previous.encode()+canonical(payload)).hexdigest()
    conn.execute("INSERT INTO audit VALUES (?,?,?,?,?)", (case["id"], case["revision"], canonical(payload).decode(), previous, digest))


def create_case(path, *, source_case, evidence_db, uids, title, severity="high", actor="demo-analyst", rationale):
    title, actor, rationale = text(title, "title", 160), text(actor, "actor", 80), text(rationale, "rationale")
    source_case = text(source_case, "source case", 80)
    if severity not in ("low", "medium", "high", "critical"):
        raise ValueError("invalid severity")
    evidence = anchors(evidence_db, uids)
    now = datetime.now(timezone.utc).isoformat()
    case = {"id":uuid.uuid4().hex, "source_case":source_case, "title":title, "severity":severity,
            "status":"new", "revision":1, "verdict":None, "created_at":now, "updated_at":now, "evidence":evidence}
    with closing(connect(path)) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?)", tuple(canonical(case[k]).decode() if k == "evidence" else case[k] for k in ("id", "source_case", "title", "severity", "status", "revision", "verdict", "created_at", "updated_at", "evidence")))
        _append(conn, case, "create", actor, rationale)
    return case


def update_case(path, case_id, *, revision, action, actor, rationale, target=None, verdict=None, evidence_db=None, uids=None):
    actor, rationale = text(actor, "actor", 80), text(rationale, "rationale")
    if not isinstance(revision, int) or isinstance(revision, bool):
        raise ValueError("revision must be an integer")
    if action not in ("note", "transition", "attach"):
        raise ValueError("invalid case action")
    with closing(connect(path)) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        _audit(conn, case_id)
        case = _case(conn, case_id)
        if case["revision"] != revision:
            raise ValueError("revision conflict: reload the case before saving")
        if action == "attach":
            if case["status"] == "closed": raise ValueError("closed cases cannot accept new evidence")
            additions = anchors(evidence_db, uids)
            known = {record["event_uid"] for record in case["evidence"]}
            additions = [record for record in additions if record["event_uid"] not in known]
            if not additions: raise ValueError("selected evidence is already attached")
            if len(case["evidence"])+len(additions) > 30: raise ValueError("case evidence limit is 30 records")
            case["evidence"].extend(additions)
        if action == "transition":
            if target not in TRANSITIONS[case["status"]]:
                raise ValueError("invalid status transition")
            if target == "closed" and verdict not in VERDICTS:
                raise ValueError("closure requires an explicit verdict")
            case["status"], case["verdict"] = target, verdict if target == "closed" else None
        case["revision"] += 1
        case["updated_at"] = datetime.now(timezone.utc).isoformat()
        conn.execute("UPDATE cases SET status=?,revision=?,verdict=?,updated_at=?,evidence=? WHERE id=?", (case["status"],case["revision"],case["verdict"],case["updated_at"],canonical(case["evidence"]).decode(),case_id))
        _append(conn, case, action, actor, rationale)
    return case


def list_cases(path):
    with closing(connect(path)) as conn:
        conn.execute("BEGIN")
        result = []
        for row in conn.execute("SELECT id FROM cases ORDER BY created_at DESC"):
            result.append(_audit(conn, row[0])[-1]["payload"]["snapshot"])
        return result


def get_case(path, case_id):
    with closing(connect(path)) as conn:
        # All reads must share a snapshot, even if another connection commits.
        conn.execute("BEGIN")
        case = _case(conn, case_id)
        entries = _audit(conn, case_id)
        return {"case":case, "audit":entries, "anchor_sha256":entries[-1]["sha256"], "integrity":"verified against current local chain; retain export anchor independently"}


def _export_files(result):
    case = result["case"]
    case_id = case["id"]
    files = {"case.json":canonical(case)+b"\n", "audit.json":canonical(result["audit"])+b"\n",
             "evidence.jsonl":b"".join(canonical(record)+b"\n" for record in case["evidence"])}
    lines = [f"# {case['title']}", "", f"Status: {case['status']} | severity: {case['severity']} | revision: {case['revision']}", "",
             f"Source collection: {case['source_case']}", "", "This is a local portfolio investigation. Actor labels are self-declared; no response action was executed.", "", "## Analyst decisions", ""]
    for entry in result["audit"]:
        p = entry["payload"]
        lines += [f"### {p['sequence']}. {p['action']} / {p['snapshot']['status']}", "", f"{p['at']} · {p['actor']}", "", p["rationale"], ""]
    files["report.md"] = ("\n".join(lines)+"\n").encode()
    manifest = {"schema_version":1, "case_id":case_id, "revision":case["revision"], "audit_anchor_sha256":result["anchor_sha256"],
                "files":{name:hashlib.sha256(data).hexdigest() for name, data in files.items()},
                "limitations":["Relative integrity, not a digital signature", "Retained event JSON is an export, not the original EVTX bytes", "Source SHA-256 references require separately retained acquisition files"]}
    files["manifest.json"] = canonical(manifest)+b"\n"
    return files, manifest


def reviewed_export(result, output_dir):
    case = result["case"]
    output = Path(output_dir) / f"case-{case['id']}-r{case['revision']}.zip"
    if not output.exists():
        return None
    files, manifest = _export_files(result)
    try:
        with zipfile.ZipFile(output) as archive:
            if sorted(archive.namelist()) != sorted(files):
                raise ValueError("reviewed export file inventory differs")
            for name, data in files.items():
                if archive.read(name) != data:
                    raise ValueError("reviewed export does not match this audited revision")
    except zipfile.BadZipFile:
        raise ValueError("reviewed export is not a complete ZIP") from None
    return {"file":output.name, "sha256":hashlib.sha256(output.read_bytes()).hexdigest(), "manifest":manifest}


def export_case(path, case_id, output_dir):
    result = get_case(path, case_id)
    case = result["case"]
    files, manifest = _export_files(result)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"case-{case_id}-r{case['revision']}.zip"
    # Exclusive creation prevents a later export from replacing a reviewed bundle.
    import os
    from tempfile import TemporaryDirectory
    # Publish only a closed ZIP. A hard link atomically refuses an existing name.
    # No failed build can leave a partially written final revision behind.
    with TemporaryDirectory(prefix=".soclab-export-", dir=output_dir) as temporary:
        staged = Path(temporary) / "bundle.zip"
        with zipfile.ZipFile(staged, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data)
        os.link(staged, output)
    return {"file":output.name, "sha256":hashlib.sha256(output.read_bytes()).hexdigest(), "manifest":manifest}
