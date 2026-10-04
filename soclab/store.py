"""Stream JSONL evidence into a local SQLite database with atomic imports."""

from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3

from .events import normalize_event, utc_timestamp


SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    sha256 TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    event_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    event_uid TEXT PRIMARY KEY,
    source_sha256 TEXT NOT NULL REFERENCES sources(sha256),
    source_line INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    host TEXT NOT NULL,
    channel TEXT NOT NULL,
    provider TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    record_id INTEGER NOT NULL,
    event_data TEXT NOT NULL,
    original_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS event_time ON events(timestamp, event_uid);
CREATE INDEX IF NOT EXISTS event_host_time ON events(host, timestamp);
CREATE INDEX IF NOT EXISTS event_type ON events(channel, event_id);
"""


def connect(db: Path) -> sqlite3.Connection:
    db = Path(db)
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


def ingest(source: Path, db: Path) -> dict:
    source = Path(source).resolve()
    with source.open("rb") as evidence:
        digest = hashlib.file_digest(evidence, "sha256").hexdigest()
    with closing(connect(db)) as conn, conn:
        known = conn.execute("SELECT event_count FROM sources WHERE sha256 = ?", (digest,)).fetchone()
        if known:
            return {"source_sha256": digest, "events": known[0], "already_imported": True}
        conn.execute("INSERT INTO sources VALUES (?, ?, 0)", (digest, str(source)))
        count = 0
        # utf-8-sig accepts the BOM produced by some Windows tools.
        imported_digest = hashlib.sha256()
        with source.open("rb") as stream:
            for line_number, raw_line in enumerate(stream, 1):
                imported_digest.update(raw_line)
                try:
                    line = raw_line.decode("utf-8-sig" if line_number == 1 else "utf-8")
                except UnicodeDecodeError as exc:
                    raise ValueError(f"{source.name}: line {line_number}: evidence is not UTF-8") from exc
                if not line.strip():
                    continue
                try:
                    event = normalize_event(json.loads(line), digest, line_number)
                except (ValueError, TypeError) as exc:
                    raise ValueError(f"{source.name}: line {line_number}: {exc}") from exc
                event["event_data"] = json.dumps(event["event_data"], ensure_ascii=False, sort_keys=True)
                keys = tuple(event)
                conn.execute(
                    f"INSERT INTO events ({','.join(keys)}) VALUES ({','.join('?' for _ in keys)})",
                    tuple(event.values()),
                )
                count += 1
        if imported_digest.hexdigest() != digest:
            raise ValueError("source changed during ingestion; import rolled back")
        if count == 0:
            raise ValueError("source contains no events")
        conn.execute("UPDATE sources SET event_count = ? WHERE sha256 = ?", (count, digest))
    return {"source_sha256": digest, "events": count, "already_imported": False}


def iter_events(db: Path, *, host=None, user=None, start=None, end=None, event_id=None, term=None):
    if not Path(db).is_file():
        raise ValueError(f"database does not exist: {db}; ingest evidence first")
    clauses, parameters = [], []
    for field, value in (("host", host), ("event_id", event_id)):
        if value is not None:
            clauses.append(f"{field} = ?")
            parameters.append(value)
    for operator, value in ((">=", start), ("<=", end)):
        if value is not None:
            clauses.append(f"timestamp {operator} ?")
            parameters.append(utc_timestamp(value))
    query = "SELECT * FROM events"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY timestamp, source_sha256, source_line"
    with closing(sqlite3.connect(Path(db).resolve().as_uri()+"?mode=ro", uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        for row in conn.execute(query, parameters):
            event = dict(row)
            event["event_data"] = json.loads(event["event_data"])
            if user is not None:
                values = [event["event_data"].get(k, "") for k in ("User", "TargetUserName", "SubjectUserName")]
                if user.casefold() not in [v.casefold() for v in values]:
                    continue
            if term is not None and term.casefold() not in event["original_json"].casefold():
                continue
            yield event


def sources(db: Path) -> list[dict]:
    with closing(sqlite3.connect(Path(db).resolve().as_uri()+"?mode=ro", uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute("SELECT * FROM sources ORDER BY sha256")]
