"""A localhost-only evidence viewer; it is not a SIEM or an incident response service."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from contextlib import closing
from itertools import islice
import json
import secrets
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .store import iter_events


def case_index(path):
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data.get("cases"), list) or not data["cases"]:
        raise ValueError("case index must contain cases; run scripts/reproduce.ps1 first")
    ids = [case["id"] for case in data["cases"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case IDs")
    return data


def build_handler(index_path: Path, operations_db=None):
    root = Path(__file__).resolve().parents[1]
    index = case_index(index_path)
    cases = {case["id"]: case for case in index["cases"]}
    csrf = secrets.token_urlsafe(32)
    assets = {"/": ("index.html", "text/html"), "/styles.css": ("styles.css", "text/css"), "/app.js": ("app.js", "text/javascript"), "/investigation.js": ("investigation.js", "text/javascript"), "/operations.js": ("operations.js", "text/javascript")}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, status, body, content_type="application/json"):
            if not isinstance(body, bytes):
                body = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            host = self.headers.get("Host", "")
            port = self.server.server_port
            if len(self.headers.get_all("Host", [])) != 1 or host not in (f"localhost:{port}", f"127.0.0.1:{port}"):
                return self.respond(403, {"error": "localhost access only"})
            url = urlparse(self.path)
            params = parse_qs(url.query)
            try:
                if url.path in assets:
                    name, mime = assets[url.path]
                    return self.respond(200, (root / "web" / name).read_bytes(), mime)
                if url.path == "/api/operations":
                    from .operations import list_cases
                    return self.respond(200, {"enabled":operations_db is not None, "csrf":csrf if operations_db else None, "cases":list_cases(operations_db) if operations_db else []})
                if url.path == "/api/operations/case" and operations_db:
                    from .operations import get_case, reviewed_export
                    result = get_case(operations_db, params.get("id", [""])[0])
                    result["export"] = reviewed_export(result, Path(operations_db).parent / "exports")
                    return self.respond(200, result)
                if url.path == "/api/operations/download" and operations_db:
                    name = params.get("file", [""])[0]
                    import re
                    if not re.fullmatch(r"case-[a-f0-9]{32}-r[1-9][0-9]*\.zip", name):
                        raise ValueError("invalid export filename")
                    path = Path(operations_db).parent / "exports" / name
                    return self.respond(200, path.read_bytes(), "application/zip")
                if url.path == "/api/cases":
                    result = []
                    for case in cases.values():
                        manifest = json.loads((root / case["analysis"] / "manifest.json").read_text(encoding="utf-8"))
                        result.append({**{k: case[k] for k in ("id", "title", "kind", "verdict", "report")}, "manifest": manifest})
                    return self.respond(200, {"version": __version__, "run_id": index.get("advanced_run_id", index["run_id"]), "cases": result, "note": index["note"]})
                if url.path == "/api/evaluation":
                    if "evaluation" not in index:
                        return self.respond(404, {"error": "run scripts/build_advanced.py first"})
                    return self.respond(200, json.loads((root / index["evaluation"]).read_text(encoding="utf-8")))
                case = cases.get(params.get("case", [""])[0])
                if case is None:
                    return self.respond(404, {"error": "unknown case"})
                if url.path == "/api/findings":
                    path = root / case["analysis"] / "findings.jsonl"
                    return self.respond(200, [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line])
                if url.path == "/api/hunts":
                    from .hunting import run_hunts
                    return self.respond(200, run_hunts(root / case["db"]))
                if url.path == "/api/investigation":
                    if "investigation" not in case:
                        return self.respond(404, {"error": "run scripts/build_advanced.py first"})
                    return self.respond(200, json.loads((root / case["investigation"]).read_text(encoding="utf-8")))
                if url.path == "/api/events":
                    limit = int(params.get("limit", ["50"])[0])
                    if not 1 <= limit <= 200:
                        raise ValueError("limit must be 1..200")
                    eid = params.get("event_id", [None])[0]
                    events = iter_events(root / case["db"], event_id=int(eid) if eid else None, term=params.get("term", [None])[0])
                    return self.respond(200, list(islice(events, limit)))
                if url.path == "/api/event":
                    uid = params.get("uid", [""])[0]
                    if len(uid) != 64 or any(c not in "0123456789abcdef" for c in uid):
                        raise ValueError("invalid event UID")
                    db = (root / case["db"]).resolve()
                    with closing(sqlite3.connect(db.as_uri()+"?mode=ro", uri=True)) as conn:
                        row = conn.execute("SELECT original_json,source_sha256,source_line,event_uid FROM events WHERE event_uid=?", (uid,)).fetchone()
                    if row is None:
                        return self.respond(404, {"error": "event not in this case"})
                    return self.respond(200, {"original":json.loads(row[0]),"source_sha256":row[1],"source_line":row[2],"event_uid":row[3]})
                if url.path == "/api/report":
                    return self.respond(200, {"markdown": (root / case["report"]).read_text(encoding="utf-8")})
                return self.respond(404, {"error": "not found"})
            except (ValueError, OSError, KeyError, sqlite3.Error) as exc:
                return self.respond(400, {"error": str(exc)})

        def do_POST(self):
            # Browser-origin checks plus an unpredictable per-process token.
            # This is a single-user loopback workspace, not multi-user authentication.
            host = self.headers.get("Host", "")
            port = self.server.server_port
            if len(self.headers.get_all("Host", [])) != 1 or len(self.headers.get_all("Origin", [])) != 1 or host not in (f"127.0.0.1:{port}", f"localhost:{port}") or self.headers.get("Origin") != "http://"+host:
                return self.respond(403, {"error":"same-origin localhost requests required"})
            if not operations_db or len(self.headers.get_all("X-SOC-CSRF", [])) != 1 or not secrets.compare_digest(self.headers.get("X-SOC-CSRF", "").encode("utf-8"), csrf.encode("ascii")):
                return self.respond(403, {"error":"workspace disabled or invalid CSRF token"})
            try:
                if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                    raise ValueError("JSON with Content-Length required")
                if len(self.headers.get_all("Content-Length", [])) != 1:
                    raise ValueError("one Content-Length required")
                length = int(self.headers["Content-Length"])
                if not 1 <= length <= 65536:
                    raise ValueError("request body must be 1..65536 bytes")
                self.connection.settimeout(10)
                try:
                    data = json.loads(self.rfile.read(length))
                except RecursionError:
                    raise ValueError("JSON nesting exceeds the request parser limit") from None
                if not isinstance(data, dict):
                    raise ValueError("request must be an object")
                from .operations import create_case, update_case, export_case
                if self.path == "/api/operations/create":
                    source = cases.get(data.get("source_case"))
                    if not source:
                        raise ValueError("unknown source collection")
                    result = create_case(operations_db, source_case=source["id"], evidence_db=root/source["db"],
                                         uids=data["uids"], title=data["title"], severity=data.get("severity", "high"), actor=data["actor"], rationale=data["rationale"])
                elif self.path == "/api/operations/update":
                    evidence_db = None
                    if data["action"] == "attach":
                        from .operations import get_case
                        owned = get_case(operations_db, data["id"])["case"]["source_case"]
                        if data.get("source_case") != owned or owned not in cases:
                            raise ValueError("attachment must use the operations case's source collection")
                        evidence_db = root / cases[owned]["db"]
                    result = update_case(operations_db, data["id"], revision=data["revision"], action=data["action"],
                                         actor=data["actor"], rationale=data["rationale"], target=data.get("target"), verdict=data.get("verdict"), evidence_db=evidence_db, uids=data.get("uids"))
                elif self.path == "/api/operations/export":
                    result = export_case(operations_db, data["id"], Path(operations_db).parent/"exports")
                else:
                    return self.respond(404, {"error":"unknown workspace action"})
                return self.respond(200, result)
            except (ValueError, TypeError, OSError, KeyError, sqlite3.Error) as exc:
                return self.respond(400, {"error":str(exc)})

    return Handler


def serve(index_path: Path, port: int, operations_db=None):
    if not 1024 <= port <= 65535:
        raise ValueError("port must be 1024..65535")
    server = ThreadingHTTPServer(("127.0.0.1", port), build_handler(index_path, operations_db))
    mode = "local case workspace; source evidence read-only" if operations_db else "read-only, offline evidence"
    print(f"SOC Lab {__version__}: http://127.0.0.1:{port} ({mode})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
