"""A localhost-only evidence viewer; it is not a SIEM or an incident response service."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from itertools import islice
import json
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


def build_handler(index_path: Path):
    root = Path(__file__).resolve().parents[1]
    index = case_index(index_path)
    cases = {case["id"]: case for case in index["cases"]}
    assets = {"/": ("index.html", "text/html"), "/styles.css": ("styles.css", "text/css"), "/app.js": ("app.js", "text/javascript")}

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
            host = self.headers.get("Host", "").split(":")[0]
            if host not in ("localhost", "127.0.0.1"):
                return self.respond(403, {"error": "localhost access only"})
            url = urlparse(self.path)
            params = parse_qs(url.query)
            try:
                if url.path in assets:
                    name, mime = assets[url.path]
                    return self.respond(200, (root / "web" / name).read_bytes(), mime)
                if url.path == "/api/cases":
                    result = []
                    for case in cases.values():
                        manifest = json.loads((root / case["analysis"] / "manifest.json").read_text(encoding="utf-8"))
                        result.append({**{k: case[k] for k in ("id", "title", "kind", "verdict", "report")}, "manifest": manifest})
                    return self.respond(200, {"version": __version__, "run_id": index["run_id"], "cases": result, "note": index["note"]})
                case = cases.get(params.get("case", [""])[0])
                if case is None:
                    return self.respond(404, {"error": "unknown case"})
                if url.path == "/api/findings":
                    path = root / case["analysis"] / "findings.jsonl"
                    return self.respond(200, [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line])
                if url.path == "/api/events":
                    limit = int(params.get("limit", ["50"])[0])
                    if not 1 <= limit <= 200:
                        raise ValueError("limit must be 1..200")
                    eid = params.get("event_id", [None])[0]
                    events = iter_events(root / case["db"], event_id=int(eid) if eid else None, term=params.get("term", [None])[0])
                    return self.respond(200, list(islice(events, limit)))
                if url.path == "/api/report":
                    return self.respond(200, {"markdown": (root / case["report"]).read_text(encoding="utf-8")})
                return self.respond(404, {"error": "not found"})
            except (ValueError, OSError, KeyError) as exc:
                return self.respond(400, {"error": str(exc)})

    return Handler


def serve(index_path: Path, port: int):
    if not 1024 <= port <= 65535:
        raise ValueError("port must be 1024..65535")
    server = ThreadingHTTPServer(("127.0.0.1", port), build_handler(index_path))
    print(f"SOC Lab {__version__}: http://127.0.0.1:{port} (read-only, offline evidence)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
