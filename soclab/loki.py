"""Bounded localhost HTTP transport for replayed evidence, never endpoint collection."""

from datetime import datetime, timezone
import json
import re
import time
from urllib.parse import urlencode, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError


def nanoseconds(timestamp):
    value = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("timestamp needs a timezone")
    delta = value.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def flatten(event):
    fields = event["event_data"]
    result = {k: event[k] for k in ("event_uid", "source_sha256", "source_line", "host", "channel", "provider", "event_id", "record_id")}
    result["original_timestamp"] = event["timestamp"]
    for name, source in {"image":"Image", "command_line":"CommandLine", "user":"User", "target_user":"TargetUserName", "ip":"IpAddress", "logon_type":"LogonType", "process_guid":"ProcessGuid", "parent_guid":"ParentProcessGuid", "destination_ip":"DestinationIp", "script_block":"ScriptBlockText"}.items():
        result[name] = fields.get(source, "")
    result["event_data"] = fields
    return result


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(req.full_url, code, "backend redirects are not allowed", headers, fp)


class Loki:
    def __init__(self, endpoint="http://127.0.0.1:3100", *, timeout=20):
        url = urlparse(endpoint)
        if url.scheme != "http" or url.hostname not in ("127.0.0.1", "localhost") or url.path not in ("", "/") or url.username or url.password or url.query or url.fragment:
            raise ValueError("Loki endpoint must be a plain localhost HTTP origin")
        self.endpoint, self.timeout = endpoint.rstrip("/"), timeout
        self.transport = build_opener(NoRedirect())

    def request(self, path, payload=None):
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode() if payload is not None else None
        request = Request(self.endpoint + path, data=raw, headers={"Content-Type":"application/json"})
        for attempt in range(3):
            try:
                with self.transport.open(request, timeout=self.timeout) as response:
                    body = response.read(16_000_001)
                    if len(body) > 16_000_000:
                        raise ValueError("backend response exceeds 16 MB")
                    return json.loads(body) if body else {"status":"accepted"}
            except HTTPError as exc:
                if exc.code not in (429, 502, 503, 504) or attempt == 2:
                    raise ValueError(f"Loki HTTP {exc.code}: {exc.read(2000).decode(errors='replace')}") from exc
            except URLError as exc:
                if attempt == 2:
                    raise ValueError(f"Loki unavailable: {exc.reason}") from exc
            time.sleep(0.25 * 2 ** attempt)

    def replay(self, events, *, case_id, run_id, kind, mode="historical", batch_size=250):
        if mode not in ("historical", "replay_now") or not 1 <= batch_size <= 500:
            raise ValueError("invalid replay mode or batch size")
        for value in (case_id, run_id, kind):
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
                raise ValueError("stream labels must be short alphanumeric identifiers")
        labels = {"job":"soclab", "case_id":case_id, "replay_run":run_id, "kind":kind, "mode":mode}
        batch, count, minimum, maximum = [], 0, None, None
        now = time.time_ns() - 1_000_000_000
        for event in events:
            stamp = nanoseconds(event["timestamp"]) if mode == "historical" else now + count * 1000
            minimum = stamp if minimum is None else min(minimum, stamp)
            maximum = stamp if maximum is None else max(maximum, stamp)
            record = flatten(event)
            record["replay_mode"] = mode
            batch.append([str(stamp), json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))])
            count += 1
            if len(batch) == batch_size:
                self.request("/loki/api/v1/push", {"streams":[{"stream":labels, "values":batch}]})
                batch = []
        if batch:
            self.request("/loki/api/v1/push", {"streams":[{"stream":labels, "values":batch}]})
        return {"labels":labels, "sent_records":count, "start_ns":minimum, "end_ns":maximum, "delivery":"at-least-once HTTP batches; no exactly-once claim"}

    def query(self, expression, at_ns):
        return self.request("/loki/api/v1/query?" + urlencode({"query":expression, "time":str(at_ns)}))

    def logs(self, expression, start_ns, end_ns, limit=100):
        if not 1 <= limit <= 500:
            raise ValueError("log query limit must be 1..500")
        return self.request("/loki/api/v1/query_range?" + urlencode({"query":expression, "start":str(start_ns), "end":str(end_ns), "limit":limit, "direction":"forward"}))
