"""Small transparent detection engine; the rule format is NOT Sigma."""

from collections import defaultdict, deque
from datetime import datetime
import hashlib
import json
from pathlib import Path

from .events import field_value


def load_rules(path: Path) -> list[dict]:
    with Path(path).open(encoding="utf-8") as stream:
        rules = json.load(stream)
    if not isinstance(rules, list) or not rules:
        raise ValueError("rules must be a nonempty JSON list")
    seen = set()
    for rule in rules:
        required = ("id", "title", "severity", "attack", "rationale", "false_positives", "limitations", "conditions")
        if not isinstance(rule, dict) or any(key not in rule for key in required):
            raise ValueError("rule missing required metadata")
        if not isinstance(rule["id"], str) or rule["id"] in seen:
            raise ValueError("rule IDs must be unique strings")
        seen.add(rule["id"])
        if rule["severity"] not in ("low", "medium", "high", "critical"):
            raise ValueError(f"invalid severity: {rule['id']}")
        if not isinstance(rule["conditions"], list) or not rule["conditions"]:
            raise ValueError(f"rule needs conditions: {rule['id']}")
        for condition in rule["conditions"]:
            if not isinstance(condition, dict) or not isinstance(condition.get("field"), str):
                raise ValueError("each condition needs a field")
            if condition.get("op") not in ("equals", "endswith_any", "contains_any"):
                raise ValueError("unsupported rule operator")
            if "value" not in condition:
                raise ValueError("each condition needs a value")
            if condition["op"] != "equals":
                value = condition["value"]
                if not isinstance(value, list) or not value or any(not isinstance(v, str) or not v for v in value):
                    raise ValueError("text operators require a nonempty list of nonempty strings")
    return rules


def matches(event: dict, rule: dict) -> bool:
    for condition in rule["conditions"]:
        actual = field_value(event, condition["field"])
        expected = condition["value"]
        op = condition["op"]
        if actual is None:
            return False
        if op == "equals":
            if isinstance(actual, str) and isinstance(expected, str):
                if actual.casefold() != expected.casefold():
                    return False
            elif actual != expected:
                return False
        else:
            if not isinstance(actual, str):
                return False
            actual = actual.casefold()
            if op == "contains_any" and not any(v.casefold() in actual for v in expected):
                return False
            if op == "endswith_any" and not any(actual.endswith(v.casefold()) for v in expected):
                return False
    return True


def finding(rule: dict, events: list[dict], reason: str | None = None) -> dict:
    evidence = [{key: event[key] for key in (
        "event_uid", "timestamp", "host", "channel", "provider", "event_id", "record_id",
        "source_sha256", "source_line", "event_data",
    )} for event in events]
    identifier = hashlib.sha256((rule["id"] + ":" + ":".join(e["event_uid"] for e in evidence)).encode()).hexdigest()
    return {
        "finding_id": identifier,
        "rule_id": rule["id"],
        "title": rule["title"],
        "suggested_severity": rule["severity"],
        "status": "needs_review",
        "attack": rule["attack"],
        "reason": reason or rule["rationale"],
        "false_positives": rule["false_positives"],
        "limitations": rule["limitations"],
        "evidence": evidence,
    }


AUTH_RULE = {
    "id": "AUTH-001",
    "title": "Repeated failed logons followed by a successful logon",
    "severity": "high",
    "attack": ["T1110"],
    "rationale": "Authentication failures and a subsequent success require account/source verification.",
    "false_positives": ["User password mistakes", "Services using stale credentials", "Shared/NAT source IP"],
    "limitations": [
        "Not proof of compromise or password guessing.",
        "Requires Security 4625 and 4624 with matching host, user, domain, IP and logon type.",
        "Does not detect distributed guessing or account changes between attempts.",
        "Missing domain/logon type/source fields prevent correlation; source files are independent unless explicitly combined.",
    ],
}


def auth_key(event: dict, cross_source: bool) -> tuple | None:
    data = event["event_data"]
    fields = [event["host"], data.get("TargetUserName"), data.get("TargetDomainName"), data.get("IpAddress"), data.get("LogonType")]
    if any(not isinstance(v, str) or v.strip().casefold() in ("", "-", "unknown") for v in fields):
        return None
    # Local/loopback and unspecified addresses do not identify a remote source.
    if fields[3] in ("0.0.0.0", "::", "127.0.0.1", "::1"):
        return None
    scope = "combined" if cross_source else event["source_sha256"]
    return (scope, *(v.casefold() for v in fields))


def seconds(event: dict) -> float:
    return datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).timestamp()


def detect(events, rules: list[dict], *, threshold: int = 5, window_seconds: int = 600, cross_source: bool = False):
    if threshold < 1 or window_seconds < 1:
        raise ValueError("threshold and window_seconds must be positive")
    failures = defaultdict(deque)
    for event in events:
        for rule in rules:
            if matches(event, rule):
                yield finding(rule, [event])
        if event["channel"].casefold() != "security" or event["provider"].casefold() != "microsoft-windows-security-auditing":
            continue
        if event["event_id"] not in (4624, 4625):
            continue
        key = auth_key(event, cross_source)
        if key is None:
            continue
        now = seconds(event)
        # Expire inactive keys too; state does not accumulate for the entire log.
        for old_key in list(failures):
            queue = failures[old_key]
            while queue and now - seconds(queue[0]) > window_seconds:
                queue.popleft()
            if not queue:
                del failures[old_key]
        if event["event_id"] == 4625:
            queue = failures[key]
            queue.append(event)
            # Retain only the latest threshold failures, enough to establish the alert.
            while len(queue) > threshold:
                queue.popleft()
        else:
            queue = failures.get(key, ())
            if len(queue) >= threshold:
                yield finding(AUTH_RULE, [*queue, event], f"At least {threshold} failures followed by success within {window_seconds}s; verify account/source context.")
            failures.pop(key, None)
