"""Scenario-scoped evidence graph and explainable five-stage investigation leads.

No PID, account-name-only or proximity-only causal joins are permitted here.
The caller must explicitly approve all source hashes as one collection scenario.
"""

from collections import Counter, defaultdict
from bisect import bisect_left, bisect_right
import hashlib
import json
from pathlib import Path
import shlex
import uuid

from .detections import auth_key, seconds

SYSMON = "microsoft-windows-sysmon"
SECURITY = "microsoft-windows-security-auditing"


def guid(value):
    try:
        parsed = uuid.UUID(value.strip("{}"))
        return str(parsed) if parsed.int else None
    except (ValueError, AttributeError, TypeError):
        return None


def is_sysmon(event, eid=None):
    return (event["provider"].casefold() == SYSMON and
            event["channel"].casefold() == "microsoft-windows-sysmon/operational" and
            (eid is None or event["event_id"] == eid))


def is_security(event, eid=None):
    return (event["provider"].casefold() == SECURITY and event["channel"].casefold() == "security" and
            (eid is None or event["event_id"] == eid))


def reference(event):
    return {k: event[k] for k in ("event_uid", "source_sha256", "source_line", "record_id", "timestamp", "host", "event_id")}


def risk_reason(event):
    """Conservative command markers, not a Windows command-line or script parser."""
    data = event["event_data"]
    image = data.get("Image", "").replace("/", "\\").rsplit("\\", 1)[-1].casefold()
    command = data.get("CommandLine", "")
    try:
        tokens = [t.casefold() for t in shlex.split(command, posix=False)]
    except ValueError:
        return None
    if image == "mshta.exe" and any(t.strip('"\'').startswith(("https://", "http://", "javascript:", "vbscript:")) for t in tokens[1:]):
        return "mshta remote/inline script argument"
    if image in ("powershell.exe", "pwsh.exe"):
        for token in tokens[1:]:
            if token in ("-file", "-f", "-command", "-c"):
                break  # Later strings can be script arguments or script content.
            if token in ("-encodedcommand", "-enc"):
                return "PowerShell encoded-command host argument"
    return None


def task_creation(event):
    data = event["event_data"]
    image = data.get("Image", "").replace("/", "\\").rsplit("\\", 1)[-1].casefold()
    try:
        tokens = [t.strip('"').casefold() for t in shlex.split(data.get("CommandLine", ""), posix=False)]
    except ValueError:
        return False
    return image == "schtasks.exe" and "/create" in tokens and "/tr" in tokens


def scoped_events(events, scope):
    if not isinstance(scope, dict):
        raise ValueError("scenario scope must be an object")
    approved = scope.get("source_sha256")
    if not isinstance(scope.get("id"), str) or not scope["id"].strip() or not isinstance(scope.get("collection_reason"), str) or not scope["collection_reason"].strip():
        raise ValueError("scenario needs an ID and explicit collection reason")
    if not isinstance(approved, list) or not approved:
        raise ValueError("scenario needs unique approved source hashes")
    if any(not isinstance(h, str) or len(h) != 64 or any(c not in "0123456789abcdef" for c in h) for h in approved):
        raise ValueError("invalid approved SHA-256")
    if len(set(approved)) != len(approved):
        raise ValueError("scenario needs unique approved source hashes")
    from itertools import islice
    events = list(islice(events, 100_001))
    if len(events) > 100_000:
        raise ValueError("investigation graph is limited to 100000 events per scenario")
    events.sort(key=lambda e: (e["timestamp"], e["source_sha256"], e["source_line"]))
    actual = {e["source_sha256"] for e in events}
    if actual != set(approved):
        raise ValueError("observed sources differ from the explicitly approved scenario")
    canonical, aliases = {}, {}
    for event in events:
        semantic = {k: event[k] for k in ("timestamp", "host", "provider", "channel", "event_id", "record_id", "event_data")}
        digest = hashlib.sha256(json.dumps(semantic, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        if digest in canonical:
            aliases[canonical[digest]["event_uid"]].append(reference(event))
        else:
            canonical[digest] = event
            aliases[event["event_uid"]] = [reference(event)]
    return list(canonical.values()), aliases, len(events)


def investigate(events, scope, *, threshold=5, auth_window=600, chain_window=900):
    if threshold < 2 or auth_window < 1 or chain_window < 1:
        raise ValueError("invalid investigation thresholds/windows")
    events, aliases, raw_count = scoped_events(events, scope)
    diagnostics = []
    creates = defaultdict(list)
    for e in events:
        if is_sysmon(e, 1):
            g = guid(e["event_data"].get("ProcessGuid"))
            if g:
                creates[(e["host"].casefold(), g)].append(e)
            else:
                diagnostics.append({"code": "missing_process_guid", "evidence": reference(e)})
    ambiguous = {key for key, records in creates.items() if len(records) > 1}
    for key in sorted(ambiguous):
        diagnostics.append({"code": "conflicting_process_creation", "host": key[0], "guid": key[1], "evidence": [reference(e) for e in creates[key]]})
    nodes, by_key = [], {}
    for key, records in creates.items():
        if key in ambiguous:
            continue
        e = records[0]
        node = {"id": e["event_uid"], "host": e["host"], "guid": key[1], "timestamp": e["timestamp"],
                "image": e["event_data"].get("Image", ""), "command": e["event_data"].get("CommandLine", ""),
                "user": e["event_data"].get("User", ""), "risk_marker": risk_reason(e), "evidence": aliases[e["event_uid"]], "activity": []}
        nodes.append(node); by_key[key] = node
    edges, parent_of = [], {}
    for key, node in by_key.items():
        e = creates[key][0]
        pg = guid(e["event_data"].get("ParentProcessGuid"))
        parent = by_key.get((key[0], pg))
        if not parent:
            if pg:
                diagnostics.append({"code": "parent_not_observed", "child": node["id"], "parent_guid": pg})
            continue
        cursor = parent["id"]; visited = {node["id"]}
        while cursor in parent_of and cursor not in visited:
            visited.add(cursor); cursor = parent_of[cursor]
        if cursor in visited or parent["timestamp"] > node["timestamp"]:
            diagnostics.append({"code": "invalid_parent_order_or_cycle", "child": node["id"]})
            continue
        parent_of[node["id"]] = parent["id"]
        edges.append({"from": parent["id"], "to": node["id"], "basis": "same host + ParentProcessGuid = ProcessGuid + parent observed no later than child", "evidence": reference(e)})
    for e in events:
        if is_sysmon(e) and e["event_id"] != 1:
            key = (e["host"].casefold(), guid(e["event_data"].get("ProcessGuid")))
            node = by_key.get(key)
            if node and e["timestamp"] >= node["timestamp"]:
                node["activity"].append({"evidence": reference(e), "fields": e["event_data"]})
            elif key[1]:
                diagnostics.append({"code": "unjoined_process_activity", "evidence": reference(e)})
    def descendant(child, ancestor):
        seen = set()
        while child in parent_of and child not in seen:
            seen.add(child); child = parent_of[child]
            if child == ancestor: return True
        return False
    chains, candidates = [], []
    # Index once; a successful logon must not rescan every unrelated event.
    failure_index, session_index, task_index = defaultdict(list), defaultdict(list), defaultdict(list)
    for e in events:
        if is_security(e, 4625):
            identity = auth_key(e, True)
            if identity is not None: failure_index[identity].append(e)
        if is_sysmon(e, 1) and task_creation(e):
            child, seen = e["event_uid"], set()
            while child in parent_of and child not in seen:
                seen.add(child); child = parent_of[child]
                task_index[child].append(e)
    failure_times = {key:[seconds(e) for e in records] for key,records in failure_index.items()}
    for key, node in by_key.items():
        e = creates[key][0]
        if node["risk_marker"]:
            d = e["event_data"]
            session_index[(key[0], guid(d.get("LogonGuid")), d.get("User", "").casefold())].append(node)
    for success in events:
        if not is_security(success, 4624) or success["event_data"].get("LogonType") not in ("3", "10"):
            continue
        identity = auth_key(success, True)
        if identity is None: continue
        times = failure_times.get(identity, [])
        at = seconds(success)
        failures = failure_index.get(identity, [])[bisect_left(times, at-auth_window):bisect_right(times, at)]
        if len(failures) < threshold: continue
        logon = guid(success["event_data"].get("LogonGuid"))
        missing = []
        sd = success["event_data"]
        expected_user = (sd["TargetDomainName"] + "\\" + sd["TargetUserName"]).casefold()
        linked = []
        eligible = session_index.get((success["host"].casefold(), logon, expected_user), []) if logon else []
        for node in eligible:
            e = creates[(node["host"].casefold(), node["guid"])][0]; d = e["event_data"]
            if not 0 <= seconds(e)-seconds(success) <= chain_window:
                continue
            if sd.get("TargetLogonId") and d.get("LogonId") and sd["TargetLogonId"].casefold() != d["LogonId"].casefold():
                continue
            if node["risk_marker"]: linked.append(node)
        if not logon: missing.append("nonzero logon GUID")
        if not linked: missing.append("risky process with matching host, logon GUID and domain-qualified user")
        complete = False
        for node in linked:
            executable = creates[(node["host"].casefold(), node["guid"])][0]
            network = [a for a in node["activity"] if a["evidence"]["event_id"] == 3 and 0 <= seconds_from_ref(a["evidence"])-seconds(success) <= chain_window and a["fields"].get("Initiated", "").casefold() == "true"]
            tasks = [e for e in task_index.get(node["id"], []) if 0 <= seconds(e)-seconds(success) <= chain_window]
            if network and tasks:
                complete = True
                stages = [{"name": "Repeated failures", "evidence": [reference(e) for e in failures[-threshold:]]},
                          {"name": "Matching successful network logon", "evidence": [reference(success)]},
                          {"name": "Session-linked risky process", "evidence": [reference(executable)]},
                          {"name": "Process-linked initiated connection", "evidence": [network[0]["evidence"]]},
                          {"name": "Descendant task-creation command", "evidence": [reference(tasks[0])]}]
                identifier = hashlib.sha256((scope["id"] + success["event_uid"] + node["id"]).encode()).hexdigest()
                chains.append({"id": identifier, "rule_id": "CHAIN-001", "title": "Authentication-to-execution-to-task investigation lead",
                               "status": "needs_review", "host": success["host"], "user": expected_user, "stages": stages,
                               "join_basis": ["approved collection source scope", "auth host/account/domain/IP/type", "nonzero LogonGuid + host + user; LogonId checked when present", "ProcessGuid", "observed parent ancestry"],
                               "limitations": ["Not proof of compromise, payload execution, task registration or task execution", "Authorized administrative behavior can match", "Clock skew and missing telemetry can prevent joins", "Only selected command markers are recognized"]})
            else:
                if not network: missing.append("initiated network activity for the risky process")
                if not tasks: missing.append("observed descendant task-creation process")
        candidates.append({"success": reference(success), "failure_count": len(failures), "complete": complete, "missing": sorted(set(missing)) if not complete else []})
    counts = Counter(f"{e['provider']} / {e['event_id']}" for e in events)
    requirements = [("Failed logon", SECURITY, 4625), ("Successful logon", SECURITY, 4624), ("Process creation", SYSMON, 1), ("Network connection", SYSMON, 3), ("Task registration", SECURITY, 4698)]
    from . import __version__
    return {"schema_version": 1, "engine_version": __version__, "engine_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "scenario": scope, "raw_events": raw_count, "unique_observations": len(events), "duplicate_observations": raw_count-len(events),
            "parameters": {"failure_threshold": threshold, "auth_window_seconds": auth_window, "chain_window_seconds": chain_window},
            "nodes": nodes, "edges": edges, "chains": chains, "candidates": candidates, "diagnostics": diagnostics,
            "telemetry": [{"name": name, "provider": provider, "event_id": eid, "count": sum(1 for e in events if (is_security(e,eid) if provider==SECURITY else is_sysmon(e,eid)))} for name,provider,eid in requirements],
            "event_counts": dict(counts), "verdict": "unassessed; correlation creates review leads"}


def seconds_from_ref(ref):
    return seconds(ref)


def write_investigation(db, scope_path, output):
    from .store import iter_events
    output = Path(output)
    if output.exists(): raise ValueError("investigation output already exists")
    result = investigate(iter_events(db), json.loads(Path(scope_path).read_text(encoding="utf-8")))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n", encoding="utf-8", newline="\n")
    return result
