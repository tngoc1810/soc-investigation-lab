"""Bounded, scenario-scoped authentication leads; no success is invented."""

from collections import defaultdict, deque

from .detections import auth_key, finding, seconds


BURST_RULE = {
    "id": "AUTH-002", "title": "Repeated failed network logons", "severity": "medium", "attack": ["T1110.001"],
    "rationale": "A concentrated failure burst warrants source/account verification even without a later success.",
    "false_positives": ["Stale service credentials", "Misconfigured clients", "User mistakes behind shared IPs"],
    "limitations": ["No evidence of successful access", "Missing identity/source fields prevent correlation", "One finding per key per window", "Duplicate input events can inflate the threshold"],
}
EXPLICIT_RULE = {
    "id": "AUTH-003", "title": "Explicit credentials used across multiple target accounts", "severity": "medium", "attack": ["T1110.003"],
    "rationale": "One origin using explicit credentials for many accounts is a spray-like lead; 4648 does not establish failures or password reuse.",
    "false_positives": ["Authorized identity testing", "Administration using multiple accounts", "Credential management tools"],
    "limitations": ["4648 records explicit credential use, not authentication outcome", "Password values are unavailable; spraying cannot be confirmed", "One finding per source/subject/target context per window"],
}


def credential_leads(events, *, threshold=10, window_seconds=300, cross_source=False):
    if threshold < 2 or window_seconds < 1:
        raise ValueError("credential threshold must be >= 2 and window must be positive")
    buckets = defaultdict(deque)
    last_alert = {}
    for event in events:
        if event["channel"].casefold() != "security" or event["provider"].casefold() != "microsoft-windows-security-auditing":
            continue
        if event["event_id"] not in (4625, 4648):
            continue
        data = event["event_data"]
        if event["event_id"] == 4625:
            identity = auth_key(event, cross_source)
            if identity is None or data.get("LogonType") not in ("3", "10"):
                continue
            key = ("burst", *identity)
            rule = BURST_RULE
        else:
            names = ("SubjectUserSid", "SubjectUserName", "TargetDomainName", "TargetServerName", "IpAddress")
            values = [data.get(name, "").strip() for name in names]
            account = data.get("TargetUserName", "").strip()
            if any(value in ("", "-") for value in values) or account in ("", "-"):
                continue
            scope = "combined" if cross_source else event["source_sha256"]
            key = ("explicit", scope, event["host"].casefold(), *(value.casefold() for value in values))
            rule = EXPLICIT_RULE
        now = seconds(event)
        for expired_key in list(buckets):
            queue = buckets[expired_key]
            while queue and now - seconds(queue[0]) > window_seconds:
                queue.popleft()
            if not queue:
                del buckets[expired_key]
        for expired_key in list(last_alert):
            if now - last_alert[expired_key] > window_seconds:
                del last_alert[expired_key]
        queue = buckets[key]
        if key[0] == "explicit":
            # Latest evidence per account; retained state is threshold-bounded.
            user = data["TargetUserName"].casefold()
            for prior in tuple(queue):
                if prior["event_data"]["TargetUserName"].casefold() == user:
                    queue.remove(prior)
        queue.append(event)
        while len(queue) > threshold:
            queue.popleft()
        if len(queue) >= threshold and key not in last_alert:
            yield finding(rule, list(queue), f"At least {threshold} {'distinct target accounts' if key[0] == 'explicit' else 'failed network logons'} within {window_seconds}s. {rule['rationale']}")
            last_alert[key] = now
