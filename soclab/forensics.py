"""Bounded script-block reconstruction. Script content is never executed."""

from collections import defaultdict
import base64
import binascii
import hashlib
import shlex

from .investigation import reference


def reconstruct(events, *, maximum_chars=262144):
    groups, rejected = defaultdict(list), []
    for event in events:
        if event["event_id"] != 4104 or event["provider"].casefold() != "microsoft-windows-powershell" or event["channel"].casefold() != "microsoft-windows-powershell/operational":
            continue
        fields = event["event_data"]
        block = fields.get("ScriptBlockId", "")
        if not block:
            rejected.append({"reason":"missing ScriptBlockId", "evidence":reference(event)})
            continue
        # A file boundary is retained: unrelated exports require explicit review.
        key = (event["source_sha256"], event["host"].casefold(), block.casefold())
        groups[key].append(event)
    result = []
    for key, records in groups.items():
        totals, parts, reasons = set(), defaultdict(set), []
        for event in records:
            fields = event["event_data"]
            try:
                number, total = int(fields["MessageNumber"]), int(fields["MessageTotal"])
                if not 1 <= number <= total <= 1000:
                    raise ValueError()
                fragment = fields["ScriptBlockText"]
                if not isinstance(fragment, str): raise ValueError()
                totals.add(total); parts[number].add(fragment)
            except (KeyError, TypeError, ValueError):
                reasons.append("invalid fragment metadata")
        if len(totals) != 1: reasons.append("inconsistent message totals")
        if any(len(values) != 1 for values in parts.values()): reasons.append("conflicting fragment content")
        expected = next(iter(totals)) if len(totals) == 1 else None
        missing = sorted(set(range(1, expected+1))-set(parts)) if expected else []
        if missing: reasons.append("missing message parts")
        length = sum(len(next(iter(values))) for values in parts.values())
        if length > maximum_chars: reasons.append("script exceeds reconstruction limit")
        complete = not reasons
        script = "".join(next(iter(parts[n])) for n in range(1, expected+1)) if complete else None
        result.append({"source_sha256":key[0], "host":records[0]["host"], "script_block_id":key[2],
                       "complete":complete, "expected_parts":expected, "observed_parts":sorted(parts), "missing_parts":missing,
                       "reasons":sorted(set(reasons)), "script":script,
                       "script_sha256":hashlib.sha256(script.encode()).hexdigest() if script is not None else None,
                       "evidence":[reference(e) for e in records], "assessment":"Static text reconstruction; not proof that each statement executed"})
    return {"blocks":result, "rejected":rejected, "scope":"same host + ScriptBlockId + source hash; cross-file and runspace attribution require analyst review"}


def decode_command(command, *, maximum_bytes=262144):
    """Selected exact host switches; not a complete Windows command-line parser."""
    try: tokens=shlex.split(command, posix=False)
    except ValueError: raise ValueError("unbalanced command quoting") from None
    if not tokens or tokens[0].strip('"').replace("/", "\\").rsplit("\\",1)[-1].casefold() not in ("powershell.exe","pwsh.exe"):
        raise ValueError("expected a PowerShell executable")
    for index, token in enumerate(tokens[1:],1):
        if token.casefold() in ("-file","-f","-command","-c"):
            raise ValueError("no supported encoded host argument before script content")
        if token.casefold() in ("-enc","-encodedcommand"):
            if index+1 == len(tokens): raise ValueError("missing encoded argument")
            encoded=tokens[index+1].strip('"')
            if len(encoded) > 4*((maximum_bytes+2)//3): raise ValueError("encoded input exceeds limit")
            try:
                raw=base64.b64decode(encoded,validate=True)
                if len(raw)>maximum_bytes: raise ValueError("decoded input exceeds limit")
                script=raw.decode("utf-16-le",errors="strict")
            except (binascii.Error, UnicodeError) as exc: raise ValueError("invalid Base64 / UTF-16LE argument") from exc
            return {"script":script,"decoded_sha256":hashlib.sha256(raw).hexdigest(),"encoding":"UTF-16LE","assessment":"Decoded for inspection only; never executed"}
    raise ValueError("no supported encoded host argument")
