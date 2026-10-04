"""Parse complete Sigma rules with pySigma; do not pretend to run a SIEM backend."""

import json
from pathlib import Path
from sigma.collection import SigmaCollection

root = Path(__file__).resolve().parents[1]
checks = []
for path in sorted((root / "rules/sigma").glob("*.yml")):
    collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    if collection.errors:
        raise ValueError(f"Sigma parse error in {path.name}")
    for rule in collection.rules:
        for condition in rule.detection.parsed_condition:
            _ = condition.parsed  # Force condition parsing, including referenced selections.
        checks.append({"file": path.name, "id": str(rule.id), "condition": rule.detection.condition, "result": "parsed"})
if len(checks) != 3:
    raise ValueError("expected three Sigma reference rules")
print(json.dumps({"validator": "pySigma", "rules": checks, "scope": "Schema/condition parsing; no live backend execution"}, indent=2))
