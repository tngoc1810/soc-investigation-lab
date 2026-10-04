"""Check published evidence against the reviewed release checksum inventory."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    inventory = json.loads((ROOT / "evidence/checksums.json").read_text(encoding="utf-8"))
    for relative, expected in inventory["files"].items():
        path = (ROOT / relative).resolve()
        if not path.is_relative_to(ROOT / "evidence"):
            raise ValueError("checksum path is outside published evidence")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"published evidence changed: {relative}")
    print(f"Verified {len(inventory['files'])} published evidence files.")


if __name__ == "__main__":
    main()
