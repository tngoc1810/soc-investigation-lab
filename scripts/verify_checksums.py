"""Check published evidence against the reviewed release checksum inventory."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify(root=ROOT):
    root = Path(root).resolve()
    inventory = json.loads((root / "evidence/checksums.json").read_text(encoding="utf-8"))
    actual_files = {path.relative_to(root).as_posix() for path in (root / "evidence").rglob("*")
                    if path.is_file() and path != root / "evidence/checksums.json"}
    if actual_files != set(inventory["files"]):
        raise ValueError("published evidence inventory differs: missing or unlisted files")
    for relative, expected in inventory["files"].items():
        path = (root / relative).resolve()
        if not path.is_relative_to(root / "evidence"):
            raise ValueError("checksum path is outside published evidence")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"published evidence changed: {relative}")
    return len(inventory['files'])


def main():
    print(f"Verified {verify()} published evidence files, including inventory completeness.")


if __name__ == "__main__":
    main()
