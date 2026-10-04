"""Run with python -m soclab from the repository root."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys

from .report import analyze
from .store import ingest, iter_events


def main(argv=None) -> int:
    # Windows console encodings may not support evidence or workspace names.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Offline Windows SOC investigation lab; findings require analyst review.")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("ingest", help="Atomically import a JSONL evidence file")
    p.add_argument("source", type=Path)
    p.add_argument("--db", type=Path, required=True)
    p = sub.add_parser("analyze", help="Export timeline, findings and a draft analyst report")
    p.add_argument("--db", type=Path, required=True)
    p.add_argument("--rules", type=Path, default=Path("rules/windows.json"))
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--auth-threshold", type=int, default=5)
    p.add_argument("--auth-window-seconds", type=int, default=600)
    p.add_argument("--cross-source-auth", action="store_true", help="Only for exports verified to belong to the same scenario; duplicates can inflate counts")
    p = sub.add_parser("search", help="Search original events, not only alert matches")
    p.add_argument("--db", type=Path, required=True)
    p.add_argument("--host")
    p.add_argument("--user")
    p.add_argument("--start", help="Timezone-aware ISO timestamp, inclusive")
    p.add_argument("--end", help="Timezone-aware ISO timestamp, inclusive")
    p.add_argument("--event-id", type=int)
    p.add_argument("--term")
    p.add_argument("--limit", type=int, default=50)
    args = parser.parse_args(argv)
    try:
        if args.command == "ingest":
            print(json.dumps(ingest(args.source, args.db), indent=2))
        elif args.command == "analyze":
            manifest = analyze(args.db, args.rules, args.out, threshold=args.auth_threshold, window_seconds=args.auth_window_seconds, cross_source=args.cross_source_auth)
            print(json.dumps({k: manifest[k] for k in ("event_count", "finding_count", "findings_by_rule", "processing_seconds", "verdict")}, indent=2))
        else:
            if args.limit < 1:
                raise ValueError("--limit must be positive")
            from itertools import islice
            for event in islice(iter_events(args.db, host=args.host, user=args.user, start=args.start, end=args.end, event_id=args.event_id, term=args.term), args.limit):
                print(json.dumps(event, ensure_ascii=False))
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"soclab: {exc}", file=sys.stderr)
        return 2
    return 0
