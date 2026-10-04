"""Run with python -m soclab from the repository root."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys

from .report import analyze
from .store import ingest, iter_events
from .query import QUERY_NAMES, run_query


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
    p.add_argument("--credential-threshold", type=int, default=10)
    p.add_argument("--credential-window", type=int, default=300)
    p.add_argument("--context", type=Path, help="Exact context allowlist; matching findings remain auditable")
    p = sub.add_parser("investigate", help="Build a source-scoped process graph and explainable investigation chains")
    p.add_argument("--db", type=Path, required=True)
    p.add_argument("--scope", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p = sub.add_parser("evaluate", help="Evaluate scenario-level review labels on the synthetic development/holdout corpus")
    p.add_argument("--out", type=Path, default=Path("output/evaluation.json"))
    p = sub.add_parser("search", help="Search original events, not only alert matches")
    p.add_argument("--db", type=Path, required=True)
    p.add_argument("--host")
    p.add_argument("--user")
    p.add_argument("--start", help="Timezone-aware ISO timestamp, inclusive")
    p.add_argument("--end", help="Timezone-aware ISO timestamp, inclusive")
    p.add_argument("--event-id", type=int)
    p.add_argument("--term")
    p.add_argument("--limit", type=int, default=50)
    p = sub.add_parser("query", help="Execute a checked-in SQLite investigation query (read-only)")
    p.add_argument("name", choices=QUERY_NAMES)
    p.add_argument("--db", type=Path, required=True)
    p = sub.add_parser("serve", help="Open the local, read-only case explorer")
    p.add_argument("--index", type=Path, default=Path("output/portfolio/index.json"))
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--operations-db", type=Path, help="Enable analyst case decisions in a separate local database")
    p = sub.add_parser("case", help="Manage analyst decisions separately from source evidence")
    p.add_argument("action", choices=("list", "show", "update", "export"))
    p.add_argument("--workspace", type=Path, default=Path("output/operations/cases.sqlite"))
    p.add_argument("--id")
    p.add_argument("--revision", type=int)
    p.add_argument("--target")
    p.add_argument("--verdict")
    p.add_argument("--actor", default="local-analyst")
    p.add_argument("--rationale")
    p.add_argument("--out", type=Path, default=Path("output/operations/exports"))
    p = sub.add_parser("hunt", help="Execute eight fixed read-only investigation hypotheses")
    p.add_argument("--db", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p = sub.add_parser("forensics", help="Reconstruct complete PowerShell 4104 blocks without executing them")
    p.add_argument("--db", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p = sub.add_parser("decode", help="Decode a supported PowerShell encoded host argument as text")
    p.add_argument("--command-file", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "ingest":
            print(json.dumps(ingest(args.source, args.db), indent=2))
        elif args.command == "analyze":
            manifest = analyze(args.db, args.rules, args.out, threshold=args.auth_threshold, window_seconds=args.auth_window_seconds, cross_source=args.cross_source_auth, credential_threshold=args.credential_threshold, credential_window=args.credential_window, context_path=args.context)
            print(json.dumps({k: manifest[k] for k in ("event_count", "finding_count", "findings_by_rule", "processing_seconds", "verdict")}, indent=2))
        elif args.command == "query":
            print(json.dumps(run_query(args.db, args.name), ensure_ascii=False, indent=2))
        elif args.command == "investigate":
            from .investigation import write_investigation
            result = write_investigation(args.db, args.scope, args.out)
            print(json.dumps({k: result[k] for k in ("raw_events", "unique_observations", "duplicate_observations", "chains", "candidates")}, indent=2))
        elif args.command == "evaluate":
            from .corpus import write_evaluation
            print(json.dumps(write_evaluation(args.out)["metrics"], indent=2))
        elif args.command == "serve":
            from .webapp import serve
            serve(args.index, args.port, args.operations_db)
        elif args.command == "case":
            from .operations import list_cases, get_case, update_case, export_case
            if args.action == "list": result = list_cases(args.workspace)
            elif args.action == "show": result = get_case(args.workspace, args.id)
            elif args.action == "export": result = export_case(args.workspace, args.id, args.out)
            else: result = update_case(args.workspace, args.id, revision=args.revision, action="transition" if args.target else "note", target=args.target, verdict=args.verdict, actor=args.actor, rationale=args.rationale)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif args.command in ("hunt", "forensics", "decode"):
            if args.command == "hunt":
                from .hunting import run_hunts
                result = run_hunts(args.db)
            elif args.command == "forensics":
                from .forensics import reconstruct
                result = reconstruct(iter_events(args.db))
            else:
                from .forensics import decode_command
                result = decode_command(args.command_file.read_text(encoding="utf-8-sig"))
            args.out.parent.mkdir(parents=True, exist_ok=True)
            with args.out.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(result, indent=2, ensure_ascii=False)+"\n")
            print(f"Wrote {args.command} artifact: {args.out}")
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
