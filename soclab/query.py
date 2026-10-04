"""Execute checked-in investigation queries against a read-only database."""

from contextlib import closing
from pathlib import Path
import sqlite3

QUERY_NAMES = ("mshta_remote", "auth_summary", "powershell_content")


def run_query(db: Path, name: str):
    if name not in QUERY_NAMES:
        raise ValueError("unknown query name")
    if not Path(db).is_file():
        raise ValueError("database does not exist")
    root = Path(__file__).resolve().parents[1]
    sql = (root / "queries" / "sqlite" / f"{name}.sql").read_text(encoding="utf-8")
    with closing(sqlite3.connect(Path(db).resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        return [dict(row) for row in conn.execute(sql)]
