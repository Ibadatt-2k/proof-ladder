"""Export every analyst correction in the database into tests/regression/cases.jsonl."""
from pathlib import Path

from app.db import SessionLocal, init_db
from app.pipeline import export_regressions

if __name__ == "__main__":
    init_db()
    with SessionLocal() as db:
        n = export_regressions(db, Path(__file__).resolve().parent.parent / "tests" / "regression" / "cases.jsonl")
    print(f"{n} regression case(s) written")
