"""Create the schema on a PostgreSQL database.

Usage::

    python database/migrations/init_postgres.py

Reads ``DATABASE_URL`` from the environment or ``.env``. Refuses to run against
SQLite so it cannot be mistaken for the development database.
"""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from config import settings  # noqa: E402
from core.database import configure, init_db  # noqa: E402


def main() -> int:
    url = settings.database_url
    if url.startswith("sqlite"):
        print("This script is for PostgreSQL. DATABASE_URL currently points at SQLite.")
        return 1
    parsed = urlsplit(url)
    print(f"Creating schema on {parsed.hostname}:{parsed.port or 5432}{parsed.path}")
    configure(url)
    init_db()
    print("Schema ready.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
