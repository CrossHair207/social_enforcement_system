"""CSV / JSON export helpers used by the dashboard and tests."""

from __future__ import annotations

import csv
import io
import json
from typing import Iterable, Mapping, Sequence


def to_csv(rows: Iterable[Mapping[str, object]], columns: Sequence[str]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(columns), extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row.get(key, "") for key in columns})
    return buffer.getvalue()


def to_json(payload: object) -> str:
    return json.dumps(payload, indent=2, default=str, sort_keys=False)


def parse_csv(text: str) -> list[dict[str, str]]:
    """Parse an uploaded CSV into a list of dictionaries (lower-cased keys)."""
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        return []
    return [
        {(key or "").strip().lower(): (value or "").strip() for key, value in row.items()}
        for row in reader
    ]


def parse_json_records(text: str) -> list[dict]:
    data = json.loads(text or "[]")
    if isinstance(data, dict):
        data = data.get("targets", [])
    if not isinstance(data, list):
        raise ValueError("JSON import expects a list of objects")
    return [item for item in data if isinstance(item, dict)]
