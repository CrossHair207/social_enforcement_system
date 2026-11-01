"""Cryptographic hashing used for evidence integrity.

Each stored file keeps a SHA-256 digest in the database. Re-hashing the file on
demand proves whether it changed after collection, which is what makes an
evidence package defensible.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO

CHUNK_SIZE = 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
        digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hashes_match(left: str, right: str) -> bool:
    return bool(left) and bool(right) and left.lower() == right.lower()
