"""Upload validation: type allow-list, size limit, magic-byte agreement.

The goal is to stop an operator (or a compromised account) from storing
executables, HTML with active script content, or oversized files in the evidence
store, while accepting the formats an enforcement case actually needs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from core.security import safe_filename

#: Executable / script signatures that must never be stored as evidence.
DANGEROUS_MAGIC = (
    b"MZ",  # Windows PE
    b"\x7fELF",  # ELF
    b"\xca\xfe\xba\xbe",  # Mach-O fat
    b"\xcf\xfa\xed\xfe",  # Mach-O 64
    b"#!",  # shebang script
)

#: Extension -> accepted magic prefixes. Extensions not listed are treated as
#: text-like and get content checks instead.
MAGIC_BY_EXTENSION: dict[str, tuple[bytes, ...]] = {
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".webp": (b"RIFF",),
    ".pdf": (b"%PDF-",),
    ".mp4": (b"\x00\x00\x00", b"ftyp"),
    ".mov": (b"\x00\x00\x00", b"ftyp", b"moov"),
    ".mp3": (b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"),
    ".m4a": (b"\x00\x00\x00", b"ftyp"),
}

TEXT_EXTENSIONS = {".txt", ".json", ".eml", ".html"}

DOUBLE_EXTENSION_RE = re.compile(
    r"\.(php\d?|phtml|py|rb|pl|sh|bat|cmd|exe|dll|com|scr|js|mjs|jar|apk|msi|ps1|vbs)$",
    re.IGNORECASE,
)

MIME_BY_EXTENSION = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".pdf": "application/pdf",
    ".mp4": "video/mp4",
    ".mov": "video/quicktime",
    ".mp3": "audio/mpeg",
    ".m4a": "audio/mp4",
    ".txt": "text/plain",
    ".json": "application/json",
    ".eml": "message/rfc822",
    ".html": "text/html",
}


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    reason: str = ""
    safe_name: str = ""
    extension: str = ""
    media_type: str = ""


def validate_upload(
    filename: str,
    data: bytes,
    *,
    allowed_extensions: tuple[str, ...],
    max_bytes: int,
) -> ValidationResult:
    original = (filename or "").strip()
    if not original:
        return ValidationResult(False, "uploaded file has no name")
    if "/" in original or "\\" in original or ".." in original:
        return ValidationResult(False, "filename contains a path component")

    extension = Path(original).suffix.lower()
    if extension not in allowed_extensions:
        return ValidationResult(
            False,
            f"file type '{extension or 'none'}' is not allowed "
            f"(allowed: {', '.join(allowed_extensions)})",
        )
    if DOUBLE_EXTENSION_RE.search(original):
        return ValidationResult(False, "double extension with an executable suffix is rejected")
    if not data:
        return ValidationResult(False, "file is empty")
    if len(data) > max_bytes:
        return ValidationResult(
            False, f"file exceeds the {max_bytes // (1024 * 1024)} MB limit"
        )

    head = data[:512]
    for magic in DANGEROUS_MAGIC:
        if head.startswith(magic):
            return ValidationResult(False, "file content looks like an executable or script")

    expected = MAGIC_BY_EXTENSION.get(extension)
    if expected and not any(head.startswith(prefix) for prefix in expected):
        return ValidationResult(
            False, f"file content does not match the '{extension}' extension"
        )

    if extension == ".html":
        lowered = data[:4096].lower()
        if b"<script" in lowered or b"javascript:" in lowered:
            return ValidationResult(
                False,
                "HTML evidence containing script content is rejected; file a screenshot instead",
            )

    return ValidationResult(
        ok=True,
        safe_name=safe_filename(original),
        extension=extension,
        media_type=MIME_BY_EXTENSION.get(extension, "application/octet-stream"),
    )
