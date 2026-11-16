"""Text helpers: safe file reading, binary detection, redaction and escaping."""

from __future__ import annotations

import html
import os
import re
from pathlib import Path

MAX_TEXT_BYTES = 2 * 1024 * 1024
SNIPPET_LIMIT = 180

_BINARY_SNIFF = 8192
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_WHITESPACE = re.compile(r"\s+")


def is_binary_bytes(data: bytes) -> bool:
    """Detect binary content without relying on file extensions."""
    if not data:
        return False
    if b"\x00" in data[:_BINARY_SNIFF]:
        return True
    sample = data[:_BINARY_SNIFF]
    if not sample:
        return False
    suspicious = sum(1 for byte in sample if byte < 9 or 13 < byte < 32)
    return suspicious / len(sample) > 0.30


def is_probably_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return is_binary_bytes(handle.read(_BINARY_SNIFF))
    except OSError:
        return False


def read_text(path: Path, max_bytes: int = MAX_TEXT_BYTES) -> str | None:
    """Read a UTF-8 text file, returning ``None`` for binary or oversized files."""
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if is_binary_bytes(data):
        return None
    return data.decode("utf-8", errors="replace")


def is_skipped_dir(name: str, extra: set[str] | None = None) -> bool:
    skipped = {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        "dist",
        "build",
        ".pipelineguard-cache",
    }
    if extra:
        skipped |= extra
    return name in skipped


def redact(value: str, keep: int = 4) -> str:
    """Redact a secret, keeping only its first and last four characters.

    Values shorter than 12 characters are fully masked because a short prefix
    and suffix would reveal most of the credential.
    """
    if not value:
        return ""
    if len(value) < 12:
        return "*" * len(value)
    if len(value) <= keep * 2 + 4:
        return value[:keep] + "..." + value[-keep:]
    return value[:keep] + "..." + value[-keep:]


def snippet(text: str, limit: int = SNIPPET_LIMIT) -> str:
    """Collapse whitespace and bound a snippet for reports."""
    cleaned = _WHITESPACE.sub(" ", text).strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3] + "..."


def normalize_context(value: str) -> str:
    """Normalize context so fingerprints survive moves and reindentation."""
    lowered = _WHITESPACE.sub(" ", value.strip().lower())
    return lowered


def escape_markdown(value: str) -> str:
    """Escape a value for safe inline use in Markdown."""
    escaped = value.replace("\\", "\\\\")
    for char in ("`", "*", "_", "[", "]", "<", ">", "|", "#", "!", "(", ")"):
        escaped = escaped.replace(char, "\\" + char)
    return escaped


def escape_html(value: str) -> str:
    return html.escape(value, quote=True)


def strip_control(value: str) -> str:
    return _CONTROL_CHARS.sub("", value)


def safe_relpath(path: Path, root: Path) -> str:
    """Return a POSIX relative path, falling back to the absolute path."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return path.as_posix()


def inside_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def format_bytes(size: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.0f} B"


def relative_display(path: str, root: Path) -> str:
    if not path:
        return path
    candidate = Path(path)
    if candidate.is_absolute() and inside_root(candidate, root):
        return os.path.relpath(candidate, root)
    return path
