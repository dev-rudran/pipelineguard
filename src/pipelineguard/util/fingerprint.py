"""Stable finding fingerprints.

A fingerprint must survive line shifts, re-indentation and reordering so that
policy allowances and baselines keep working after a file is reformatted.
The fingerprint therefore hashes the scanner, rule identifier, path and a
normalized context string; it never includes line numbers and never includes
the raw secret.
"""

from __future__ import annotations

import hashlib

from .text import normalize_context


def fingerprint(
    scanner: str,
    rule_id: str,
    path: str,
    context: str,
    length: int = 16,
) -> str:
    """Return ``sha256(scanner + rule_id + path + normalized_context)[:length]``."""
    normalized = normalize_context(context)
    material = "\x00".join((scanner.strip().lower(), rule_id.strip(), path.strip(), normalized))
    digest = hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()
    return digest[:length]


def short_hash(value: str, length: int = 8) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:length]
