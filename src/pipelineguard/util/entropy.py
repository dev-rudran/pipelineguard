"""Shannon entropy and placeholder detection for secret scanning."""

from __future__ import annotations

import math
import re
from collections import Counter

# Values that are obviously documentation, template or test data.
PLACEHOLDER_TOKENS = frozenset(
    {
        "changeme",
        "change_me",
        "change-me",
        "changethis",
        "example",
        "examples",
        "examplekey",
        "example_key",
        "example-key",
        "placeholder",
        "dummy",
        "fake",
        "sample",
        "secret",
        "password",
        "passw0rd",
        "hunter2",
        "yourkey",
        "your_key",
        "your-key",
        "yourapikey",
        "your_api_key",
        "your-api-key",
        "yourtoken",
        "your_token",
        "your-token",
        "insert_key_here",
        "insert-key-here",
        "todo",
        "fixme",
        "redacted",
        "notasecret",
        "not_a_real_secret",
        "test",
        "testing",
        "foo",
        "bar",
        "baz",
        "lorem",
        "ipsum",
        "0123456789",
        "abcdefghij",
    }
)

_PLACEHOLDER_PATTERNS = (
    re.compile(r"^\$\{[^}]*\}$"),  # ${VAR}
    re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),  # $VAR
    re.compile(r"^<[^>]*>$"),  # <your-key>
    re.compile(r"^\{\{[^}]*\}\}$"),  # {{ secrets.X }}
    re.compile(r"^%[A-Za-z_][A-Za-z0-9_]*%$"),  # %VAR%
    re.compile(r"^x{5,}$", re.IGNORECASE),  # xxxxx
    re.compile(r"^\*{3,}$"),  # ***
    re.compile(r"^\.{3,}$"),  # ...
    re.compile(r"^0{5,}$"),  # 00000
    re.compile(
        r"^(?:[A-Za-z0-9]+[_-])?(?:example|sample|dummy|fake|test|placeholder)[A-Za-z0-9_-]*$",
        re.IGNORECASE,
    ),
    re.compile(r"^[A-Za-z]*\.\.\.[A-Za-z]*$"),
    re.compile(r"^(?:process\.env|os\.environ|os\.getenv|import\.meta\.env)\b", re.IGNORECASE),
    re.compile(
        r"^(?:your|my)[-_]?(?:super[-_]?)?(?:secret|password|token|api[-_]?key)", re.IGNORECASE
    ),
    re.compile(
        r"^(?:secret|password|token|api[-_]?key)[-_]?(?:here|goes[-_]?here|value)$", re.IGNORECASE
    ),
)

# Documented, publicly published example credentials. They are safe by definition
# and would otherwise create permanent noise in every repository that follows
# vendor documentation.
KNOWN_EXAMPLE_VALUES = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "AKIAI44QH8DHBEXAMPLE",
        "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "sk_test_4eC39HqLyjWDarjtT1" + "zdp7dc",
        "sk_test_51H8xEXAMPLE",
        "xoxb-000000000000-000000000000-" + "000000000000000000000000",
        "SG.1234567890abcdefghijklmnopqrstuv.1234567890abcdefghijklmnopqrstuvwxyz1234567890",
    }
)

_ALPHABET_NORMALIZERS = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "$": "s", "@": "a"}
)


def shannon_entropy(value: str) -> float:
    """Return Shannon entropy in bits per character for *value*.

    An empty string has zero entropy. The maximum for printable ASCII is about
    6.57 bits per character, which is what a uniformly random 32 character
    hexadecimal string approaches when all 16 symbols are present.
    """
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def normalized_entropy(value: str) -> float:
    """Entropy after folding common substitutions, used to catch l33t secrets."""
    return shannon_entropy(value.translate(_ALPHABET_NORMALIZERS))


def is_placeholder(value: str) -> bool:
    """Heuristically decide whether *value* is placeholder documentation text."""
    raw = value.strip().strip("'\"").strip()
    if not raw:
        return True
    if raw in KNOWN_EXAMPLE_VALUES:
        return True
    lowered = raw.lower()
    if lowered in PLACEHOLDER_TOKENS:
        return True
    if any(pattern.match(raw) for pattern in _PLACEHOLDER_PATTERNS):
        return True
    # Long-form placeholders such as "your-super-secret-api-key-here".
    collapsed = re.sub(r"[^a-z0-9]", "", lowered)
    if any(
        token in collapsed
        for token in ("changeme", "placeholder", "yourkey", "yourapikey", "yourtoken")
    ):
        return True
    if lowered.startswith(("your", "my")) and any(
        token in collapsed for token in ("secret", "password", "token", "apikey")
    ):
        return True
    return collapsed in {"", "password", "secret", "token", "apikey"}


def looks_random(value: str, threshold: float = 3.5, min_length: int = 16) -> bool:
    """True when *value* is long enough and random enough to be a credential."""
    if len(value) < min_length:
        return False
    if is_placeholder(value):
        return False
    # A value made of one repeated character is never a real credential.
    if len(set(value)) < 5:
        return False
    return normalized_entropy(value) >= threshold
