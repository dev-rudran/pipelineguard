"""Unit tests for entropy and placeholder detection."""

from __future__ import annotations

import math

import pytest

from pipelineguard.util.entropy import (
    KNOWN_EXAMPLE_VALUES,
    is_placeholder,
    looks_random,
    normalized_entropy,
    shannon_entropy,
)


def test_entropy_empty_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_single_character_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_two_symbols():
    assert shannon_entropy("abababab") == pytest.approx(1.0)


def test_entropy_uniform_distribution():
    assert shannon_entropy("abcd") == pytest.approx(2.0)
    assert shannon_entropy("abcdefgh") == pytest.approx(3.0)


def test_entropy_random_value_is_high():
    assert shannon_entropy("kQ3rT8vW2xZ5aB7cD9eF1gH4jK6mN0pQ2sT4uV6w") > 4.0


def test_entropy_matches_manual_calculation():
    value = "aabbc"
    expected = -(2 / 5 * math.log2(2 / 5) + 2 / 5 * math.log2(2 / 5) + 1 / 5 * math.log2(1 / 5))
    assert shannon_entropy(value) == pytest.approx(expected)


def test_normalized_entropy_folds_substitutions():
    assert normalized_entropy("pa55w0rd") < shannon_entropy("pa55w0rd") + 0.01


@pytest.mark.parametrize(
    "value",
    [
        "",
        "changeme",
        "CHANGEME",
        "example",
        "placeholder",
        "xxxxxxx",
        "********",
        "${API_KEY}",
        "$API_KEY",
        "<your-key>",
        "{{ secrets.TOKEN }}",
        "%API_KEY%",
        "your-super-secret-key-here",
        "my-api-key",
        "process.env.API_KEY",
        "os.environ",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ],
)
def test_placeholder_detection(value):
    assert is_placeholder(value)


@pytest.mark.parametrize(
    "value",
    [
        "kQ3rT8vW2xZ5aB7cD9eF1gH4jK6mN0pQ2sT4uV6w",
        "AKIAQ7Z2M4N6P8R1T3V5",
        "rJCZ1UbCHb8RyYiBG7Qb08Y3sKl4FCB8",
    ],
)
def test_non_placeholders(value):
    assert not is_placeholder(value)


def test_documented_examples_are_known():
    assert "AKIAIOSFODNN7EXAMPLE" in KNOWN_EXAMPLE_VALUES
    assert "AKIAI44QH8DHBEXAMPLE" in KNOWN_EXAMPLE_VALUES


@pytest.mark.parametrize(
    "value,expected",
    [
        ("short", False),
        ("aaaaaaaaaaaaaaaaaaaaaaaa", False),
        ("kQ3rT8vW2xZ5aB7cD9eF1gH4jK6mN0pQ2sT4uV6w", True),
        ("AKIAQ7Z2M4N6P8R1T3V5", True),
        ("changeme-changeme-changeme", False),
    ],
)
def test_looks_random(value, expected):
    assert looks_random(value, threshold=3.5, min_length=16) is expected


def test_looks_random_threshold_is_configurable():
    value = "AbCdEfGhIjKlMnOp"
    assert looks_random(value, threshold=1.0, min_length=16) is True
    assert looks_random(value, threshold=5.9, min_length=16) is False
