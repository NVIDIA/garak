"""Regression tests for the badchars probe ASCII variant cap."""

import pytest

from garak.probes.badchars import ASCII_PRINTABLE, BadCharacters


@pytest.mark.parametrize(
    ("limit", "expected_count"),
    [
        (1, 1),
        (2, 2),
        (3, 3),
    ],
)
def test_select_ascii_respects_small_limits(limit: int, expected_count: int) -> None:
    selected = BadCharacters._select_ascii(limit)

    assert len(selected) == expected_count
    assert all(character in ASCII_PRINTABLE for character in selected)
