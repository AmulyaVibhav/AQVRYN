"""
Unit tests for password generator.
"""
from __future__ import annotations

import sys

import pytest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent.parent))

from core.generator.password_generator import (
    LOWERCASE,
    SYMBOLS,
    UPPERCASE,
    GeneratorConfig,
    PasswordGenerator,
    estimate_strength,
)
from core.models.vault_models import PasswordStrength


class TestPasswordGenerator:
    def _gen(self, **kwargs) -> str:
        config = GeneratorConfig(**kwargs)
        return PasswordGenerator().generate(config)

    def test_correct_length(self):
        for length in [8, 16, 20, 32, 64]:
            pw = self._gen(length=length)
            assert len(pw) == length

    def test_uppercase_present(self):
        pw = self._gen(
            length=30, use_uppercase=True, use_lowercase=False,
            use_digits=False, use_symbols=False,
            min_uppercase=1, min_lowercase=0, min_digits=0, min_symbols=0,
        )
        assert any(c in UPPERCASE for c in pw)
        assert not any(c in LOWERCASE for c in pw)

    def test_lowercase_present(self):
        pw = self._gen(
            length=30, use_uppercase=False, use_lowercase=True,
            use_digits=False, use_symbols=False,
            min_uppercase=0, min_lowercase=1, min_digits=0, min_symbols=0,
        )
        assert any(c in LOWERCASE for c in pw)

    def test_digits_present(self):
        pw = self._gen(
            length=30, use_uppercase=False, use_lowercase=False,
            use_digits=True, use_symbols=False,
            min_uppercase=0, min_lowercase=0, min_digits=1, min_symbols=0,
        )
        assert any(c.isdigit() for c in pw)

    def test_symbols_present(self):
        pw = self._gen(
            length=30, use_uppercase=False, use_lowercase=False,
            use_digits=False, use_symbols=True,
            min_uppercase=0, min_lowercase=0, min_digits=0, min_symbols=1,
        )
        assert any(c in SYMBOLS for c in pw)

    def test_exclude_ambiguous(self):
        from core.generator.password_generator import AMBIGUOUS_CHARS
        pw = self._gen(length=50, exclude_ambiguous=True)
        assert not any(c in AMBIGUOUS_CHARS for c in pw)

    def test_minimum_requirements_satisfied(self):
        pw = self._gen(
            length=20,
            use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True,
            min_uppercase=2, min_lowercase=2, min_digits=2, min_symbols=2,
        )
        assert sum(1 for c in pw if c in UPPERCASE) >= 2
        assert sum(1 for c in pw if c in LOWERCASE) >= 2
        assert sum(1 for c in pw if c.isdigit()) >= 2
        assert sum(1 for c in pw if c in SYMBOLS) >= 2

    def test_uniqueness(self):
        """Generated passwords should rarely repeat (probabilistic)."""
        pws = {self._gen(length=20) for _ in range(50)}
        assert len(pws) >= 48, "Expected high password uniqueness"

    def test_no_charset_raises(self):
        with pytest.raises(ValueError):
            GeneratorConfig(
                use_uppercase=False, use_lowercase=False,
                use_digits=False, use_symbols=False,
            )

    def test_short_length_raises(self):
        with pytest.raises(ValueError):
            GeneratorConfig(length=4)

    def test_passphrase_word_count(self):
        pg = PasswordGenerator()
        pp = pg.generate_passphrase(word_count=5, separator="-", include_number=False)
        words = pp.split("-")
        assert len(words) == 5

    def test_passphrase_with_number(self):
        pg = PasswordGenerator()
        pp = pg.generate_passphrase(word_count=4, separator=" ", include_number=True)
        assert any(part.isdigit() for part in pp.split())

    def test_passphrase_capitalization(self):
        pg = PasswordGenerator()
        pp = pg.generate_passphrase(word_count=4, capitalize=True)
        words = [w for w in pp.replace("-", " ").split() if w.isalpha()]
        assert all(w[0].isupper() for w in words)


class TestPasswordStrength:
    def test_empty_password_is_very_weak(self):
        result = estimate_strength("")
        assert result.strength == PasswordStrength.VERY_WEAK

    def test_short_simple_password_is_weak(self):
        result = estimate_strength("password")
        assert result.score <= 1

    def test_long_random_password_is_strong(self):
        result = estimate_strength("J#9kP@mN!2qX$vL5^wR8")
        assert result.score >= 3

    def test_common_password_is_weak(self):
        result = estimate_strength("123456")
        assert result.score <= 1

    def test_strength_provides_crack_time(self):
        result = estimate_strength("somePassw0rd!")
        assert result.crack_time_display != ""
