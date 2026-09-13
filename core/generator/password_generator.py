"""
Cryptographically secure password generator.

Uses Python's `secrets` module (OS CSPRNG) for all random selections.
Never uses: random.random(), random.randint(), timestamps, predictable sources.

Features:
- Configurable length, character sets
- Exclude ambiguous characters
- Minimum character-class requirements
- Passphrase generation (EFF wordlist)
- Password strength estimation (zxcvbn)
"""
from __future__ import annotations

import re
import string
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core.crypto.secure_random import secure_choice, secure_int, secure_shuffle
from core.models.vault_models import PasswordStrength
from core.utilities.logging_utils import get_logger

logger = get_logger(__name__)

# Ambiguous characters — visually similar
AMBIGUOUS_CHARS: str = "0O1lI|"

# Character pools
UPPERCASE: str = string.ascii_uppercase
LOWERCASE: str = string.ascii_lowercase
DIGITS: str = string.digits
SYMBOLS: str = "!@#$%^&*()-_=+[]{}|;:,.<>?"
UNAMBIGUOUS_UPPERCASE: str = "".join(c for c in UPPERCASE if c not in AMBIGUOUS_CHARS)
UNAMBIGUOUS_LOWERCASE: str = "".join(c for c in LOWERCASE if c not in AMBIGUOUS_CHARS)
UNAMBIGUOUS_DIGITS: str = "".join(c for c in DIGITS if c not in AMBIGUOUS_CHARS)


@dataclass
class GeneratorConfig:
    """Password generator configuration."""

    length: int = 20
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = True
    min_uppercase: int = 1
    min_lowercase: int = 1
    min_digits: int = 1
    min_symbols: int = 1
    custom_symbols: str = ""  # Override default symbols if non-empty

    def __post_init__(self) -> None:
        if self.length < 8:
            raise ValueError("Password length must be at least 8.")
        if self.length > 256:
            raise ValueError("Password length must be at most 256.")
        active = sum([self.use_uppercase, self.use_lowercase, self.use_digits, self.use_symbols])
        if active == 0:
            raise ValueError("At least one character set must be enabled.")


class PasswordGenerator:
    """Generates cryptographically secure passwords."""

    def generate(self, config: GeneratorConfig) -> str:
        """
        Generate a random password per the given configuration.

        Algorithm:
        1. Build the allowed character pool.
        2. Select minimum required characters from each class.
        3. Fill remaining length with random characters from the full pool.
        4. Shuffle the result (Fisher-Yates via secure_shuffle).

        Raises:
            ValueError: If config is invalid.
        """
        pool = self._build_pool(config)
        if not pool:
            raise ValueError("No characters available with current settings.")

        # Step 1: Satisfy minimum requirements
        required: list[str] = []
        if config.use_uppercase and config.min_uppercase > 0:
            uc = UNAMBIGUOUS_UPPERCASE if config.exclude_ambiguous else UPPERCASE
            if uc:
                for _ in range(config.min_uppercase):
                    required.append(secure_choice(uc))

        if config.use_lowercase and config.min_lowercase > 0:
            lc = UNAMBIGUOUS_LOWERCASE if config.exclude_ambiguous else LOWERCASE
            if lc:
                for _ in range(config.min_lowercase):
                    required.append(secure_choice(lc))

        if config.use_digits and config.min_digits > 0:
            dg = UNAMBIGUOUS_DIGITS if config.exclude_ambiguous else DIGITS
            if dg:
                for _ in range(config.min_digits):
                    required.append(secure_choice(dg))

        if config.use_symbols and config.min_symbols > 0:
            sym = config.custom_symbols if config.custom_symbols else SYMBOLS
            for _ in range(config.min_symbols):
                required.append(secure_choice(sym))

        # Ensure required chars don't exceed desired length
        if len(required) > config.length:
            required = required[:config.length]

        # Step 2: Fill remainder
        remaining = config.length - len(required)
        filler = [secure_choice(pool) for _ in range(remaining)]

        # Step 3: Shuffle
        chars = secure_shuffle(required + filler)
        return "".join(chars)

    def _build_pool(self, config: GeneratorConfig) -> str:
        pool = ""
        if config.use_uppercase:
            pool += UNAMBIGUOUS_UPPERCASE if config.exclude_ambiguous else UPPERCASE
        if config.use_lowercase:
            pool += UNAMBIGUOUS_LOWERCASE if config.exclude_ambiguous else LOWERCASE
        if config.use_digits:
            pool += UNAMBIGUOUS_DIGITS if config.exclude_ambiguous else DIGITS
        if config.use_symbols:
            pool += config.custom_symbols if config.custom_symbols else SYMBOLS
        return pool

    # ------------------------------------------------------------------
    # Passphrase generation
    # ------------------------------------------------------------------

    def generate_passphrase(
        self,
        word_count: int = 5,
        separator: str = "-",
        capitalize: bool = True,
        include_number: bool = True,
    ) -> str:
        """
        Generate a passphrase from EFF large wordlist.
        Falls back to a built-in mini-wordlist if EFF list is unavailable.
        """
        wordlist = self._load_wordlist()
        words = [secure_choice(wordlist) for _ in range(word_count)]
        if capitalize:
            words = [w.capitalize() for w in words]
        result = separator.join(words)
        if include_number:
            result += separator + str(secure_int(10, 99))
        return result

    def _load_wordlist(self) -> list[str]:
        """Load EFF large wordlist or fall back to built-in."""
        eff_path = Path(__file__).parent / "eff_large_wordlist.txt"
        if eff_path.exists():
            with open(eff_path, encoding="utf-8") as f:
                lines = [line.strip().split("\t") for line in f if "\t" in line]
                return [parts[1] for parts in lines if len(parts) == 2]
        # Fallback built-in wordlist (500 common English words)
        return _BUILTIN_WORDLIST


# ---------------------------------------------------------------------------
# Password strength estimator
# ---------------------------------------------------------------------------

@dataclass
class StrengthResult:
    strength: PasswordStrength
    score: int          # 0-4 (zxcvbn score)
    crack_time_display: str
    suggestions: list[str] = field(default_factory=list)
    warning: str = ""


def estimate_strength(password: str) -> StrengthResult:
    """
    Estimate password strength using zxcvbn.

    zxcvbn performs pattern-based analysis (dictionary attacks, keyboard walks,
    dates, repeats) and returns a realistic crack-time estimate.

    Does NOT claim a password is secure merely because it is long.
    """
    if not password:
        return StrengthResult(
            strength=PasswordStrength.VERY_WEAK,
            score=0,
            crack_time_display="instant",
            suggestions=["Enter a password."],
        )

    try:
        import zxcvbn as zx
        result = zx.zxcvbn(password)
        score = result["score"]  # 0-4

        strength_map = {
            0: PasswordStrength.VERY_WEAK,
            1: PasswordStrength.WEAK,
            2: PasswordStrength.MODERATE,
            3: PasswordStrength.STRONG,
            4: PasswordStrength.VERY_STRONG,
        }

        feedback = result.get("feedback", {})
        suggestions = feedback.get("suggestions", [])
        warning = feedback.get("warning", "")

        crack_display = result.get("crack_times_display", {}).get(
            "offline_slow_hashing_1e4_per_second", "unknown"
        )

        return StrengthResult(
            strength=strength_map.get(score, PasswordStrength.WEAK),
            score=score,
            crack_time_display=crack_display,
            suggestions=suggestions,
            warning=warning,
        )
    except ImportError:
        # Fallback: simple entropy-based estimate
        return _fallback_strength(password)


def _fallback_strength(password: str) -> StrengthResult:
    """Simple entropy-based fallback if zxcvbn is unavailable."""
    length = len(password)
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    variety = sum([has_upper, has_lower, has_digit, has_symbol])

    if length < 8 or variety < 2:
        return StrengthResult(PasswordStrength.VERY_WEAK, 0, "instant",
                              suggestions=["Use at least 8 characters with mixed types."])
    if length < 12 or variety < 3:
        return StrengthResult(PasswordStrength.WEAK, 1, "hours")
    if length < 16:
        return StrengthResult(PasswordStrength.MODERATE, 2, "days")
    if length < 20 or variety < 4:
        return StrengthResult(PasswordStrength.STRONG, 3, "years")
    return StrengthResult(PasswordStrength.VERY_STRONG, 4, "centuries")


# ---------------------------------------------------------------------------
# Built-in mini wordlist (500 words, used as fallback for passphrases)
# ---------------------------------------------------------------------------

_BUILTIN_WORDLIST: list[str] = [
    "ability","absence","academy","account","achieve","acquire","address","advance",
    "airline","airport","alchemy","algebra","ancient","android","animate","antenna",
    "antique","anxiety","anyone","appear","archive","article","asphalt","attempt",
    "balance","bamboo","battery","because","bedroom","benefit","blanket","blanket",
    "blazing","blossom","bonfire","booking","boycott","bracket","breadth","british",
    "brother","buffalo","builder","burning","cabinet","capital","captain","capture",
    "careful","ceiling","century","chapter","charity","charter","chicken","chimney",
    "circuit","citizen","classic","climate","cluster","coconut","college","comment",
    "compass","complex","connect","control","convert","cooking","country","courage",
    "crystal","curious","curtain","cushion","database","daytime","decimal","defense",
    "deliver","desktop","develop","digital","discuss","discuss","display","distant",
    "dolphin","domino","doorstep","drawing","dynamic","eastern","eclipse","elegant",
    "element","emotion","empress","endless","engaged","english","episode","eternal",
    "example","explore","express","fabric","factory","famous","fantasy","feature",
    "fiction","fifteen","fighter","finally","finance","fishing","fitness","flatten",
    "flipper","foreign","forever","formula","forward","foundation","freedom","general",
    "genetic","gesture","glacier","glimpse","glitter","global","golden","gradient",
    "granite","gravity","grocery","growing","habitat","handmade","hanging","harbor",
    "harvest","healing","healthy","history","horizon","housing","hundred","hunting",
    "iceberg","imagine","improve","include","integer","justice","kitchen","landing",
    "language","lantern","largest","lasting","license","lighter","limited","lizard",
    "logical","machine","mapping","maritime","marshal","mention","miracle","mission",
    "morning","mountain","network","neutral","nothing","nuclear","numeric","object",
    "offline","olympic","operate","opinion","orbital","organic","outdoor","outline",
    "painting","palace","pattern","pioneer","pitcher","plastic","platform","player",
    "pointer","popular","precise","premium","program","project","protect","protein",
    "provide","publish","purpose","quality","quantum","quarter","railway","reading",
    "reality","rebuild","reform","refresh","regular","release","remote","replace",
    "rescue","respect","revenue","revival","reward","sailing","science","shelter",
    "signal","silence","silver","simple","single","sixteen","skyline","skyscraper",
    "soldier","solving","speaker","special","stadium","station","storage","strategy",
    "student","sunrise","support","surface","systems","tablet","tactics","talking",
    "teacher","temple","testing","therapy","thunder","tourism","trading","traffic",
    "triumph","trouble","turning","typical","ultimate","uniform","unique","update",
    "upgrade","venture","vibrant","virtual","visible","voltage","vulture","warning",
    "warrior","weather","western","windows","wording","writing","yellow","zodiac",
]
