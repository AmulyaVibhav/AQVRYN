#!/usr/bin/env python3
"""
SecureVault Password Manager — main entry point.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is on the path
_ROOT = Path(__file__).parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def main() -> None:
    """Launch the desktop application."""
    from config.settings import validate_crypto_config
    validate_crypto_config()

    from desktop.application.app import main as _main
    _main()


if __name__ == "__main__":
    main()
