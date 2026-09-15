"""Package entry point for the SecureVault desktop app."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    """Launch the SecureVault desktop application."""
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from main import main as _main

    _main()


if __name__ == "__main__":
    main()
