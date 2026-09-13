#!/usr/bin/env python3
"""
Build script for desktop packaging using PyInstaller.
Supports: Windows, Linux, macOS.
"""
import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent


def build():
    system = platform.system()
    print(f"Building SecureVault for {system}...")

    icon_flag = []
    if system == "Windows":
        icon_path = ROOT / "assets" / "icon.ico"
        if icon_path.exists():
            icon_flag = ["--icon", str(icon_path)]
    elif system == "Darwin":
        icon_path = ROOT / "assets" / "icon.icns"
        if icon_path.exists():
            icon_flag = ["--icon", str(icon_path)]

    sep = ";" if system == "Windows" else ":"

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "SecureVault",
        "--onefile",
        "--windowed",
        f"--add-data", f"config{sep}config",
        *icon_flag,
        str(ROOT / "main.py"),
    ]

    result = subprocess.run(cmd, cwd=str(ROOT))
    if result.returncode != 0:
        print("Build FAILED.")
        sys.exit(1)

    print("Build complete. Check the 'dist/' directory.")


if __name__ == "__main__":
    build()
