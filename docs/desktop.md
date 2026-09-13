# Desktop Packaging Guide

## Windows — PyInstaller EXE

```bash
pip install pyinstaller

pyinstaller --name SecureVault \
    --onefile \
    --windowed \
    --icon assets/icon.ico \
    --add-data "config;config" \
    main.py

# Output: dist/SecureVault.exe
```

## Linux — AppImage / tar.gz

```bash
pyinstaller --name SecureVault \
    --onefile \
    --add-data "config:config" \
    main.py

# Output: dist/SecureVault
```

For AppImage packaging, use `appimagetool` after creating the PyInstaller output.

## macOS — .app Bundle

```bash
pyinstaller --name SecureVault \
    --onefile \
    --windowed \
    --icon assets/icon.icns \
    --add-data "config:config" \
    --target-arch x86_64 \
    main.py

# For Apple Silicon + Intel universal binary:
# --target-arch universal2
```

## Build Script

```bash
scripts/build_desktop.sh   # Linux/macOS
scripts/build_desktop.bat  # Windows
```

## Requirements

- PyInstaller ≥ 6.6.0
- All dependencies installed in the virtual environment
- PyQt6 binaries available (automatically included by PyInstaller)
