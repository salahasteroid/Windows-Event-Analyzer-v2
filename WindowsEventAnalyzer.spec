# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path


project_dir = Path(SPECPATH)

a = Analysis(
    [str(project_dir / "main.py")],
    pathex=[str(project_dir)],
    binaries=[],
    datas=[
        (str(project_dir / "database" / "event_definitions.json"), "database"),
        (str(project_dir / "database" / "error_codes.json"), "database"),
        (str(project_dir / "database" / "rules.json"), "database"),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="WindowsEventAnalyzer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # UPX-packed executables are often flagged by antivirus; the size
    # saving is not worth it for an admin tool.
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=str(project_dir / "version_info.txt"),
)
