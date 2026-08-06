# PyInstaller spec for the bundled `dastcore` sidecar (one-file executable).
#
# Bundles the package data the engine loads by path at runtime (rules/*.yaml,
# ai_rules/*, and the Jinja templates for both the HTML report and the web
# dashboard) and the dynamic imports uvicorn needs. Playwright is excluded on
# purpose: it is imported lazily and the headless browser can't be shipped this
# way, so the packaged binary supports the `http` engine (not `headless`).
#
# Build via ../sidecar/build_sidecar.py (which also names it for the Tauri
# sidecar convention). Tweaks may be needed per PyInstaller / platform.

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = collect_data_files(
    "dastcore",
    includes=[
        "rules/*.yaml",
        "ai_rules/*.yaml",
        "ai_rules/wordlists/*.txt",
        "report/templates/*.j2",
        "web/templates/*.j2",
    ],
)

# Pull every dastcore submodule (some are imported lazily, e.g. the web layer),
# plus uvicorn's dynamically-loaded loops/protocols, plus the multipart parser
# Starlette imports on demand for form handling.
hiddenimports = (
    collect_submodules("dastcore")
    + collect_submodules("uvicorn")
    + ["multipart", "python_multipart"]
)

block_cipher = None

a = Analysis(
    ["entry.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["playwright"],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="dastcore",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
