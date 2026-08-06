# dastcore sidecar (PyInstaller)

Bundles `dastcore` into a single-file executable so the desktop app is fully
self-contained — no Python needed on the end user's machine. Tauri ships it as a
[sidecar](https://tauri.app/develop/sidecar/) (`bundle.externalBin`), and the
desktop shell runs it instead of a `dastcore` on `PATH`.

## Build it

From the `desktop/` directory:

```bash
pip install "dastcore[web]" pyinstaller   # dastcore importable + PyInstaller
npm run sidecar                            # == python sidecar/build_sidecar.py
```

This produces `src-tauri/binaries/dastcore-<host-triple>[.exe]`, exactly the name
Tauri expects for the current platform. Run it on **each** OS you want to ship —
PyInstaller output is platform-specific. After that, `npm run tauri dev|build`
picks the sidecar up automatically.

## What's included / excluded

- **Included:** the full CLI + web dashboard, all rule/AI-rule data, and the HTML
  report + web templates.
- **Excluded:** Playwright/Chromium. The packaged binary therefore supports the
  `http` discovery engine; `--engine headless|both` needs a normal install with
  the `headless` extra. (Playwright is imported lazily, so this only limits the
  packaged binary, not dastcore itself.)

## Notes

- `dastcore.spec` collects the by-path data files and uvicorn's dynamic imports.
  Depending on your PyInstaller version / platform you may need to add a hidden
  import or hook — build once and run `dastcore-… serve` to confirm it starts.
- The built binaries are git-ignored; they are build artifacts, not source.
- A future refinement is code-signing the sidecar as part of the release build.
