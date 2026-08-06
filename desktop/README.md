# dastcore desktop (Tauri)

A thin native desktop shell around the **same** `dastcore serve` web dashboard.
On launch it reserves a free local port, starts `dastcore serve` on it as a child
process, and shows that local server in a native window — no browser, one icon to
click. It shares scan history and schedules with the CLI (both use
`~/.dastcore/dastcore.db`).

> **Status: buildable scaffold.** The Rust glue and Tauri config are complete and
> idiomatic (Tauri v2), but the app must be compiled on a machine with the Rust +
> Node toolchains (it can't be prebuilt here). Icons are generated in a one-time
> setup step (below). Treat this as the starting point for desktop packaging.

## How it works

- `src-tauri/src/main.rs` — reserves a port, spawns `dastcore serve --host
  127.0.0.1 --port <port>`, waits until it answers, then redirects the window to
  it. The child process is killed when the window closes.
- The window opens immediately on a small loading page (`frontend/index.html`) and
  navigates itself to the dashboard once the server is healthy.
- The server binary is `dastcore` on `PATH` by default. Override it with the
  **`DASTCORE_CMD`** environment variable (e.g. an absolute path, or a future
  bundled sidecar).

## Prerequisites

1. **dastcore with the web extra** available on `PATH`:
   ```bash
   pip install "dastcore[web]"      # or: pipx install "dastcore[web]"
   ```
2. **Rust** (stable) — https://rustup.rs
3. **Node.js 18+** (for the Tauri CLI).
4. Platform webview build deps — see the Tauri prerequisites guide
   (on Linux: `libwebkit2gtk-4.1-dev`, `librsvg2-dev`, `patchelf`, …).

## First-time setup

```bash
cd desktop
npm install
npm run tauri icon path/to/logo.png   # generates src-tauri/icons/* (one time)
```

## Run in development

```bash
npm run tauri dev
```

## Build installers

```bash
npm run tauri build
```

Bundles land in `src-tauri/target/release/bundle/` (`.msi`/`.exe` on Windows,
`.dmg`/`.app` on macOS, `.deb`/`.AppImage` on Linux).

## Bundling Python (optional, later)

The pragmatic MVP assumes `dastcore` is installed. To ship a fully self-contained
app that needs no Python, build a single-file `dastcore` with PyInstaller, add it
to `src-tauri` as a Tauri **sidecar** (`bundle.externalBin`), and point
`DASTCORE_CMD` at the resolved sidecar path. That is the natural next step once
the scaffold builds cleanly on each target platform.
