# App icons

Tauri needs a set of platform icons to build the desktop app. They are **not**
committed here — generate them once from a single source image (512×512 PNG or
an SVG) with the Tauri CLI, from the `desktop/` directory:

```bash
npm install
npm run tauri icon path/to/logo.png
```

That writes `32x32.png`, `128x128.png`, `128x128@2x.png`, `icon.icns` and
`icon.ico` into this folder — the exact paths referenced by
`src-tauri/tauri.conf.json` under `bundle.icon`. After that, `npm run tauri dev`
and `npm run tauri build` will work.
