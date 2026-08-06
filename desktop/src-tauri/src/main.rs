// dastcore desktop shell (Tauri v2).
//
// Strategy: on launch, reserve a free local port, start `dastcore serve` on it as
// a child process, and point the window at that local server once it answers. The
// window opens immediately on a loading page and redirects itself when the server
// is healthy. The child is killed when the app exits.
//
// This deliberately reuses the exact same web dashboard `dastcore serve` provides,
// so the desktop app and the CLI share behaviour and scan history (~/.dastcore).
//
// The server binary is `dastcore` on PATH by default; override with the
// DASTCORE_CMD environment variable (e.g. to point at a bundled sidecar).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::TcpListener;
use std::process::{Child, Command};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use tauri::{Manager, RunEvent};

/// Holds the spawned server so we can terminate it on exit.
struct ServerProcess(Mutex<Option<Child>>);

/// Reserve an ephemeral local port by binding to :0 and reading the assigned port.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .expect("could not reserve a local port")
}

/// Start `dastcore serve` bound to the given port.
fn spawn_server(port: u16) -> std::io::Result<Child> {
    let program = std::env::var("DASTCORE_CMD").unwrap_or_else(|_| "dastcore".to_string());
    let mut command = Command::new(program);
    command.args(["serve", "--host", "127.0.0.1", "--port", &port.to_string()]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW: no console popup
    }
    command.spawn()
}

/// Poll the server root until it responds, or the timeout elapses.
fn wait_until_healthy(url: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if ureq::get(url).timeout(Duration::from_secs(2)).call().is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(300));
    }
    false
}

fn main() {
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}/");

    let child = spawn_server(port)
        .expect("failed to start `dastcore serve` — is dastcore installed and on PATH? (pip install 'dastcore[web]')");

    tauri::Builder::default()
        .manage(ServerProcess(Mutex::new(Some(child))))
        .setup(move |app| {
            let window = app
                .get_webview_window("main")
                .expect("main window is defined in tauri.conf.json");
            // Wait for the server off the UI thread, then redirect the loading page to it.
            thread::spawn(move || {
                if wait_until_healthy(&url, Duration::from_secs(40)) {
                    let _ = window.eval(&format!("window.location.replace('{url}')"));
                } else {
                    let _ = window.eval(
                        "document.body.innerHTML = '<p style=\"font-family:sans-serif;padding:2rem;line-height:1.5\">\
                         No se pudo iniciar el servidor local de dastcore.<br>\
                         Comprueba que está instalado: <code>pip install \\'dastcore[web]\\'</code>.</p>'",
                    );
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building the dastcore desktop app")
        .run(|app_handle, event| {
            if let RunEvent::ExitRequested { .. } = event {
                // Terminate the server process we started.
                if let Some(state) = app_handle.try_state::<ServerProcess>() {
                    if let Ok(mut guard) = state.0.lock() {
                        if let Some(mut child) = guard.take() {
                            let _ = child.kill();
                        }
                    }
                }
            }
        });
}
