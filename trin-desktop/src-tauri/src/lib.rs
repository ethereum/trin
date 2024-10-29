use ethportal_api::{jsonrpsee::http_client::HttpClientBuilder, Web3ApiClient};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::{sync::Mutex, thread::sleep, time::Duration};
use sysinfo::{Pid, System};
use tauri::{async_runtime::JoinHandle, Emitter, Manager, State};
use tauri_plugin_autostart::MacosLauncher;
use tauri_plugin_shell::{
    process::{CommandChild, CommandEvent},
    ShellExt,
};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrinStats {
    cpu: f32,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
struct TrinConfig {
    // args received from the frontend must be camelCase
    httpPort: usize,
    storage: usize,
}

#[derive(Default)]
struct AppData {
    trin_handle: Mutex<Option<CommandChild>>,
    // todo: double check that we need this
    log_handle: Mutex<Option<JoinHandle<()>>>,
    // todo: double check that we need this
    status_handle: Mutex<Option<JoinHandle<()>>>,
}

// this is the jsonrpc request used to make sure
// that the trin node is running
// ... hmm. ok this might not be the best way to check that
// the trin node is running. eg. the node will respond even if
// it is not connected to the network (aka error binding to udp socket)
async fn check_trin_status(http_port: &usize) -> bool {
    let endpoint = format!("http://localhost:{}", http_port);
    let client = HttpClientBuilder::default().build(&endpoint).unwrap();
    client.client_version().await.is_ok()
}

#[tauri::command]
#[allow(clippy::needless_lifetimes)]
async fn launch_trin<'l>(
    app: tauri::AppHandle,
    app_data: State<'l, AppData>,
    trin_config: TrinConfig,
) -> Result<String, String> {
    info!("starting trin with config: {:?}", trin_config);

    let web3_http_address = format!("http://127.0.0.1:{}", trin_config.httpPort);
    let (mut rx, child) = app
        .shell()
        .sidecar("trin")
        .expect("failed to create `trin` binary command")
        .args([
            "--web3-transport=http",
            "--portal-subnetworks=history",
            format!("--web3-http-address={}", web3_http_address).as_str(),
            format!("--mb={}", trin_config.storage).as_str(),
        ])
        .spawn()
        .map_err(|e| e.to_string())?;

    // todo: improve logging ... aka where to write logs
    // spawn a thread that will read the stdout of the trin process
    let log_handle = tauri::async_runtime::spawn(async move {
        // read events such as stdout
        while let Some(event) = rx.recv().await {
            if let CommandEvent::Stdout(line_bytes) = event {
                let line = String::from_utf8_lossy(&line_bytes);
                // write to stdin
                info!("Child process stdout: {}", line);
            }
        }
    });

    // if trin is not responding to jsonrpc requests after 30 seconds,
    // we assume it crashed
    let mut i = 0;
    while i <= 30 {
        info!("checking trin");
        // trin has successfully started
        if check_trin_status(&trin_config.httpPort).await {
            break;
        }
        sleep(Duration::from_secs(1));
        i += 1;
        if i == 20 {
            let _ = child.kill();
            return Err("unable to get a response from the rpc server".to_string());
        }
    }

    // spawn a thread that will ping the trin node every 3 seconds
    // to make sure it is still running
    let app_clone = app.clone();
    let pid = child.pid();
    let status_handle = tauri::async_runtime::spawn(async move {
        info!("checking trin status, pid: {:?}", pid);
        // Initialize system information gatherer
        let mut sys = System::new_all();
        loop {
            // Refresh process list and CPU usage
            sys.refresh_all();

            // Get process ID for the port
            let pid = Pid::from(pid as usize);

            // Get the main process and all its children
            let mut total_cpu = 0.0;
            let mut process_count = 0;

            // Check main process
            if let Some(process) = sys.process(pid) {
                total_cpu += process.cpu_usage();
                process_count += 1;

                // Get all processes to check for children
                for process_check in sys.processes().values() {
                    if process_check.parent() == Some(pid) {
                        total_cpu += process_check.cpu_usage();
                        process_count += 1;
                    }
                }
            }
            println!(
                "Port {}: {} process(es), Total CPU Usage: {:.1}%",
                pid, process_count, total_cpu
            );
            app_clone
                .emit("trin-stats", TrinStats { cpu: total_cpu })
                .expect("failed to emit event");

            if !check_trin_status(&trin_config.httpPort).await {
                app_clone
                    .emit("trin-crashed", ())
                    .expect("failed to emit event");
                break;
            }
            sleep(Duration::from_secs(3));
        }
    });

    // todo: test by killing this - then remove
    info!("Child process started: {:?}", pid);
    *app_data.status_handle.lock().unwrap() = Some(status_handle);
    *app_data.log_handle.lock().unwrap() = Some(log_handle);
    *app_data.trin_handle.lock().unwrap() = Some(child);
    Ok("started".to_string())
}

#[tauri::command]
#[allow(clippy::needless_lifetimes)]
async fn shutdown_trin<'l>(app_data: State<'l, AppData>) -> Result<String, String> {
    info!("stopping trin");
    let mut trin_handle = app_data.trin_handle.lock().unwrap();
    if let Some(child) = trin_handle.take() {
        child.kill().expect("failed to kill child process");
    } else {
        warn!("unable to kill trin child process");
    }
    let mut log_handle = app_data.log_handle.lock().unwrap();
    if let Some(handle) = log_handle.take() {
        handle.abort();
    } else {
        warn!("unable to kill log handle");
    }
    let mut status_handle = app_data.status_handle.lock().unwrap();
    if let Some(handle) = status_handle.take() {
        handle.abort();
    } else {
        warn!("unable to kill status handle");
    }
    Ok("stopped trin".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            // args that are passed to your app on startup
            None,
        ))
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let app_data = AppData::default();
            app.manage(app_data);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![launch_trin, shutdown_trin,])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
