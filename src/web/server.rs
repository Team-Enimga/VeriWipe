//! Embedded Axum Web Server & Real-Time Event Dispatcher.
//! Provides REST endpoints and Server-Sent Events (SSE) for both in-OS desktop GUI
//! and bare-metal Live USB kiosk operation.

use crate::blockchain::crypto::KeyAuthority;
use crate::blockchain::BlockchainLedger;
use crate::config::{RuntimePaths, WipeMethod, DEFAULT_HOST, DEFAULT_PORT, PRODUCT_NAME, PRODUCT_VERSION, TEAM_NAME, PROBLEM_STATEMENT};
use crate::devices::detector::list_block_devices;
use crate::devices::lab::{cleanup_synthetic_disks, create_synthetic_disk, list_synthetic_disks};
use crate::recovery::carver::carve_media;
use crate::sanitizer::drive::execute_wipe;
use crate::sanitizer::file::shred_path;
use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    pub tx: broadcast::Sender<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemStatus {
    pub product: String,
    pub version: String,
    pub team: String,
    pub problem_statement: String,
    pub authority_pubkey: String,
    pub total_blocks: usize,
    pub chain_valid: bool,
}

#[derive(Debug, Deserialize)]
pub struct WipeRequest {
    pub target: String,
    pub method: String,
    pub verify_percentage: Option<u32>,
    pub operator: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CarveRequest {
    pub source: String,
    pub format: Option<String>,
    pub output_dir: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ShredRequest {
    pub target: String,
    pub operator: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LabCreateRequest {
    pub size_mb: Option<u64>,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AutonukeRequest {
    pub dry_run: Option<bool>,
    pub countdown_seconds: Option<u32>,
}

pub async fn start_server(host: Option<&str>, port: Option<u16>) -> Result<(), Box<dyn std::error::Error>> {
    let host_str = host.unwrap_or(DEFAULT_HOST);
    let port_num = port.unwrap_or(DEFAULT_PORT);

    let (tx, _rx) = broadcast::channel::<String>(100);
    let state = AppState { tx };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Check if frontend/dist exists to serve as static files
    let frontend_dir = Path::new("frontend/dist");
    let app = if frontend_dir.exists() {
        Router::new()
            .nest_service("/assets", ServeDir::new(frontend_dir.join("assets")))
            .fallback_service(ServeDir::new(frontend_dir))
    } else {
        Router::new().route("/", get(render_embedded_dashboard))
    };

    let router = app
        .route("/api/status", get(get_status))
        .route("/api/devices", get(get_devices))
        .route("/api/wipe", post(post_wipe))
        .route("/api/carve", post(post_carve))
        .route("/api/shred", post(post_shred))
        .route("/api/blockchain", get(get_blockchain))
        .route("/api/blockchain/verify", get(get_blockchain_verify))
        .route("/api/lab/create", post(post_lab_create))
        .route("/api/lab/list", get(get_lab_list))
        .route("/api/lab/clean", post(post_lab_clean))
        .route("/api/autonuke", post(post_autonuke))
        .route("/api/events", get(sse_handler))
        .layer(cors)
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", host_str, port_num).parse()?;
    info!("VeriWipe Axum Embedded Server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

// -------------------------------------------------------------
// API Handlers
// -------------------------------------------------------------

async fn get_status() -> Json<SystemStatus> {
    let paths = RuntimePaths::get();
    let authority = KeyAuthority::load_or_generate(&paths.authority_privkey, &paths.authority_pubkey)
        .unwrap_or_else(|_| panic!("Failed to load authority key"));
    let ledger = BlockchainLedger::load_or_create(&paths.ledger_file, &authority)
        .unwrap_or_else(|_| panic!("Failed to load blockchain ledger"));
    let verify = ledger.verify_chain();

    Json(SystemStatus {
        product: PRODUCT_NAME.to_string(),
        version: PRODUCT_VERSION.to_string(),
        team: TEAM_NAME.to_string(),
        problem_statement: PROBLEM_STATEMENT.to_string(),
        authority_pubkey: authority.public_key_hex(),
        total_blocks: ledger.blocks.len(),
        chain_valid: verify.is_valid,
    })
}

async fn get_devices() -> Json<serde_json::Value> {
    let devices = list_block_devices(true);
    Json(serde_json::json!({
        "devices": devices,
        "total": devices.len(),
    }))
}

async fn post_wipe(
    State(state): State<AppState>,
    Json(req): Json<WipeRequest>,
) -> Json<serde_json::Value> {
    let method = match req.method.to_uppercase().as_str() {
        "NIST_800_88_CLEAR" => WipeMethod::Nist800_88Clear,
        "DOD_5220_22_M" => WipeMethod::Dod5220_22M,
        "ZERO_QUICK" => WipeMethod::ZeroQuick,
        _ => WipeMethod::Nist800_88Purge,
    };

    let verify_pct = req.verify_percentage.unwrap_or(100);
    let operator = req.operator.unwrap_or_else(|| "Web_Operator".to_string());
    let tx = state.tx.clone();

    let progress_cb = Box::new(move |pass, total, written, total_bytes, throughput| {
        let pct = (written as f64 / total_bytes as f64) * 100.0;
        let event = serde_json::json!({
            "type": "WIPE_PROGRESS",
            "pass": pass,
            "total_passes": total,
            "written_bytes": written,
            "total_bytes": total_bytes,
            "percent": pct,
            "throughput_mbps": throughput
        });
        let _ = tx.send(event.to_string());
    });

    match execute_wipe(
        &req.target,
        method,
        verify_pct,
        &operator,
        "National Technical Research Organisation (NTRO)",
        Some(progress_cb),
    ) {
        Ok(res) => Json(serde_json::json!({ "success": true, "result": res })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })),
    }
}

async fn post_carve(
    State(state): State<AppState>,
    Json(req): Json<CarveRequest>,
) -> Json<serde_json::Value> {
    let format = req.format.unwrap_or_else(|| "ALL".to_string());
    let out_dir = req.output_dir.unwrap_or_else(|| "./carved_evidence".to_string());
    let tx = state.tx.clone();

    let progress_cb = Box::new(move |scanned, total, count| {
        let pct = (scanned as f64 / total as f64) * 100.0;
        let event = serde_json::json!({
            "type": "CARVE_PROGRESS",
            "scanned_bytes": scanned,
            "total_bytes": total,
            "percent": pct,
            "artifacts_found": count
        });
        let _ = tx.send(event.to_string());
    });

    match carve_media(
        Path::new(&req.source),
        Path::new(&out_dir),
        &format,
        true,
        Some(progress_cb),
    ) {
        Ok(res) => Json(serde_json::json!({ "success": true, "result": res })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })),
    }
}

async fn post_shred(Json(req): Json<ShredRequest>) -> Json<serde_json::Value> {
    let operator = req.operator.unwrap_or_else(|| "Web_Operator".to_string());
    match shred_path(&req.target, &operator) {
        Ok(res) => Json(serde_json::json!({ "success": true, "result": res })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })),
    }
}

async fn get_blockchain() -> Json<serde_json::Value> {
    let paths = RuntimePaths::get();
    let authority = KeyAuthority::load_or_generate(&paths.authority_privkey, &paths.authority_pubkey).unwrap();
    let ledger = BlockchainLedger::load_or_create(&paths.ledger_file, &authority).unwrap();
    Json(serde_json::json!({
        "blocks": ledger.blocks,
        "total_blocks": ledger.blocks.len(),
    }))
}

async fn get_blockchain_verify() -> Json<serde_json::Value> {
    let paths = RuntimePaths::get();
    let authority = KeyAuthority::load_or_generate(&paths.authority_privkey, &paths.authority_pubkey).unwrap();
    let ledger = BlockchainLedger::load_or_create(&paths.ledger_file, &authority).unwrap();
    let res = ledger.verify_chain();
    Json(serde_json::json!({ "verification": res }))
}

async fn post_lab_create(Json(req): Json<LabCreateRequest>) -> Json<serde_json::Value> {
    let paths = RuntimePaths::get();
    let size = req.size_mb.unwrap_or(20);
    let name = req.name.unwrap_or_else(|| "forensic_demo.img".to_string());

    match create_synthetic_disk(&paths.lab_dir, &name, size) {
        Ok(manifest) => Json(serde_json::json!({ "success": true, "manifest": manifest })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })),
    }
}

async fn get_lab_list() -> Json<serde_json::Value> {
    let paths = RuntimePaths::get();
    let list = list_synthetic_disks(&paths.lab_dir);
    Json(serde_json::json!({ "disks": list }))
}

async fn post_lab_clean() -> Json<serde_json::Value> {
    let paths = RuntimePaths::get();
    match cleanup_synthetic_disks(&paths.lab_dir) {
        Ok(count) => Json(serde_json::json!({ "success": true, "cleaned_count": count })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })),
    }
}

async fn post_autonuke(Json(req): Json<AutonukeRequest>) -> Json<serde_json::Value> {
    let dry_run = req.dry_run.unwrap_or(true); // default to safe dry-run via web API unless confirmed
    let countdown = req.countdown_seconds.unwrap_or(5);

    match crate::autonomous::autonuke::run_autonuke(true, dry_run, countdown) {
        Ok(report) => Json(serde_json::json!({ "success": true, "report": report })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })),
    }
}

async fn sse_handler(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.tx.subscribe();
    let stream = async_stream::stream! {
        while let Ok(msg) = rx.recv().await {
            yield Ok(Event::default().data(msg));
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn render_embedded_dashboard() -> Html<&'static str> {
    Html(include_str!("embedded_ui.html"))
}
