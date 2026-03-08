//! Web UI request inspector — serves a dashboard at localhost showing HTTP requests in real-time.

use std::collections::VecDeque;
use std::sync::Arc;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::get;
use tokio::sync::{broadcast, Mutex};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tracing::info;

const MAX_HISTORY: usize = 1000;

/// Max body size to capture (256KB). Larger bodies are truncated.
pub const MAX_BODY_CAPTURE: usize = 256 * 1024;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RequestEvent {
    pub id: u64,
    pub method: String,
    pub path: String,
    pub host: String,
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
    pub request_size: u64,
    pub response_size: u64,
    pub request_headers: Vec<(String, String)>,
    pub response_headers: Vec<(String, String)>,
    pub request_body: Option<String>,
    pub response_body: Option<String>,
    pub timestamp: u64,
}

#[derive(Clone)]
pub struct InspectorState {
    pub tx: broadcast::Sender<RequestEvent>,
    history: Arc<Mutex<VecDeque<RequestEvent>>>,
}

impl InspectorState {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1000);

        let state = Self {
            tx: tx.clone(),
            history: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_HISTORY))),
        };

        // Background task to accumulate history
        let history = state.history.clone();
        let mut rx = tx.subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let mut hist = history.lock().await;
                        // If this is a response event (status set, method empty), merge with existing
                        if event.status.is_some() && event.method.is_empty() {
                            if let Some(existing) = hist.iter_mut().find(|e| e.id == event.id) {
                                existing.status = event.status;
                                existing.duration_ms = event.duration_ms;
                                existing.response_size = event.response_size;
                                existing.response_headers = event.response_headers;
                                existing.response_body = event.response_body;
                                continue;
                            }
                        }
                        if hist.len() >= MAX_HISTORY {
                            hist.pop_front();
                        }
                        hist.push_back(event);
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::debug!("inspector history lagged {n} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        state
    }
}

pub async fn start_inspector(port: u16, state: InspectorState) {
    let app = axum::Router::new()
        .route("/", get(dashboard))
        .route("/events", get(sse_handler))
        .route("/api/requests", get(api_requests))
        .with_state(state);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            info!("inspector: failed to bind {addr}: {e}");
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        info!("inspector server error: {e}");
    }
}

async fn dashboard() -> impl IntoResponse {
    Html(include_str!("inspector.html"))
}

async fn api_requests(State(state): State<InspectorState>) -> impl IntoResponse {
    let hist = state.history.lock().await;
    Json(hist.iter().cloned().collect::<Vec<_>>())
}

async fn sse_handler(
    State(state): State<InspectorState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let json = serde_json::to_string(&event).ok()?;
            Some(Ok(Event::default().data(json)))
        }
        Err(_) => None,
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}
