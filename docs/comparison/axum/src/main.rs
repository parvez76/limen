use axum::{
    Json, Router,
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Event {
    id: String,
    kind: String,
    count: i32,
}

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

async fn health() -> &'static str {
    "ok"
}

async fn create_event(body: Result<Json<Event>, JsonRejection>) -> Result<Json<Event>, ApiError> {
    let Json(event) = body.map_err(|e| ApiError(e.status(), e.body_text()))?;
    if event.count < 0 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "count must be >= 0".into()));
    }
    Ok(Json(event))
}

async fn not_found() -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "not found".into())
}

async fn method_not_allowed() -> ApiError {
    ApiError(StatusCode::METHOD_NOT_ALLOWED, "method not allowed".into())
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/health", get(health))
        .route("/events", post(create_event))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed);
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
