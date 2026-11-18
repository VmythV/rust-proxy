use crate::{config::Upstream, egress::EgressLookup, journal::Journal};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{
        Html, Sse,
        sse::{Event, KeepAlive},
    },
    routing::get,
};
use futures_util::stream::{self, Stream};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

#[derive(Clone)]
struct Dashboard {
    log: Arc<Journal>,
    config: Value,
    egress: Arc<EgressLookup>,
}

pub fn dashboard(
    log: Arc<Journal>,
    upstream: Arc<Upstream>,
    listen: SocketAddr,
    tls: bool,
) -> Router {
    Router::new()
        .route("/", get(async || Html(include_str!("../web/index.html"))))
        .route(
            "/api/config",
            get(async |State(s): State<Dashboard>| Json(s.config)),
        )
        .route("/api/traffic", get(traffic))
        .route(
            "/api/egress",
            get(async |State(s): State<Dashboard>| Json(s.egress.check(false).await))
                .post(async |State(s): State<Dashboard>| Json(s.egress.check(true).await)),
        )
        .route("/api/events", get(events))
        .with_state(Dashboard {
            log,
            config: json!({"upstream":upstream.label,"listen":listen,"tls":tls}),
            egress: Arc::new(EgressLookup::new(upstream)),
        })
}

#[derive(Clone, Copy, Deserialize)]
struct Page {
    before: Option<i64>,
    #[serde(default)]
    active: bool,
}

async fn snapshot(s: Dashboard, q: Page) -> anyhow::Result<Value> {
    tokio::task::spawn_blocking(move || {
        let mut rows = s.log.rows(q.before, q.active)?;
        let more = rows.len() > 100;
        rows.truncate(100);
        let (active, up, down) = s.log.live();
        Ok(json!({"rows":rows,"more":more,"active":active,"up":up,"down":down}))
    })
    .await?
}

async fn traffic(
    State(s): State<Dashboard>,
    Query(q): Query<Page>,
) -> Result<Json<Value>, StatusCode> {
    snapshot(s, q)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn events(
    State(s): State<Dashboard>,
    Query(q): Query<Page>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let timer = tokio::time::interval(Duration::from_secs(1));
    Sse::new(stream::unfold(
        (s, timer),
        move |(s, mut timer)| async move {
            timer.tick().await;
            let event = match snapshot(s.clone(), q).await {
                Ok(value) => Event::default().data(value.to_string()),
                Err(_) => Event::default().event("journal-error").data("unavailable"),
            };
            Some((Ok(event), (s, timer)))
        },
    ))
    .keep_alive(KeepAlive::default())
}
