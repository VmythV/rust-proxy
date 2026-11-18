use crate::{
    config::{Upstream, client_tls},
    journal::now,
    upstream::{self, Target},
};
use anyhow::{Context, Result, ensure};
use axum::{
    body::{Body, to_bytes},
    http::{Request, header::HOST},
};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::Mutex, time::timeout};
use tokio_rustls::rustls::pki_types::ServerName;

const HOSTNAME: &str = "ipwho.is";
const SUCCESS_TTL: Duration = Duration::from_secs(600);
const ERROR_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Deserialize, Serialize)]
struct Network {
    isp: Option<String>,
    org: Option<String>,
    asn: Option<u32>,
}

#[derive(Clone, Deserialize, Serialize)]
struct ExitInfo {
    ip: IpAddr,
    country: Option<String>,
    country_code: Option<String>,
    region: Option<String>,
    city: Option<String>,
    connection: Option<Network>,
}

#[derive(Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Outcome {
    Ok { info: ExitInfo },
    Error { message: String },
}

#[derive(Clone, Serialize)]
pub struct Report {
    checked_at: i64,
    #[serde(flatten)]
    outcome: Outcome,
}

pub struct EgressLookup {
    upstream: Arc<Upstream>,
    cached: Mutex<Option<(Instant, Report)>>,
}

impl EgressLookup {
    pub fn new(upstream: Arc<Upstream>) -> Self {
        Self {
            upstream,
            cached: Mutex::new(None),
        }
    }

    pub async fn check(&self, refresh: bool) -> Report {
        let requested = Instant::now();
        // Holding this lock through the lookup coalesces concurrent dashboard requests.
        let mut cache = self.cached.lock().await;
        if let Some((completed, report)) = &*cache {
            let ttl = match report.outcome {
                Outcome::Ok { .. } => SUCCESS_TTL,
                Outcome::Error { .. } => ERROR_TTL,
            };
            if *completed >= requested || (!refresh && completed.elapsed() < ttl) {
                return report.clone();
            }
        }
        let result = timeout(Duration::from_secs(15), self.lookup()).await;
        let outcome = match result {
            Ok(Ok(info)) => Outcome::Ok { info },
            Ok(Err(e)) => Outcome::Error {
                message: e.to_string(),
            },
            Err(_) => Outcome::Error {
                message: "查询超时".into(),
            },
        };
        let report = Report {
            checked_at: now(),
            outcome,
        };
        *cache = Some((Instant::now(), report.clone()));
        report
    }

    async fn lookup(&self) -> Result<ExitInfo> {
        let tunnel = self
            .upstream
            .tunnel(&Target {
                host: HOSTNAME.into(),
                port: 443,
            })
            .await
            .map_err(|e| anyhow::anyhow!("上游连接失败（{e}）"))?;
        // The lookup service uses the system's roots. upstream_ca only trusts the upstream.
        let tls = tokio::task::spawn_blocking(|| client_tls(None))
            .await?
            .context("无法加载查询服务的受信任证书")?;
        let stream = tls
            .connect(ServerName::try_from(HOSTNAME)?, tunnel)
            .await
            .context("查询服务 TLS 验证或握手失败")?;
        let mut sender = upstream::http(Box::new(stream)).await?;
        let request = Request::get("/")
            .header(HOST, HOSTNAME)
            .header("accept", "application/json")
            .header("user-agent", "rust-proxy/0.1")
            .body(Body::empty())?;
        let resp = sender
            .send_request(request)
            .await
            .context("查询服务连接中断")?;
        ensure!(
            resp.status().is_success(),
            "查询服务返回 HTTP {}",
            resp.status().as_u16()
        );
        let bytes = to_bytes(Body::new(resp.into_body()), 64 * 1024)
            .await
            .context("无法读取查询结果")?;
        let raw: serde_json::Value =
            serde_json::from_slice(&bytes).context("查询服务返回了无效数据")?;
        ensure!(raw["success"] == true, "查询服务未能识别出口地址");
        serde_json::from_value(raw).context("查询结果缺少有效 IP 或字段格式异常")
    }
}
