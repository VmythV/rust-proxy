mod config;
mod egress;
mod journal;
mod proxy;
mod upstream;
mod vless;
mod web;
#[cfg(unix)]
mod xray;

use anyhow::{Context, Result, bail};
use std::{env, path::PathBuf, sync::Arc};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let path = match args.next().as_deref().and_then(|s| s.to_str()) {
        None => PathBuf::from("proxy.toml"),
        Some("--config") => PathBuf::from(args.next().context("--config requires a path")?),
        Some("--help" | "-h") => {
            println!(
                "rust-proxy [--config PATH]\nDefault: proxy.toml\nProxy 127.0.0.1:20808  ·  Web 127.0.0.1:20809"
            );
            return Ok(());
        }
        _ => bail!("usage: rust-proxy [--config PATH]"),
    };
    anyhow::ensure!(args.next().is_none(), "too many arguments");
    let config = config::Config::load(&path)?;
    let (upstream, mut worker) = config.upstream().await?;
    let upstream = Arc::new(upstream);
    let tls = config.inbound_tls()?;
    let proxy = TcpListener::bind(config.proxy_listen)
        .await
        .context("bind proxy listener")?;
    let web = TcpListener::bind(config.web_listen)
        .await
        .context("bind web listener")?;
    let journal = journal::Journal::open(&config.database)?;
    let dashboard = web::dashboard(
        journal.clone(),
        upstream.clone(),
        proxy.local_addr()?,
        tls.is_some(),
    );
    println!(
        "Proxy {} → {}\nWeb http://{}",
        proxy.local_addr()?,
        upstream.label,
        web.local_addr()?
    );
    let worker_exit = async {
        match worker.as_mut() {
            Some(child) => child.wait().await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        result = proxy::serve(proxy, tls, upstream, journal) => result?,
        result = axum::serve(web, dashboard) => result?,
        result = shutdown() => result?,
        status = worker_exit => bail!("Xray exited ({})", status?),
    }
    if let Some(mut child) = worker {
        child.kill().await?;
    }
    Ok(())
}

async fn shutdown() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        let mut hangup = signal(SignalKind::hangup())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = term.recv() => Ok(()),
            _ = hangup.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}
