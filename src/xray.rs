use crate::upstream::Socket;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{fs::Permissions, os::unix::fs::PermissionsExt, process::Stdio, time::Duration};
use tempfile::TempDir;
use tokio::{
    io::AsyncWriteExt,
    net::UnixStream,
    process::{Child, Command},
    time::{sleep, timeout},
};

pub struct Relay(TempDir);

impl Relay {
    pub async fn start(outbound: Value, deadline: Duration) -> Result<(Self, Child)> {
        let dir = tempfile::Builder::new()
            .prefix("rust-proxy-")
            .permissions(Permissions::from_mode(0o700))
            .tempdir()?;
        let socket = dir.path().join("http");
        let config = json!({
            "log": {"loglevel": "none"},
            "inbounds": [{"listen": socket, "protocol": "http", "settings": {}}],
            "outbounds": [outbound]
        });
        let mut child = Command::new("xray")
            .args(["run", "-format", "json", "-c", "stdin:"])
            .stdin(Stdio::piped())
            // Xray diagnostics can include the complete encryption setting.
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .context("this VLESS profile requires xray on PATH")?;
        let config = serde_json::to_vec(&config)?;
        timeout(deadline, async {
            {
                let mut stdin = child.stdin.take().context("open Xray configuration pipe")?;
                stdin.write_all(&config).await.context("send Xray configuration")?;
            }
            loop {
                if let Some(status) = child.try_wait()? {
                    bail!("Xray rejected its configuration or failed to start ({status}); check its version, VLESS settings and CA");
                }
                match UnixStream::connect(&socket).await {
                    Ok(_) => return Ok(()),
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused) => {}
                    Err(e) => return Err(e).context("open private Xray socket"),
                }
                sleep(Duration::from_millis(20)).await;
            }
        }).await.context("Xray startup timed out")??;
        Ok((Self(dir), child))
    }

    pub async fn connect(&self) -> Result<Socket> {
        Ok(Box::new(
            UnixStream::connect(self.0.path().join("http"))
                .await
                .context("connect to local Xray")?,
        ))
    }
}
