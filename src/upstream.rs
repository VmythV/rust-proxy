use crate::config::Upstream;
use anyhow::{Context, Result, anyhow, bail, ensure};
use axum::{
    body::Body,
    http::{
        HeaderValue, Method, Request,
        header::{HOST, PROXY_AUTHORIZATION},
        uri::Authority,
    },
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use std::{net::IpAddr, str::FromStr};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::rustls::pki_types::ServerName;

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream for T {}
pub type Socket = Box<dyn Stream>;

pub struct Target {
    pub host: String,
    pub port: u16,
}
impl Target {
    pub fn parse(authority: &Authority, default_port: Option<u16>) -> Result<Self> {
        ensure!(!authority.as_str().contains('@'), "invalid destination");
        let host = authority.host();
        let port = match authority.port_u16() {
            Some(p) => p,
            None if authority.as_str() == host => {
                default_port.context("destination requires a port")?
            }
            None => bail!("invalid destination port"),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        ensure!(!host.is_empty() && port != 0, "invalid destination");
        Ok(Self {
            host: host.into(),
            port,
        })
    }

    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

pub async fn http(stream: Socket) -> Result<http1::SendRequest<Body>> {
    let (tx, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .context("HTTP upstream handshake")?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    Ok(tx)
}

impl Upstream {
    // Every outbound socket originates here. The destination is only encoded in
    // protocol messages and is never supplied to the resolver or TCP dialer.
    pub async fn transport(&self) -> Result<Socket> {
        let tcp = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .context("connect to upstream")?;
        if let Some(tls) = &self.tls {
            let name =
                ServerName::try_from(self.host.clone()).context("invalid upstream TLS name")?;
            return Ok(Box::new(
                tls.connect(name, tcp)
                    .await
                    .context("upstream TLS verification or handshake failed")?,
            ));
        }
        Ok(Box::new(tcp))
    }

    pub fn authorize(&self, req: &mut Request<Body>) -> Result<()> {
        if let Some((user, pass)) = &self.credentials {
            let mut h = HeaderValue::from_str(&format!(
                "Basic {}",
                STANDARD.encode(format!("{user}:{pass}"))
            ))?;
            h.set_sensitive(true);
            req.headers_mut().insert(PROXY_AUTHORIZATION, h);
        }
        Ok(())
    }

    pub async fn tunnel(&self, dest: &Target) -> Result<Socket> {
        timeout(self.timeout, async {
            let stream = self.transport().await?;
            if self.socks {
                return self.socks_connect(stream, dest).await;
            }
            let mut client = http(stream).await?;
            let target = dest.authority();
            let mut req = Request::builder()
                .method(Method::CONNECT)
                .uri(&target)
                .header(HOST, &target)
                .body(Body::empty())?;
            self.authorize(&mut req)?;
            let resp = client
                .send_request(req)
                .await
                .context("upstream CONNECT request failed")?;
            ensure!(
                resp.status().is_success(),
                "upstream CONNECT returned {}",
                resp.status().as_u16()
            );
            let upgraded = hyper::upgrade::on(resp)
                .await
                .context("open upstream tunnel")?;
            Ok(Box::new(TokioIo::new(upgraded)) as Socket)
        })
        .await
        .context("upstream connection timed out")?
    }

    async fn socks_connect(&self, mut s: Socket, dest: &Target) -> Result<Socket> {
        let method = if self.credentials.is_some() { 2 } else { 0 };
        s.write_all(&[5, 1, method]).await?;
        let mut choice = [0; 2];
        s.read_exact(&mut choice)
            .await
            .context("SOCKS5 greeting failed")?;
        ensure!(
            choice == [5, method],
            "SOCKS5 authentication method rejected"
        );
        if let Some((user, pass)) = &self.credentials {
            let mut auth = vec![1];
            for field in [user, pass] {
                ensure!(
                    !field.is_empty() && field.len() <= 255,
                    "invalid SOCKS5 credential length"
                );
                auth.push(field.len() as u8);
                auth.extend(field.as_bytes());
            }
            s.write_all(&auth).await?;
            s.read_exact(&mut choice).await?;
            ensure!(choice == [1, 0], "SOCKS5 authentication rejected");
        }
        let mut req = vec![5, 1, 0];
        match IpAddr::from_str(&dest.host) {
            Ok(IpAddr::V4(ip)) => {
                req.push(1);
                req.extend(ip.octets());
            }
            Ok(IpAddr::V6(ip)) => {
                req.push(4);
                req.extend(ip.octets());
            }
            Err(_) => {
                let n =
                    u8::try_from(dest.host.len()).map_err(|_| anyhow!("SOCKS5 domain too long"))?;
                req.extend([3, n]);
                req.extend(dest.host.as_bytes());
            }
        }
        req.extend(dest.port.to_be_bytes());
        s.write_all(&req).await?;
        let mut reply = [0; 4];
        s.read_exact(&mut reply)
            .await
            .context("SOCKS5 CONNECT failed")?;
        ensure!(reply[0] == 5 && reply[2] == 0, "invalid SOCKS5 response");
        ensure!(reply[1] == 0, "SOCKS5 CONNECT rejected (code {})", reply[1]);
        let n = match reply[3] {
            1 => 4,
            4 => 16,
            3 => s.read_u8().await? as usize,
            _ => bail!("invalid SOCKS5 address type"),
        };
        s.read_exact(&mut vec![0; n + 2]).await?;
        Ok(s)
    }
}
