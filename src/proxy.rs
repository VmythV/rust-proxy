use crate::{
    config::Upstream,
    journal::{Counts, Entry, Journal},
    upstream::{self, Socket, Target},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use axum::{
    body::{Body, Bytes},
    http::{
        HeaderMap, Method, Request, Response, StatusCode, Uri,
        header::{CONNECTION, HOST, HeaderName},
    },
    response::IntoResponse,
};
use http_body::{Body as HttpBody, Frame, SizeHint};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    net::{Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

pub async fn serve(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    up: Arc<Upstream>,
    log: Arc<Journal>,
) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let (tls, up, log) = (tls.clone(), up.clone(), log.clone());
        tokio::spawn(async move {
            let result = dispatch(stream, tls, up, log).await;
            if let Err(e) = result {
                eprintln!("connection: {e}");
            }
        });
    }
}

async fn dispatch(
    s: TcpStream,
    tls: Option<TlsAcceptor>,
    up: Arc<Upstream>,
    log: Arc<Journal>,
) -> Result<()> {
    let mut first = [0];
    if timeout(Duration::from_secs(15), s.peek(&mut first)).await?? == 0 {
        return Ok(());
    }
    let (stream, protocol): (Socket, _) = match first[0] {
        5 => return socks_in(s, up, log).await,
        22 => (
            Box::new(
                timeout(
                    Duration::from_secs(15),
                    tls.context("HTTPS proxy listener requires certificate")?
                        .accept(s),
                )
                .await??,
            ),
            "HTTPS",
        ),
        _ => (Box::new(s), "HTTP"),
    };
    http1::Builder::new()
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |req| {
                let (up, log) = (up.clone(), log.clone());
                async move { Ok::<_, Infallible>(handle(req, protocol, up, log).await) }
            }),
        )
        .with_upgrades()
        .await?;
    Ok(())
}

fn failure(code: StatusCode, message: &'static str) -> Response<Body> {
    (code, [(CONNECTION, "close")], message).into_response()
}

async fn handle(
    mut req: Request<Incoming>,
    protocol: &str,
    up: Arc<Upstream>,
    log: Arc<Journal>,
) -> Response<Body> {
    let connect = req.method() == Method::CONNECT;
    if !connect && req.uri().scheme_str() != Some("http") {
        return failure(
            StatusCode::BAD_REQUEST,
            "Expected an absolute HTTP URL or CONNECT",
        );
    }
    let Some(authority) = req.uri().authority().cloned() else {
        return failure(StatusCode::BAD_REQUEST, "Missing destination");
    };
    let Ok(dest) = Target::parse(&authority, if connect { None } else { Some(80) }) else {
        return failure(StatusCode::BAD_REQUEST, "Invalid destination");
    };
    let target = if connect {
        dest.authority()
    } else {
        format!("http://{}{}", authority, req.uri().path())
    };
    let Ok(mut entry) = log.begin(protocol, req.method().as_str(), &target, &up.label) else {
        return failure(StatusCode::INTERNAL_SERVER_ERROR, "Traffic log unavailable");
    };
    if connect {
        match up.tunnel(&dest).await {
            Ok(remote) => {
                let client = hyper::upgrade::on(&mut req);
                entry.status = Some(200);
                tokio::spawn(async move {
                    match client.await {
                        Ok(client) => relay(Box::new(TokioIo::new(client)), remote, entry).await,
                        Err(_) => entry.finish("client disconnected"),
                    }
                });
                Response::new(Body::empty())
            }
            Err(e) => {
                entry.status = Some(502);
                entry.finish(&e.to_string());
                failure(StatusCode::BAD_GATEWAY, "Upstream tunnel failed")
            }
        }
    } else {
        let counts = entry.counts.clone();
        let response = timeout(up.response_timeout, forward(req, dest, up, counts)).await;
        let upstream_resp = match response {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                entry.status = Some(502);
                entry.finish(&e.to_string());
                return failure(StatusCode::BAD_GATEWAY, "Upstream request failed");
            }
            Err(_) => {
                entry.status = Some(504);
                entry.finish("upstream response timed out");
                return failure(StatusCode::GATEWAY_TIMEOUT, "Upstream timed out");
            }
        };
        entry.status = Some(upstream_resp.status().as_u16());
        let (mut parts, body) = upstream_resp.into_parts();
        strip_hop_headers(&mut parts.headers);
        let counts = entry.counts.clone();
        Response::from_parts(parts, Body::new(Metered::new(body, counts, Some(entry))))
    }
}

async fn forward(
    req: Request<Incoming>,
    dest: Target,
    up: Arc<Upstream>,
    counts: Arc<Counts>,
) -> Result<Response<Incoming>> {
    let (mut parts, body) = req.into_parts();
    let authority = parts.uri.authority().context("missing target")?.to_string();
    strip_hop_headers(&mut parts.headers);
    parts.headers.insert(HOST, authority.parse()?);
    let stream = if up.socks {
        parts.uri = Uri::builder()
            .path_and_query(
                parts
                    .uri
                    .path_and_query()
                    .cloned()
                    .unwrap_or_else(|| "/".parse().unwrap()),
            )
            .build()?;
        up.tunnel(&dest).await?
    } else {
        timeout(up.timeout, up.transport())
            .await
            .context("upstream connection timed out")??
    };
    let mut req = Request::from_parts(parts, Body::new(Metered::new(body, counts, None)));
    if !up.socks {
        up.authorize(&mut req)?;
    }
    let mut client = upstream::http(stream).await?;
    let resp = client
        .send_request(req)
        .await
        .context("upstream HTTP transfer failed")?;
    ensure!(
        up.socks || resp.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "upstream HTTP authentication rejected"
    );
    Ok(resp)
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|s| s.split(','))
        .filter_map(|s| HeaderName::from_bytes(s.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

// Use actual streamed body frames, including chunked bodies of unknown size.
struct Metered {
    body: Incoming,
    counts: Arc<Counts>,
    response: Option<Entry>,
}
impl Metered {
    fn new(body: Incoming, counts: Arc<Counts>, response: Option<Entry>) -> Self {
        Self {
            body,
            counts,
            response,
        }
    }
}
impl HttpBody for Metered {
    type Data = Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let frame = std::task::ready!(Pin::new(&mut self.body).poll_frame(cx));
        if let Some(Ok(data)) = &frame {
            if let Some(bytes) = data.data_ref() {
                let count = if self.response.is_some() {
                    &self.counts.down
                } else {
                    &self.counts.up
                };
                count.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
        } else if let Some(entry) = &mut self.response {
            entry.finish(if frame.is_none() {
                "ok"
            } else {
                "upstream body interrupted"
            });
        }
        Poll::Ready(frame)
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}
impl Drop for Metered {
    fn drop(&mut self) {
        if let Some(entry) = &mut self.response {
            entry.finish(if self.body.is_end_stream() {
                "ok"
            } else {
                "body interrupted"
            });
        }
    }
}

async fn socks_request(s: &mut TcpStream) -> Result<Target> {
    let version = s.read_u8().await?;
    ensure!(version == 5, "invalid SOCKS version");
    let n = s.read_u8().await?;
    let mut methods = vec![0; n as usize];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        s.write_all(&[5, 255]).await?;
        bail!("no supported SOCKS5 method");
    }
    s.write_all(&[5, 0]).await?;
    let mut head = [0; 4];
    s.read_exact(&mut head).await?;
    ensure!(head[0] == 5 && head[2] == 0, "invalid SOCKS request");
    if head[1] != 1 {
        socks_reply(s, 7).await?;
        bail!("unsupported SOCKS command");
    }
    let host = match head[3] {
        1 => {
            let mut a = [0; 4];
            s.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        4 => {
            let mut a = [0; 16];
            s.read_exact(&mut a).await?;
            Ipv6Addr::from(a).to_string()
        }
        3 => {
            let n = s.read_u8().await?;
            let mut a = vec![0; n as usize];
            s.read_exact(&mut a).await?;
            let name = String::from_utf8(a)?;
            ensure!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)),
                "invalid SOCKS domain"
            );
            name
        }
        _ => {
            socks_reply(s, 8).await?;
            bail!("unknown SOCKS address type");
        }
    };
    Ok(Target {
        host,
        port: s.read_u16().await?,
    })
}

async fn socks_reply(s: &mut TcpStream, code: u8) -> Result<()> {
    s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

async fn socks_in(mut s: TcpStream, up: Arc<Upstream>, log: Arc<Journal>) -> Result<()> {
    let dest = timeout(Duration::from_secs(15), socks_request(&mut s)).await??;
    let mut entry = log.begin("SOCKS5", "CONNECT", &dest.authority(), &up.label)?;
    match up.tunnel(&dest).await {
        Ok(remote) => {
            socks_reply(&mut s, 0).await?;
            relay(Box::new(s), remote, entry).await;
        }
        Err(e) => {
            entry.finish(&e.to_string());
            socks_reply(&mut s, 1).await?;
        }
    }
    Ok(())
}

async fn pump(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    counter: &AtomicU64,
) -> Result<()> {
    let mut buf = [0; 16384];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            to.shutdown().await?;
            return Ok(());
        }
        let mut offset = 0;
        while offset < n {
            let sent = to.write(&buf[offset..n]).await?;
            if sent == 0 {
                return Err(anyhow!("tunnel write closed"));
            }
            counter.fetch_add(sent as u64, Ordering::Relaxed);
            offset += sent;
        }
        to.flush().await?;
    }
}
async fn relay(client: Socket, remote: Socket, mut entry: Entry) {
    let (cr, cw) = tokio::io::split(client);
    let (rr, rw) = tokio::io::split(remote);
    // Preserve client half-close so the peer may send a final response.
    // An upstream EOF ends the downstream session immediately.
    let upload = pump(cr, rw, &entry.counts.up);
    let download = pump(rr, cw, &entry.counts.down);
    let result = {
        tokio::pin!(upload, download);
        tokio::select! {
            r = &mut upload => match r { Ok(()) => download.await, Err(e) => Err(e) },
            r = &mut download => r,
        }
    };
    entry.finish(if result.is_ok() {
        "ok"
    } else {
        "tunnel interrupted"
    });
}
