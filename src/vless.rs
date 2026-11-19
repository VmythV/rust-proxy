use crate::upstream::{Socket, Target};
use anyhow::{Context, Result, bail, ensure};
use async_tungstenite::{ByteReader, ByteWriter, tokio::client_async, tungstenite::Message};
use axum::http::Uri;
use futures_util::TryStreamExt;
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    future::ready,
    io,
    pin::Pin,
    task::{Context as TaskContext, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf, join, split};
use url::{Position, Url};

pub struct Vless {
    id: [u8; 16],
    pub websocket: Option<Uri>,
}

pub enum Settings {
    Native(Vless, Option<String>),
    Xray(Value),
}

impl Vless {
    pub fn from_url(url: &Url, host: &str, ca: Option<&std::path::Path>) -> Result<Settings> {
        ensure!(
            url.password().is_none(),
            "VLESS takes a UUID without a password"
        );
        let id = percent_decode_str(url.username())
            .decode_utf8()
            .context("invalid VLESS UUID")?;
        let hex = id.replace('-', "");
        let canonical = id.len() == 36 && [8, 13, 18, 23].iter().all(|&i| id.as_bytes()[i] == b'-');
        ensure!(
            (canonical || id.len() == 32)
                && hex.len() == 32
                && hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid VLESS UUID"
        );
        let id = u128::from_str_radix(&hex, 16)?.to_be_bytes();
        let (mut ws, mut tls) = (false, false);
        let (mut sni, mut ws_host, mut path) = (None, None, None);
        let (mut encryption, mut flow, mut fingerprint) = (None, None, None);
        let mut seen = HashSet::new();
        for (key, value) in url.query_pairs() {
            ensure!(seen.insert(key.clone()), "duplicate VLESS URL option");
            match (key.as_ref(), value.as_ref()) {
                ("type", "tcp" | "raw")
                | ("security" | "encryption" | "headerType", "none")
                | ("flow", "")
                | ("allowInsecure", "false" | "0")
                | ("alpn", "http/1.1") => {}
                ("type", "ws") => ws = true,
                ("security", "tls") => tls = true,
                ("encryption", method) if method.starts_with("mlkem768x25519plus.") => {
                    encryption = Some(value.into_owned())
                }
                ("flow", "xtls-rprx-vision" | "xtls-rprx-vision-udp443") => {
                    flow = Some(value.into_owned())
                }
                ("fp", name) if !name.is_empty() && name != "unsafe" => {
                    fingerprint = Some(value.into_owned())
                }
                ("sni", name) if !name.is_empty() => sni = Some(value.into_owned()),
                ("host", name) if !name.is_empty() && !name.contains('@') => {
                    ws_host = Some(value.into_owned())
                }
                ("path", p) if !p.contains('#') => {
                    path = Some(if p.starts_with('/') {
                        value.into_owned()
                    } else {
                        format!("/{p}")
                    })
                }
                ("type", _) => bail!("supported VLESS transports are tcp and ws"),
                ("security", _) => bail!("supported VLESS security modes are none and tls"),
                ("flow", _) => bail!("unsupported VLESS flow"),
                ("encryption", _) => {
                    bail!("supported VLESS encryption modes are none and mlkem768x25519plus")
                }
                _ => bail!("invalid or unsupported VLESS URL option"),
            }
        }
        ensure!(tls || sni.is_none(), "VLESS sni requires TLS");
        ensure!(tls || fingerprint.is_none(), "VLESS fp requires TLS");
        ensure!(
            flow.is_none() || encryption.is_some() || (tls && !ws),
            "Vision needs VLESS Encryption or raw TCP with TLS"
        );
        ensure!(
            !seen.contains("alpn") || (ws && tls),
            "explicit VLESS ALPN requires WSS and http/1.1"
        );
        ensure!(
            ws || (path.is_none() && ws_host.is_none()),
            "VLESS path and host require WebSocket"
        );
        let websocket = if ws {
            let authority = ws_host
                .as_deref()
                .or(sni.as_deref())
                .unwrap_or(&url[Position::BeforeHost..Position::AfterPort]);
            Some(
                Uri::builder()
                    .scheme(if tls { "wss" } else { "ws" })
                    .authority(authority)
                    .path_and_query(path.as_deref().unwrap_or("/"))
                    .build()
                    .context("invalid VLESS WebSocket host or path")?,
            )
        } else {
            None
        };
        let tls_name = tls.then(|| sni.unwrap_or_else(|| host.to_owned()));
        if encryption.is_some() || flow.is_some() || fingerprint.is_some() {
            let mut stream = json!({"network": if ws { "ws" } else { "tcp" },
                                    "security": if tls { "tls" } else { "none" }});
            if let Some(uri) = websocket {
                stream["wsSettings"] = json!({"host": uri.authority().unwrap().as_str(),
                                              "path": uri.path_and_query().unwrap().as_str()});
            }
            if let Some(name) = tls_name {
                let mut settings = json!({"serverName":name});
                if let Some(fp) = fingerprint {
                    settings["fingerprint"] = json!(fp);
                }
                if ws {
                    settings["alpn"] = json!(["http/1.1"]);
                }
                if let Some(path) = ca {
                    settings["certificates"] = json!([{"usage":"verify", "certificateFile":path}]);
                }
                stream["tlsSettings"] = settings;
            }
            return Ok(Settings::Xray(json!({
                "protocol": "vless", "streamSettings": stream,
                "settings": {"address":host, "port":url.port().context("VLESS requires an explicit port")?,
                             "id":hex, "flow":flow.as_deref().unwrap_or(""),
                             "encryption":encryption.as_deref().unwrap_or("none")}
            })));
        }
        Ok(Settings::Native(Self { id, websocket }, tls_name))
    }

    pub async fn connect(&self, mut stream: Socket, dest: &Target) -> Result<Socket> {
        if let Some(uri) = &self.websocket {
            // Only this preconnected upstream socket is used, even with a different WS Host.
            let (ws, _) = client_async(uri, stream)
                .await
                .context("VLESS WebSocket upgrade failed")?;
            let (write, read) = ws.split();
            let data = read.try_filter_map(|message| {
                ready(match message {
                    Message::Binary(ref bytes) if !bytes.is_empty() => Ok(Some(message)),
                    Message::Text(_) => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "expected binary VLESS WebSocket data",
                    )
                    .into()),
                    _ => Ok(None),
                })
            });
            stream = Box::new(join(ByteReader::new(data), ByteWriter::new(write)));
        }
        let mut request = vec![0];
        request.extend(self.id);
        request.extend([0, 1]); // No addons, TCP command.
        request.extend(dest.port.to_be_bytes());
        dest.encode_address(&mut request, 2, 3)?;
        stream
            .write_all(&request)
            .await
            .context("write VLESS request")?;
        stream.flush().await?;

        // A server can wait for client payload before sending its response header.
        let (read, write) = split(stream);
        Ok(Box::new(join(
            ResponseReader {
                inner: read,
                header: Header::Version,
            },
            write,
        )))
    }
}

#[derive(Clone, Copy)]
enum Header {
    Version,
    Length,
    Addons(usize),
}

struct ResponseReader<R> {
    inner: R,
    header: Header,
}

impl<R: AsyncRead + Unpin> AsyncRead for ResponseReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut scratch = [0; 255];
        loop {
            let n = match self.header {
                Header::Version | Header::Length => 1,
                Header::Addons(0) => return Pin::new(&mut self.inner).poll_read(cx, buf),
                Header::Addons(n) => n,
            };
            let mut part = ReadBuf::new(&mut scratch[..n]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut part))?;
            let Some(&first) = part.filled().first() else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated VLESS response",
                )));
            };
            self.header = match self.header {
                Header::Version if first == 0 => Header::Length,
                Header::Version => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid VLESS response version",
                    )));
                }
                Header::Length => Header::Addons(first as usize),
                Header::Addons(left) => Header::Addons(left - part.filled().len()),
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use tokio::io::AsyncReadExt;

    const LINK: &str = "vless://00112233-4455-6677-8899-aabbccddeeff@127.0.0.1:8080";

    #[test]
    fn reject_invalid_links_without_printing_credentials() {
        for link in [
            LINK.replace("00112233", "secret"),
            LINK.replace('@', ":password@"),
            format!("{LINK}?type=grpc"),
            format!("{LINK}?type=ws&security=reality"),
            format!("{LINK}?type=ws&security=tls&allowInsecure=1"),
            format!("{LINK}?security=tls&security=none"),
            format!("{LINK}?type=ws&flow=xtls-rprx-vision"),
            format!("{LINK}?type=ws&path=%2Fedge%23fragment"),
        ] {
            let url = Url::parse(&link).unwrap();
            let err = Vless::from_url(&url, "127.0.0.1", None)
                .err()
                .expect("invalid link accepted");
            assert!(!format!("{err:#}").contains(url.username()));
        }
    }

    #[tokio::test]
    async fn websocket_carries_only_payload_and_allows_client_to_write_first() {
        let url = Url::parse(&format!("{LINK}?type=ws")).unwrap();
        let Settings::Native(vless, _) = Vless::from_url(&url, "127.0.0.1", None).unwrap() else {
            panic!("plain WS should use the native transport")
        };
        let (client, peer) = tokio::io::duplex(4096);
        let target = Target {
            host: "2001:db8::1".into(),
            port: 443,
        };
        let exchange = async {
            let client = async {
                let mut stream = vless.connect(Box::new(client), &target).await.unwrap();
                stream.write_all(b"hello").await.unwrap();
                stream.flush().await.unwrap();
                let mut payload = [0; 5];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"reply");
            };
            let peer = async {
                let mut ws = async_tungstenite::tokio::accept_async(peer).await.unwrap();
                let mut expected = vec![0];
                expected.extend(0x00112233445566778899aabbccddeeffu128.to_be_bytes());
                expected.extend([0, 1, 1, 187, 3]);
                expected.extend(
                    "2001:db8::1"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets(),
                );
                assert_eq!(ws.next().await.unwrap().unwrap(), Message::binary(expected));
                assert_eq!(
                    ws.next().await.unwrap().unwrap(),
                    Message::binary(b"hello".to_vec())
                );
                for msg in [
                    Message::binary(vec![0]),
                    Message::Ping(b"control".to_vec().into()),
                    Message::binary(vec![]),
                    Message::binary(vec![3, 1]),
                    Message::binary(b"\x02\x03reply".to_vec()),
                ] {
                    ws.send(msg).await.unwrap();
                }
                // Keep the socket open for the client's automatic pong.
                assert!(ws.next().await.unwrap().unwrap().is_pong());
            };
            tokio::join!(client, peer);
        };
        tokio::time::timeout(std::time::Duration::from_secs(3), exchange)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn invalid_or_truncated_reply_fails_before_forwarding_payload() {
        for bytes in [&[1, 0][..], &[0], &[0, 2, 1]] {
            let mut reader = ResponseReader {
                inner: bytes,
                header: Header::Version,
            };
            let mut payload = Vec::new();
            assert!(reader.read_to_end(&mut payload).await.is_err());
            assert!(payload.is_empty());
        }
    }
}
