use anyhow::{Context, Result, bail, ensure};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use std::{
    fs::File,
    io::BufReader,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::CertificateDer},
};
use url::Url;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    upstream: String,
    #[serde(default = "proxy_addr")]
    pub proxy_listen: SocketAddr,
    #[serde(default = "web_addr")]
    pub web_listen: SocketAddr,
    #[serde(default = "db_path")]
    pub database: PathBuf,
    #[serde(default = "timeout_secs")]
    connect_timeout_seconds: u64,
    #[serde(default = "response_timeout_secs")]
    response_timeout_seconds: u64,
    inbound_cert: Option<PathBuf>,
    inbound_key: Option<PathBuf>,
    upstream_ca: Option<PathBuf>,
}

fn proxy_addr() -> SocketAddr {
    ([127, 0, 0, 1], 20808).into()
}
fn web_addr() -> SocketAddr {
    ([127, 0, 0, 1], 20809).into()
}
fn db_path() -> PathBuf {
    "traffic.sqlite3".into()
}
fn timeout_secs() -> u64 {
    10
}
fn response_timeout_secs() -> u64 {
    300
}

pub struct Upstream {
    pub host: String,
    pub port: u16,
    pub socks: bool,
    pub credentials: Option<(String, String)>,
    pub tls: Option<TlsConnector>,
    pub label: String,
    pub timeout: Duration,
    pub response_timeout: Duration,
}

fn certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let certificates =
        rustls_pemfile::certs(&mut BufReader::new(file)).collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        !certificates.is_empty(),
        "no certificates found in {}",
        path.display()
    );
    Ok(certificates)
}

pub fn client_tls(extra_ca: Option<&Path>) -> Result<TlsConnector> {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if let Some(path) = extra_ca {
        for cert in certs(path)? {
            roots.add(cert)?;
        }
    }
    ensure!(!roots.is_empty(), "no trusted TLS roots");
    Ok(TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )))
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        // TOML diagnostics can include a source line containing upstream credentials.
        let mut c: Self = toml::from_str(&raw).map_err(|_| {
            anyhow::anyhow!("invalid TOML configuration (check keys and value types)")
        })?;
        let base = path.parent().unwrap_or(Path::new("."));
        c.database = base.join(c.database);
        for p in [&mut c.inbound_cert, &mut c.inbound_key, &mut c.upstream_ca]
            .into_iter()
            .flatten()
        {
            *p = base.join(&*p);
        }
        ensure!(
            c.connect_timeout_seconds > 0 && c.response_timeout_seconds > 0,
            "timeouts must be positive"
        );
        Ok(c)
    }

    pub fn upstream(&self) -> Result<Upstream> {
        let u = Url::parse(&self.upstream).map_err(|_| anyhow::anyhow!("invalid upstream URL"))?;
        let socks = u.scheme() == "socks5";
        ensure!(
            socks || matches!(u.scheme(), "http" | "https"),
            "expected socks5, http or https upstream"
        );
        ensure!(
            matches!(u.path(), "" | "/") && u.query().is_none() && u.fragment().is_none(),
            "unexpected upstream path, query or fragment"
        );
        let address = u.host_str().context("missing upstream host")?;
        let host = address
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = u.port_or_known_default().unwrap_or(1080);
        ensure!(port != 0, "invalid upstream port");
        let credentials = if u.username().is_empty() && u.password().is_none() {
            None
        } else {
            let decode = |s: &str| -> Result<String> {
                Ok(percent_decode_str(s).decode_utf8()?.into_owned())
            };
            Some((decode(u.username())?, decode(u.password().unwrap_or(""))?))
        };
        let tls = if u.scheme() == "https" {
            Some(client_tls(self.upstream_ca.as_deref())?)
        } else {
            None
        };
        Ok(Upstream {
            host,
            port,
            socks,
            credentials,
            tls,
            label: format!("{}://{}:{}", u.scheme(), address, port),
            timeout: Duration::from_secs(self.connect_timeout_seconds),
            response_timeout: Duration::from_secs(self.response_timeout_seconds),
        })
    }

    pub fn inbound_tls(&self) -> Result<Option<TlsAcceptor>> {
        match (&self.inbound_cert, &self.inbound_key) {
            (None, None) => Ok(None),
            (Some(cert), Some(key)) => {
                let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(key)?))?
                    .context("missing TLS private key")?;
                let server = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs(cert)?, key)?;
                Ok(Some(TlsAcceptor::from(Arc::new(server))))
            }
            _ => bail!("set both inbound_cert and inbound_key"),
        }
    }
}
