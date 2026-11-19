"""Black-box tests using only the loopback interface and ephemeral ports."""
import base64
import contextlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("PROXY_BIN", ROOT / "target/debug/rust-proxy"))
VLESS_ID = "00112233-4455-6677-8899-aabbccddeeff"


def readn(f, n):
    data = f.read(n)
    if len(data) != n:
        raise EOFError()
    return data


def read_head(f):
    line = f.readline().decode().rstrip()
    headers = {}
    while True:
        h = f.readline()
        if h in (b"", b"\r\n"):
            return line, headers
        k, v = h.decode().split(":", 1)
        headers[k.lower()] = v.strip()


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


@contextlib.contextmanager
def listener(handler):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            handler(self.request)

    with Server(("127.0.0.1", 0), Handler) as srv:
        thread = threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True)
        thread.start()
        try:
            yield srv.server_address[1]
        finally:
            srv.shutdown()
            thread.join()


def mock_upstream(scheme, observed, tls=None, deny=False):
    def handle(sock):
        if tls:
            try:
                sock = tls.wrap_socket(sock, server_side=True)
            except ssl.SSLError:
                return
        with sock, sock.makefile("rb") as f:
            if scheme == "socks5":
                assert readn(f, 3) == bytes([5, 1, 2])
                sock.sendall(bytes([5, 2]))
                assert readn(f, 1) == bytes([1])
                for expected in (b"user", b"p@ss"):
                    assert readn(f, readn(f, 1)[0]) == expected
                sock.sendall(bytes([1, int(deny)]))
                if deny:
                    return
                ver, cmd, rsv, atyp = readn(f, 4)
                assert (ver, cmd, rsv) == (5, 1, 0)
                if atyp == 3:
                    host = readn(f, readn(f, 1)[0]).decode()
                else:
                    host = str(ipaddress.ip_address(readn(f, {1:4, 4:16}[atyp])))
                port = struct.unpack("!H", readn(f, 2))[0]
                observed.append((host, port))
                sock.sendall(bytes([5, 0, 0, 1]) + bytes(6))
                if port != 80:
                    echo(sock, f)
                    return
            line, headers = read_head(f)
            observed.append(line)
            if scheme != "socks5":
                assert headers.get("proxy-authorization") == "Basic " + base64.b64encode(b"user:p@ss").decode()
            else:
                assert "proxy-authorization" not in headers
            if deny:
                sock.sendall(b"HTTP/1.1 407 Denied\r\nContent-Length: 0\r\n\r\n")
            elif line.startswith("CONNECT "):
                sock.sendall(b"HTTP/1.1 200 Established\r\n\r\n")
                echo(sock, f)
            else:
                body = readn(f, int(headers.get("content-length", 0)))
                response = b"upstream:" + body
                sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(response)).encode() + b"\r\n\r\n" + response)
            if tls:
                # Send TLS close_notify so completed tunnels have a clean EOF.
                with contextlib.suppress(OSError):
                    sock.unwrap().close()
    return handle


def echo(sock, f):
    data = f.readline()
    if data != b"disconnect\n":
        sock.sendall(data)
        f.readline()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def api(port, path, method="GET"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        conn.request(method, path)
        resp = conn.getresponse()
        assert resp.status == 200
        return json.loads(resp.read())
    finally:
        conn.close()


@contextlib.contextmanager
def running(directory, upstream, extra="", env=None):
    proxy, web = free_port(), free_port()
    while proxy == web:
        web = free_port()
    cfg = directory / "proxy.toml"
    cfg.write_text(f'upstream = "{upstream}"\nproxy_listen = "127.0.0.1:{proxy}"\n'
                   f'web_listen = "127.0.0.1:{web}"\nconnect_timeout_seconds = 1\n' + extra)
    proc = subprocess.Popen([BIN, "--config", cfg], stdout=subprocess.DEVNULL, env=env)
    try:
        for _ in range(200):
            if proc.poll() is not None:
                raise RuntimeError("rust-proxy exited during startup")
            try:
                api(web, "/api/config")
                break
            except OSError:
                time.sleep(.02)
        else:
            raise TimeoutError("startup")
        yield proxy, web
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
        proc.wait(timeout=5)


@contextlib.contextmanager
def xray_node(directory, certs, network, security, encrypted=False):
    port = free_port()
    stream = {"network": network, "security": security}
    client = {"id": VLESS_ID}
    encryption = decryption = "none"
    if encrypted:
        keys = dict(line.split(": ", 1) for line in subprocess.check_output(["xray", "mlkem768"], text=True).splitlines())
        encryption = "mlkem768x25519plus.native.0rtt." + keys["Client"]
        decryption = "mlkem768x25519plus.native.600s." + keys["Seed"]
        client["flow"] = "xtls-rprx-vision"
    url = f"vless://{VLESS_ID}@127.0.0.1:{port}?type={network}&security={security}&encryption={encryption}"
    if encrypted:
        url += "&flow=xtls-rprx-vision&fp=chrome"
    if network == "ws":
        stream["wsSettings"] = {"path": "/edge/test", "host": "edge.invalid"}
        path = "edge%2Ftest" if encrypted else "%2Fedge%2Ftest"
        url += f"&path={path}&host=edge.invalid"
    if security == "tls":
        stream["tlsSettings"] = {"certificates": [
            {"certificateFile": str(certs / "cert.pem"), "keyFile": str(certs / "key.pem")}]}
        url += "&sni=localhost"
    config = {"inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "vless",
              "settings": {"clients": [client], "decryption": decryption},
              "streamSettings": stream}], "outbounds": [{"protocol": "freedom"}]}
    config_path = directory / "xray.json"
    config_path.write_text(json.dumps(config))
    with subprocess.Popen(["xray", "run", "-config", config_path], stdout=subprocess.DEVNULL) as xray:
        try:
            for _ in range(100):
                if xray.poll() is not None:
                    raise RuntimeError("Xray exited during startup")
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=.2).close()
                    break
                except OSError:
                    time.sleep(.02)
            else:
                raise TimeoutError("Xray startup")
            yield url, f"vless://127.0.0.1:{port}"
        finally:
            xray.terminate()


def http_request(proxy, url, tls=None):
    if tls:
        conn = http.client.HTTPSConnection("127.0.0.1", proxy, context=tls, timeout=4)
    else:
        conn = http.client.HTTPConnection("127.0.0.1", proxy, timeout=4)
    try:
        conn.request("POST", url, b"hello", {"Proxy-Authorization":"Basic client-only"})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


@contextlib.contextmanager
def tunnel(proxy, host, port, socks=False):
    with socket.create_connection(("127.0.0.1", proxy), timeout=3) as sock, sock.makefile("rb") as f:
        if socks:
            sock.sendall(bytes([5, 1, 0]))
            assert readn(f, 2) == bytes([5, 0])
            domain = host.encode()
            sock.sendall(bytes([5,1,0,3,len(domain)]) + domain + struct.pack("!H",port))
            code = readn(f,10)[1]
        else:
            addr=f"{host}:{port}"
            sock.sendall(f"CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n\r\n".encode())
            code = int(read_head(f)[0].split()[1])
        yield code, sock, f


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certs = tempfile.TemporaryDirectory()
        d = Path(cls.certs.name)
        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=d, check=True, capture_output=True)
        openssl("req","-x509","-newkey","rsa:2048","-nodes","-subj","/CN=Test CA","-days","1",
                "-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign",
                "-keyout","ca.key","-out","ca.pem")
        openssl("req","-new","-newkey","rsa:2048","-nodes","-subj","/CN=localhost","-keyout","key.pem","-out","req.pem")
        (d/"ext").write_text("subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:ipwho.is\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
        openssl("x509","-req","-in","req.pem","-CA","ca.pem","-CAkey","ca.key","-CAcreateserial","-days","1","-extfile","ext","-out","cert.pem")
        cls.server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server_ctx.load_cert_chain(d/"cert.pem",d/"key.pem")
        cls.client_ctx = ssl.create_default_context(cafile=str(d/"ca.pem"))
        cls.tls_config = f'inbound_cert="{d}/cert.pem"\ninbound_key="{d}/key.pem"\nupstream_ca="{d}/ca.pem"\n'

    @classmethod
    def tearDownClass(cls):
        cls.certs.cleanup()

    @unittest.skipUnless(os.name == "posix" and shutil.which("xray"), "Unix and Xray required")
    def test_encrypted_wss_vision(self):
        def origin(sock):
            with sock.makefile("rb") as f:
                read_head(f)
                self.assertEqual(readn(f, 5), b"hello")
                sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

        with tempfile.TemporaryDirectory(dir="/tmp") as tmp, listener(origin) as dest:
            directory = Path(tmp)
            env = {**os.environ, "TMPDIR": tmp}
            with xray_node(directory, Path(self.certs.name), "ws", "tls", encrypted=True) as (url, label):
                with running(directory, url, self.tls_config, env) as (proxy, web):
                    self.assertEqual(http_request(proxy, f"http://127.0.0.1:{dest}/"), (200, b"ok"))
                    self.assertEqual(api(web, "/api/config")["upstream"], label)
                    relay, = directory.glob("rust-proxy-*")
                    self.assertEqual(relay.stat().st_mode & 0o777, 0o700)
                self.assertFalse(relay.exists())
                with running(directory, url.replace("sni=localhost", "sni=wrong.invalid"), self.tls_config, env) as (proxy, _):
                    self.assertEqual(http_request(proxy, f"http://127.0.0.1:{dest}/")[0], 502)

    @unittest.skipUnless(shutil.which("xray"), "Xray required for VLESS interoperability test")
    def test_vless_xray(self):
        def origin(sock):
            with sock.makefile("rb") as f:
                line, headers = read_head(f)
                self.assertEqual(line, "POST /via-xray?q=ok HTTP/1.1")
                self.assertNotIn("proxy-authorization", headers)
                body = readn(f, int(headers["content-length"]))
                sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n" + body)

        def echo_server(sock):
            with sock.makefile("rb") as f:
                echo(sock, f)

        certs = Path(self.certs.name)
        with tempfile.TemporaryDirectory() as tmp, listener(origin) as dest, listener(echo_server) as echo_port:
            directory = Path(tmp)
            for network, security in (("ws", "tls"), ("ws", "none"), ("tcp", "none"), ("tcp", "tls")):
                with self.subTest(network=network, security=security), xray_node(directory, certs, network, security) as (url, label):
                    with running(directory, url + "#private-name", self.tls_config) as (proxy, web):
                        self.assertEqual(http_request(proxy, f"http://127.0.0.1:{dest}/via-xray?q=ok"), (200, b"hello"))
                        for socks in (False, True):
                            with tunnel(proxy, "localhost", echo_port, socks) as (code, s, f):
                                self.assertEqual(code, 0 if socks else 200)
                                payload = bytes(range(32, 256)) * 300 + b"\n"
                                s.sendall(payload)
                                self.assertEqual(readn(f, len(payload)), payload)
                        self.assertEqual(api(web, "/api/config")["upstream"], label)
                        self.assertEqual(api(web, "/api/traffic")["rows"][0]["upstream"], label)
                    if network == "ws" and security == "tls":
                        for invalid, error in ((url.replace("sni=localhost", "sni=wrong.invalid"), "TLS"),
                                               (url.replace("host=edge.invalid", "host=wrong.invalid"), "WebSocket"),
                                               (url.replace("%2Fedge%2Ftest", "%2Fwrong"), "WebSocket")):
                            with running(directory, invalid, self.tls_config) as (proxy, web):
                                with tunnel(proxy, "127.0.0.1", echo_port) as (code, _, _):
                                    self.assertEqual(code, 502)
                                self.assertIn(error, api(web, "/api/traffic")["rows"][0]["outcome"])
                        with running(directory, url.replace("00112233", "00000000"), self.tls_config) as (proxy, _):
                            self.assertEqual(http_request(proxy, f"http://127.0.0.1:{dest}/via-xray?q=ok")[0], 502)

    def test_protocol_matrix_and_journal(self):
        for scheme in ["http","https","socks5"]:
            with self.subTest(scheme=scheme), tempfile.TemporaryDirectory() as tmp:
                observed=[]
                tls = self.server_ctx if scheme=="https" else None
                with listener(mock_upstream(scheme,observed,tls)) as port:
                    url=f"{scheme}://user:p%40ss@127.0.0.1:{port}"
                    with running(Path(tmp),url,self.tls_config) as (proxy,web):
                        for inbound in [None, self.client_ctx]:
                            self.assertEqual(http_request(proxy,"http://demo.invalid/path?q=secret",inbound),(200,b"upstream:hello"))
                        for socks in [True, False]:
                            with tunnel(proxy,"demo.invalid",443,socks) as (code,s,f):
                                self.assertEqual(code,0 if socks else 200)
                                s.sendall(b"through tunnel\n")
                                self.assertEqual(f.readline(),b"through tunnel\n")
                                live=api(web,"/api/traffic?active=true")
                                self.assertGreaterEqual(live["active"],1)
                                self.assertEqual((live["rows"][0]["up"],live["rows"][0]["down"]),(15,15))
                        if scheme=="socks5":
                            self.assertIn(("demo.invalid",80),observed)
                            self.assertIn("POST /path?q=secret HTTP/1.1",observed)
                        else:
                            self.assertIn("POST http://demo.invalid/path?q=secret HTTP/1.1",observed)
                        # Wait for the final downstream close to reach the log.
                        for _ in range(100):
                            if not api(web,"/api/traffic")["active"]: break
                            time.sleep(.01)
                        logs=api(web,"/api/traffic")["rows"]
                        self.assertEqual(len(logs),4)
                        self.assertTrue(all(r["outcome"]=="ok" for r in logs), logs)
                        self.assertEqual((logs[-1]["up"],logs[-1]["down"],logs[-1]["status"]),(5,14,200))
                        self.assertNotIn("secret",json.dumps(logs))
                        self.assertNotIn("user",json.dumps([logs,api(web,"/api/config")]))
                    with running(Path(tmp),url,self.tls_config) as (_,web):
                        self.assertEqual(len(api(web,"/api/traffic")["rows"]),4)

    def test_egress_lookup_uses_tunnel_and_refreshes_cached_result(self):
        # The test proxy terminates the fixture's TLS inside its CONNECT tunnel.
        # The provider domain never needs to resolve on this machine.
        requests = []
        responses = iter([
            (200, {"success": True, "ip": "2001:db8::7", "country": "Japan", "city": "Tokyo",
                   "connection": {"asn": 64512, "isp": "Test Network"}}),
            (200, {"success": True, "ip": "192.0.2.9"}),
            (429, {"success": False}),
            (200, {"success": True, "ip": "invalid"}),
        ])
        def provider(sock):
            with sock.makefile("rb") as incoming:
                line, _ = read_head(incoming)
                requests.append(line)
                sock.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
            with self.server_ctx.wrap_socket(sock, server_side=True) as tls, tls.makefile("rb") as f:
                line, headers = read_head(f)
                self.assertEqual(line, "GET / HTTP/1.1")
                self.assertEqual(headers["host"], "ipwho.is")
                self.assertNotIn("proxy-authorization", headers)
                status, payload = next(responses)
                body = json.dumps(payload).encode()
                tls.sendall(f"HTTP/1.1 {status} Test\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)

        env = {**os.environ, "SSL_CERT_FILE": str(Path(self.certs.name) / "ca.pem")}
        with tempfile.TemporaryDirectory() as tmp, listener(provider) as port:
            with running(Path(tmp), f"http://user:pass@127.0.0.1:{port}", env=env) as (_, web):
                first = api(web, "/api/egress")
                self.assertEqual(first["status"], "ok", first)
                self.assertEqual(first["info"]["ip"], "2001:db8::7")
                self.assertEqual(first["info"]["connection"]["isp"], "Test Network")
                self.assertEqual(first, api(web, "/api/egress"))
                self.assertEqual(len(requests), 1)
                refreshed = api(web, "/api/egress", "POST")
                self.assertEqual(refreshed["info"]["ip"], "192.0.2.9")
                limited = api(web, "/api/egress", "POST")
                self.assertEqual(limited["status"], "error")
                self.assertIn("429", limited["message"])
                self.assertNotIn("info", limited)
                self.assertEqual(limited, api(web, "/api/egress"))
                self.assertEqual(api(web, "/api/egress", "POST")["status"], "error")
                self.assertEqual(requests, ["CONNECT ipwho.is:443 HTTP/1.1"] * 4)

    def test_closed_upstream_never_dials_reachable_target(self):
        direct=[]
        with tempfile.TemporaryDirectory() as tmp, listener(lambda s: direct.append(True)) as target:
            with running(Path(tmp),f"http://127.0.0.1:{free_port()}") as (proxy,web):
                exit_report = api(web, "/api/egress")
                self.assertEqual(exit_report["status"], "error")
                self.assertIn("上游连接失败", exit_report["message"])
                self.assertNotIn("info", exit_report)
                self.assertEqual(http_request(proxy,f"http://127.0.0.1:{target}/")[0],502)
                for socks in (False,True):
                    with tunnel(proxy,"127.0.0.1",target,socks) as (code, _, f):
                        self.assertEqual(code,1 if socks else 502)
                        self.assertIn(f.read(), [b"",b"Upstream tunnel failed"])
                rows=api(web,"/api/traffic")["rows"]
                self.assertEqual(len(rows),3)
                self.assertTrue(all("upstream" in r["outcome"] for r in rows))
                self.assertEqual(direct,[])

    def test_rejection_timeout_and_tls(self):
        for scheme in ("http","socks5","https","timeout"):
            with self.subTest(scheme=scheme), tempfile.TemporaryDirectory() as tmp:
                handler = (lambda s: time.sleep(2)) if scheme=="timeout" else mock_upstream(scheme,[],self.server_ctx if scheme=="https" else None,True)
                with listener(handler) as port:
                    url=f"{'http' if scheme=='timeout' else scheme}://user:p%40ss@127.0.0.1:{port}"
                    with running(Path(tmp),url) as (proxy,web):
                        with tunnel(proxy,"demo.invalid",443) as (code,_,_):
                            self.assertEqual(code,502)
                        cause=api(web,"/api/traffic")["rows"][0]["outcome"]
                        self.assertIn({"http":"407","socks5":"authentication","https":"TLS","timeout":"timed out"}[scheme],cause)

    def test_tunnel_closes_on_upstream_eof(self):
        with tempfile.TemporaryDirectory() as tmp, listener(mock_upstream("http",[])) as port:
            with running(Path(tmp),f"http://user:p%40ss@127.0.0.1:{port}") as (proxy,_):
                with tunnel(proxy,"demo.invalid",443) as (code,s,f):
                    self.assertEqual(code,200)
                    s.sendall(b"disconnect\n")
                    self.assertEqual(f.read(),b"")


if __name__ == "__main__":
    unittest.main(verbosity=2)
