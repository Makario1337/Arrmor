import http.client
import gzip
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import arrmor  # noqa: E402

arrmor.log.disabled = True

SONARR_KEY = "s" * 32
RADARR_KEY = "r" * 32
SONARR_PROXY = "p" * 40
RADARR_PROXY = "q" * 40


class FakeArr(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    requests: list = []
    chunked = False
    body = None  # override response body (bytes)
    content_type = "application/json"
    gzip = False
    status = 200

    def log_message(self, *a):
        pass

    def _any(self):
        FakeArr.requests.append((self.command, self.path, dict(self.headers)))
        body = FakeArr.body if FakeArr.body is not None else json.dumps({"path": self.path}).encode()
        self.send_response(FakeArr.status)
        if 300 <= FakeArr.status < 400:
            self.send_header("Location", "http://internal-sonarr:8989/login")
        self.send_header("Content-Type", FakeArr.content_type)
        if FakeArr.gzip:
            body = gzip.compress(body)
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Set-Cookie", "secret=1")
        self.send_header("Server", "Kestrel")
        if FakeArr.chunked:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
        else:
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = _any


class ArrmorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), FakeArr)
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()
        up = f"http://127.0.0.1:{cls.upstream.server_port}"
        cfg = arrmor.load_config({
            "ARRMOR_HOST": "127.0.0.1",
            "ARRMOR_PORT": "0",
            "ARRMOR_SONARR_URL": up + "/sonarr-base",
            "ARRMOR_SONARR_API_KEY": SONARR_KEY,
            "ARRMOR_SONARR_PROXY_KEY": SONARR_PROXY,
            "ARRMOR_RADARR_URL": up,
            "ARRMOR_RADARR_API_KEY": RADARR_KEY,
            "ARRMOR_RADARR_PROXY_KEY": RADARR_PROXY,
        })
        cls.proxy = arrmor.make_server(cfg)
        threading.Thread(target=cls.proxy.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for srv in (cls.proxy, cls.upstream):
            srv.shutdown()
            srv.server_close()

    def setUp(self):
        FakeArr.requests.clear()
        FakeArr.chunked = False
        FakeArr.body = None
        FakeArr.content_type = "application/json"
        FakeArr.gzip = False
        FakeArr.status = 200

    def req(self, method, path, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.proxy.server_port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    # ------------------------------------------------------------- allowed
    def test_allowed_get_with_header_key(self):
        resp, data = self.req("GET", "/sonarr/api/v3/series", {"X-Api-Key": SONARR_PROXY})
        self.assertEqual(resp.status, 200)
        method, path, headers = FakeArr.requests[0]
        self.assertEqual(path, "/sonarr-base/api/v3/series")
        self.assertEqual(headers["X-Api-Key"], SONARR_KEY)
        self.assertIsNone(resp.getheader("Set-Cookie"))
        self.assertEqual(resp.getheader("Server"), "Arrmor")
        self.assertNotIn(SONARR_KEY.encode(), data)

    def test_allowed_get_with_query_key_is_stripped(self):
        resp, _ = self.req("GET", f"/radarr/api/v3/movie?tmdbId=603&apikey={RADARR_PROXY}&x=1")
        self.assertEqual(resp.status, 200)
        _, path, headers = FakeArr.requests[0]
        self.assertEqual(path, "/api/v3/movie?tmdbId=603&x=1")
        self.assertNotIn(RADARR_PROXY, path)
        self.assertEqual(headers["X-Api-Key"], RADARR_KEY)

    def test_numeric_id_and_lookup(self):
        for p in ("/radarr/api/v3/movie/12", "/radarr/api/v3/movie/lookup?term=tmdb:603"):
            resp, _ = self.req("GET", p, {"X-Api-Key": RADARR_PROXY})
            self.assertEqual(resp.status, 200, p)

    def test_case_insensitive_paths(self):
        # Seerr requests e.g. /api/v3/qualityProfile and /api/v3/rootFolder
        for p in ("/radarr/api/v3/qualityProfile", "/radarr/api/v3/rootFolder",
                  "/radarr/api/v3/System/Status"):
            resp, _ = self.req("GET", p, {"X-Api-Key": RADARR_PROXY})
            self.assertEqual(resp.status, 200, p)

    def test_head(self):
        resp, _ = self.req("HEAD", "/sonarr/api/v3/system/status", {"X-Api-Key": SONARR_PROXY})
        self.assertEqual(resp.status, 200)

    def test_chunked_upstream(self):
        FakeArr.chunked = True
        resp, data = self.req("GET", "/sonarr/api/v3/series", {"X-Api-Key": SONARR_PROXY})
        self.assertEqual(resp.status, 200)
        self.assertEqual(json.loads(data)["path"], "/sonarr-base/api/v3/series")

    # ------------------------------------------------------------- credential filter
    def get_sonarr(self, path="/sonarr/api/v3/series"):
        return self.req("GET", path, {"X-Api-Key": SONARR_PROXY})

    def test_upstream_never_compresses(self):
        self.req("GET", "/sonarr/api/v3/series", {"X-Api-Key": SONARR_PROXY, "Accept-Encoding": "gzip"})
        self.assertEqual(FakeArr.requests[0][2]["Accept-Encoding"], "identity")

    def test_normal_response_unchanged(self):
        FakeArr.body = b'[ {"title": "Breaking Bad", "tvdbId": 81189, "ratings": {"value": 9.5}} ]'
        resp, data = self.get_sonarr()
        self.assertEqual((resp.status, data), (200, FakeArr.body))

    def test_credential_fields_redacted(self):
        FakeArr.body = json.dumps({
            "title": "ok",
            "apiKey": "abc123",
            "nested": [{"Password": "hunter2", "user_name": "bob"}],
            "fields": [{"name": "apiKey", "value": "zzz"}, {"name": "baseUrl", "value": "/x"}],
            "token": None,
            "authentication": "forms",
        }).encode()
        resp, data = self.get_sonarr()
        self.assertEqual(resp.status, 200)
        self.assertEqual(int(resp.getheader("Content-Length")), len(data))
        doc = json.loads(data)
        self.assertEqual(doc["apiKey"], "********")
        self.assertEqual(doc["nested"][0], {"Password": "********", "user_name": "bob"})
        self.assertEqual(doc["fields"][0]["value"], "********")
        self.assertEqual(doc["fields"][1]["value"], "/x")
        self.assertIsNone(doc["token"])
        self.assertEqual(doc["authentication"], "forms")
        for secret in (b"abc123", b"hunter2", b"zzz"):
            self.assertNotIn(secret, data)

    def test_real_api_key_anywhere_blocks_response(self):
        cases = [
            json.dumps({"comment": f"key is {SONARR_KEY}"}).encode(),       # own key, odd field
            json.dumps({"x": RADARR_KEY}).encode(),                         # other instance's key
            json.dumps({"x": SONARR_KEY.upper()}).encode(),                 # different case
            f"<html>{SONARR_KEY}</html>".encode(),                          # non-JSON
        ]
        for body in cases:
            FakeArr.body = body
            resp, data = self.get_sonarr()
            self.assertEqual(resp.status, 502, body)
            self.assertNotIn(SONARR_KEY.encode(), data.lower())
            self.assertNotIn(RADARR_KEY.encode(), data.lower())

    def test_gzip_upstream_is_checked(self):
        FakeArr.gzip = True
        FakeArr.body = json.dumps({"apiKey": SONARR_KEY}).encode()
        resp, data = self.get_sonarr()
        self.assertEqual(resp.status, 200)  # redacted, so no key left
        self.assertEqual(json.loads(data), {"apiKey": "********"})
        self.assertIsNone(resp.getheader("Content-Encoding"))
        FakeArr.body = json.dumps({"other": SONARR_KEY}).encode()
        resp, _ = self.get_sonarr()
        self.assertEqual(resp.status, 502)

    def test_response_size_limit(self):
        cfg = self.proxy.RequestHandlerClass.config
        old, cfg.max_response = cfg.max_response, 100
        self.addCleanup(setattr, cfg, "max_response", old)
        FakeArr.body = b"[" + b"1," * 100 + b"1]"
        resp, _ = self.get_sonarr()
        self.assertEqual(resp.status, 502)

    # ------------------------------------------------------------- hardening
    def test_upstream_error_body_not_forwarded(self):
        FakeArr.status = 500
        FakeArr.body = b'{"message": "at Sonarr.Api.V3 in /app/sonarr/bin/Sonarr.dll"}'
        resp, data = self.get_sonarr()
        self.assertEqual(resp.status, 500)
        self.assertNotIn(b"Sonarr.dll", data)
        FakeArr.status = 404
        resp, _ = self.get_sonarr()
        self.assertEqual(resp.status, 404)

    def test_upstream_auth_failure_and_redirect(self):
        for status in (401, 403, 302):
            FakeArr.status = status
            resp, data = self.get_sonarr()
            self.assertEqual(resp.status, 502, status)
            self.assertIsNone(resp.getheader("Location"))
            self.assertNotIn(b"internal-sonarr", data)

    def test_unsafe_query_rejected(self):
        h = {"X-Api-Key": SONARR_PROXY}
        for q in ("?term=<script>", "?a=" + "x" * 3000, "?a=\"b\"", "?a=b'c"):
            self.assertBlocked(400, "GET", "/sonarr/api/v3/series" + q, h)
        resp, _ = self.req("GET", "/sonarr/api/v3/series/lookup?term=tvdb:81189&x=a%20b", h)
        self.assertEqual(resp.status, 200)

    def test_duplicate_key_headers_all_checked(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.proxy.server_port, timeout=5)
        conn.putrequest("GET", "/sonarr/api/v3/series")
        conn.putheader("X-Api-Key", SONARR_PROXY)
        conn.putheader("X-Api-Key", "wrong")
        conn.endheaders()
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 401)
        self.assertEqual(FakeArr.requests, [])

    def test_log_path_escaped(self):
        self.assertEqual(arrmor._UNPRINTABLE.sub("?", "/a\x1b[31m\nb"), "/a?[31m?b")

    def test_healthz(self):
        resp, data = self.req("GET", "/healthz")
        self.assertEqual((resp.status, data), (200, b"ok\n"))

    # ------------------------------------------------------------- denied
    def assertBlocked(self, status, method, path, headers=None, body=None):
        resp, _ = self.req(method, path, headers, body)
        self.assertEqual(resp.status, status, f"{method} {path}")
        self.assertEqual(FakeArr.requests, [], f"{method} {path} reached upstream")

    def test_write_methods_denied(self):
        h = {"X-Api-Key": RADARR_PROXY}
        self.assertBlocked(405, "POST", "/radarr/api/v3/movie", h, body=b"{}")
        self.assertBlocked(405, "PUT", "/radarr/api/v3/movie/1", h, body=b"{}")
        self.assertBlocked(405, "DELETE", "/radarr/api/v3/movie/1?deleteFiles=true", h)
        self.assertBlocked(405, "POST", "/radarr/api/v3/command", h, body=b"{}")

    def test_missing_or_wrong_key(self):
        self.assertBlocked(401, "GET", "/sonarr/api/v3/series")
        self.assertBlocked(401, "GET", "/sonarr/api/v3/series", {"X-Api-Key": "nope"})
        self.assertBlocked(401, "GET", "/sonarr/api/v3/series", {"X-Api-Key": SONARR_KEY})
        # key of another instance
        self.assertBlocked(401, "GET", "/sonarr/api/v3/series", {"X-Api-Key": RADARR_PROXY})
        # one good, one bad key
        self.assertBlocked(401, "GET", "/sonarr/api/v3/series?apikey=bad", {"X-Api-Key": SONARR_PROXY})

    def test_sensitive_get_endpoints_denied(self):
        h = {"X-Api-Key": SONARR_PROXY}
        for p in ("/sonarr/api/v3/config/host", "/sonarr/api/v3/indexer",
                  "/sonarr/api/v3/downloadclient", "/sonarr/api/v3/system/backup",
                  "/sonarr/api/v3/log/file", "/sonarr/", "/sonarr", "/sonarr/api/v3/CONFIG/host",
                  "/sonarr/api/v3/IndeXer", "/sonarr/api/v3/series/1/x", "/sonarr/api/v3/movie"):
            self.assertBlocked(403, "GET", p, h)

    def test_path_tricks_denied(self):
        h = {"X-Api-Key": SONARR_PROXY}
        for p in ("/sonarr/api/v3/series/../config/host", "/sonarr/api/v3/series/%2e%2e/config/host",
                  "/sonarr/api/v3/series%2F..%2Fconfig", "/sonarr//api/v3/series",
                  "/sonarr/api/v3/series;x", "/sonarr/api/v3/series/.", "http://evil/sonarr/api/v3/series"):
            self.assertBlocked(400, "GET", p, h)

    def test_unknown_instance(self):
        self.assertBlocked(404, "GET", "/lidarr/api/v1/artist", {"X-Api-Key": SONARR_PROXY})
        self.assertBlocked(404, "GET", "/sonarrx/api/v3/series", {"X-Api-Key": SONARR_PROXY})

    def test_get_with_body_denied(self):
        self.assertBlocked(400, "GET", "/sonarr/api/v3/series", {"X-Api-Key": SONARR_PROXY}, body=b"x")


class ClientAllowListTest(unittest.TestCase):
    def start(self, allowed):
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), FakeArr)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        cfg = arrmor.load_config({
            "ARRMOR_HOST": "127.0.0.1", "ARRMOR_PORT": "0",
            "ARRMOR_ALLOWED_CLIENTS": allowed,
            "ARRMOR_SONARR_URL": f"http://127.0.0.1:{upstream.server_port}",
            "ARRMOR_SONARR_API_KEY": SONARR_KEY, "ARRMOR_SONARR_PROXY_KEY": SONARR_PROXY,
        })
        proxy = arrmor.make_server(cfg)
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        for srv in (upstream, proxy):
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        FakeArr.requests.clear()
        return proxy.server_port

    def req(self, port, method, path):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request(method, path, headers={"X-Api-Key": SONARR_PROXY})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp.status

    def test_foreign_client_blocked(self):
        port = self.start("10.0.0.0/8, 192.168.1.5")
        self.assertEqual(self.req(port, "GET", "/sonarr/api/v3/series"), 403)
        self.assertEqual(self.req(port, "POST", "/sonarr/api/v3/series"), 403)
        self.assertEqual(self.req(port, "GET", "/nothing"), 403)
        self.assertEqual(FakeArr.requests, [])
        # local healthcheck keeps working
        self.assertEqual(self.req(port, "GET", "/healthz"), 200)

    def test_allowed_client_passes(self):
        port = self.start("127.0.0.1")
        self.assertEqual(self.req(port, "GET", "/sonarr/api/v3/series"), 200)

    def test_foreign_ip_dropped_at_connect(self):
        cfg = arrmor.load_config({**ConfigTest.base, "ARRMOR_HOST": "127.0.0.1", "ARRMOR_PORT": "0",
                                  "ARRMOR_ALLOWED_CLIENTS": "10.0.0.0/8"})
        srv = arrmor.make_server(cfg)
        self.addCleanup(srv.server_close)
        self.assertFalse(srv.verify_request(None, ("192.168.1.9", 1234)))
        self.assertTrue(srv.verify_request(None, ("10.1.2.3", 1234)))
        self.assertTrue(srv.verify_request(None, ("127.0.0.1", 1234)))  # local healthcheck

    def test_connection_limit(self):
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), FakeArr)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        cfg = arrmor.load_config({
            "ARRMOR_HOST": "127.0.0.1", "ARRMOR_PORT": "0", "ARRMOR_MAX_CONNECTIONS": "1",
            "ARRMOR_SONARR_URL": f"http://127.0.0.1:{upstream.server_port}",
            "ARRMOR_SONARR_API_KEY": SONARR_KEY, "ARRMOR_SONARR_PROXY_KEY": SONARR_PROXY,
        })
        proxy = arrmor.make_server(cfg)
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        for srv in (upstream, proxy):
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        idle = socket.create_connection(("127.0.0.1", proxy.server_port))  # occupies the only slot
        self.addCleanup(idle.close)
        time.sleep(0.2)
        with self.assertRaises((http.client.HTTPException, OSError)):
            self.req(proxy.server_port, "GET", "/sonarr/api/v3/series")
        idle.close()
        time.sleep(0.2)
        self.assertEqual(self.req(proxy.server_port, "GET", "/sonarr/api/v3/series"), 200)

    def test_ipv4_mapped_ipv6(self):
        cfg = arrmor.load_config({**ConfigTest.base, "ARRMOR_ALLOWED_CLIENTS": "192.168.1.0/24"})
        self.assertTrue(cfg.client_allowed("::ffff:192.168.1.7"))
        self.assertFalse(cfg.client_allowed("192.168.2.7"))
        self.assertFalse(cfg.client_allowed("garbage"))


@unittest.skipUnless(shutil.which("openssl"), "openssl CLI not available")
class TlsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert = os.path.join(cls.tmp.name, "arrmor.crt")
        cls.key = os.path.join(cls.tmp.name, "arrmor.key")
        # Same command as in the README
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1", "-nodes",
             "-keyout", cls.key, "-out", cls.cert, "-subj", "/CN=arrmor",
             "-addext", "subjectAltName=IP:127.0.0.1"],
            check=True, capture_output=True)
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), FakeArr)
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()
        cfg = arrmor.load_config({
            "ARRMOR_HOST": "127.0.0.1", "ARRMOR_PORT": "0",
            "ARRMOR_TLS_CERT": cls.cert, "ARRMOR_TLS_KEY": cls.key,
            "ARRMOR_RADARR_URL": f"http://127.0.0.1:{cls.upstream.server_port}",
            "ARRMOR_RADARR_API_KEY": RADARR_KEY, "ARRMOR_RADARR_PROXY_KEY": RADARR_PROXY,
        })
        cls.proxy = arrmor.make_server(cfg)
        threading.Thread(target=cls.proxy.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for srv in (cls.proxy, cls.upstream):
            srv.shutdown()
            srv.server_close()
        cls.tmp.cleanup()

    def test_verified_https_request(self):
        # Client trusts exactly this self-signed cert (like NODE_EXTRA_CA_CERTS)
        ctx = ssl.create_default_context(cafile=self.cert)
        conn = http.client.HTTPSConnection("127.0.0.1", self.proxy.server_port, context=ctx, timeout=5)
        conn.request("GET", "/radarr/api/v3/qualityProfile", headers={"X-Api-Key": RADARR_PROXY})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 200)

    def test_untrusted_client_rejects_cert(self):
        ctx = ssl.create_default_context()  # system CAs only
        conn = http.client.HTTPSConnection("127.0.0.1", self.proxy.server_port, context=ctx, timeout=5)
        with self.assertRaises(ssl.SSLCertVerificationError):
            conn.request("GET", "/healthz")
        conn.close()

    def test_plain_http_fails(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.proxy.server_port, timeout=5)
        with self.assertRaises((http.client.HTTPException, OSError)):
            conn.request("GET", "/healthz")
            conn.getresponse()
        conn.close()

    def test_tls_config_errors(self):
        base = {**ConfigTest.base}
        for env in ({**base, "ARRMOR_TLS_CERT": self.cert},
                    {**base, "ARRMOR_TLS_KEY": self.key},
                    {**base, "ARRMOR_TLS_CERT": self.key, "ARRMOR_TLS_KEY": self.cert},
                    {**base, "ARRMOR_TLS_CERT": "/nope.crt", "ARRMOR_TLS_KEY": "/nope.key"}):
            with self.assertRaises(arrmor.ConfigError):
                arrmor.load_config(env)


@unittest.skipUnless(shutil.which("openssl"), "openssl CLI not available")
class SelfSignedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.join(self.tmp.name, "certs")
        self.env = {**ConfigTest.base, "ARRMOR_HOST": "127.0.0.1", "ARRMOR_PORT": "0",
                    "ARRMOR_TLS_SELF_SIGNED": "true", "ARRMOR_TLS_DIR": self.dir,
                    "ARRMOR_TLS_SAN": "IP:127.0.0.1, DNS:arrmor.lan"}

    def read(self, name):
        with open(os.path.join(self.dir, name), "rb") as f:
            return f.read()

    def test_generates_reuses_and_regenerates(self):
        cfg = arrmor.load_config(self.env)
        self.assertIsNotNone(cfg.tls)
        first = self.read("arrmor.crt")
        self.assertEqual(os.stat(os.path.join(self.dir, "arrmor.key")).st_mode & 0o777, 0o600)
        # restart: same certificate
        arrmor.load_config(self.env)
        self.assertEqual(self.read("arrmor.crt"), first)
        # SAN changed: new certificate
        arrmor.load_config({**self.env, "ARRMOR_TLS_SAN": "IP:127.0.0.2"})
        self.assertNotEqual(self.read("arrmor.crt"), first)

    def test_client_trusting_generated_cert(self):
        cfg = arrmor.load_config(self.env)
        proxy = arrmor.make_server(cfg)
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        self.addCleanup(proxy.server_close)
        self.addCleanup(proxy.shutdown)
        cert = os.path.join(self.dir, "arrmor.crt")
        ctx = ssl.create_default_context(cafile=cert)
        conn = http.client.HTTPSConnection("127.0.0.1", proxy.server_port, context=ctx, timeout=5)
        conn.request("GET", "/healthz")
        self.assertEqual(conn.getresponse().status, 200)
        conn.close()
        if shutil.which("node"):  # what Seerr does with NODE_EXTRA_CA_CERTS
            out = subprocess.run(
                ["node", "-e", f"require('https').get('https://127.0.0.1:{proxy.server_port}/healthz',"
                 "r=>{console.log(r.statusCode);process.exit(0)}).on('error',e=>{console.log(e.code);process.exit(0)})"],
                env={**os.environ, "NODE_EXTRA_CA_CERTS": cert}, capture_output=True, text=True, timeout=10)
            self.assertEqual(out.stdout.strip(), "200")

    def test_errors(self):
        for env in ({**self.env, "ARRMOR_TLS_SAN": ""},
                    {**self.env, "ARRMOR_TLS_SAN": "10.1.5.3"},
                    {**self.env, "ARRMOR_TLS_SAN": "IP:999.1.1.1"},
                    {**self.env, "ARRMOR_TLS_SAN": "DNS:bad name"},
                    {**self.env, "ARRMOR_TLS_SELF_SIGNED": "maybe"},
                    {**self.env, "ARRMOR_TLS_CERT": "/x.crt", "ARRMOR_TLS_KEY": "/x.key"}):
            with self.assertRaises(arrmor.ConfigError, msg=str(env)):
                arrmor.load_config(env)

    def test_disabled_by_default(self):
        self.assertIsNone(arrmor.load_config(ConfigTest.base).tls)
        self.assertIsNone(arrmor.load_config({**ConfigTest.base, "ARRMOR_TLS_SELF_SIGNED": "false"}).tls)


class ConfigTest(unittest.TestCase):
    base = {"ARRMOR_SONARR_URL": "http://sonarr:8989", "ARRMOR_SONARR_API_KEY": SONARR_KEY,
            "ARRMOR_SONARR_PROXY_KEY": SONARR_PROXY}

    def test_ok(self):
        cfg = arrmor.load_config(self.base)
        self.assertEqual(cfg.instances[0].prefix, "/sonarr")
        self.assertEqual(cfg.instances[0].port, 8989)

    def test_type_inference_and_explicit(self):
        env = {"ARRMOR_SONARR4K_URL": "https://s4k", "ARRMOR_SONARR4K_API_KEY": "a",
               "ARRMOR_SONARR4K_PROXY_KEY": SONARR_PROXY,
               "ARRMOR_MOVIES_URL": "http://m:7878", "ARRMOR_MOVIES_TYPE": "radarr",
               "ARRMOR_MOVIES_API_KEY": "b", "ARRMOR_MOVIES_PROXY_KEY": RADARR_PROXY}
        cfg = arrmor.load_config(env)
        kinds = {i.name: (i.kind, i.port) for i in cfg.instances}
        self.assertEqual(kinds, {"sonarr4k": ("sonarr", 443), "movies": ("radarr", 7878)})

    def test_errors(self):
        bad = [
            {},
            {**self.base, "ARRMOR_SONARR_PROXY_KEY": "short"},
            {**self.base, "ARRMOR_SONARR_PROXY_KEY": SONARR_KEY},
            {**self.base, "ARRMOR_SONARR_API_KEY": ""},
            {**self.base, "ARRMOR_SONARR_URL": "ftp://x"},
            {**self.base, "ARRMOR_SONARR_URL": "http://u:p@x"},
            {**self.base, "ARRMOR_SONARR_EXTRA_ALLOW": "(["},
            {**self.base, "ARRMOR_ALLOWED_CLIENTS": "not-an-ip"},
            {**self.base, "ARRMOR_MAX_CONNECTIONS": "0"},
            {**self.base, "ARRMOR_MAX_UPSTREAM": "-1"},
            {**self.base, "ARRMOR_TIMEOUT": "0"},
            {**self.base, "ARRMOR_MAX_RESPONSE_MB": "abc"},
            {"ARRMOR_FOO_URL": "http://x", "ARRMOR_FOO_API_KEY": "a", "ARRMOR_FOO_PROXY_KEY": SONARR_PROXY},
            {**self.base, "ARRMOR_RADARR_URL": "http://r", "ARRMOR_RADARR_API_KEY": "x",
             "ARRMOR_RADARR_PROXY_KEY": SONARR_PROXY},
        ]
        for env in bad:
            with self.assertRaises(arrmor.ConfigError, msg=str(env)):
                arrmor.load_config(env)


if __name__ == "__main__":
    unittest.main()
