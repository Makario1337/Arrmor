import http.client
import json
import os
import sys
import threading
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

    def log_message(self, *a):
        pass

    def _any(self):
        FakeArr.requests.append((self.command, self.path, dict(self.headers)))
        body = json.dumps({"path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
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

    def test_ipv4_mapped_ipv6(self):
        cfg = arrmor.load_config({**ConfigTest.base, "ARRMOR_ALLOWED_CLIENTS": "192.168.1.0/24"})
        self.assertTrue(cfg.client_allowed("::ffff:192.168.1.7"))
        self.assertFalse(cfg.client_allowed("192.168.2.7"))
        self.assertFalse(cfg.client_allowed("garbage"))


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
            {"ARRMOR_FOO_URL": "http://x", "ARRMOR_FOO_API_KEY": "a", "ARRMOR_FOO_PROXY_KEY": SONARR_PROXY},
            {**self.base, "ARRMOR_RADARR_URL": "http://r", "ARRMOR_RADARR_API_KEY": "x",
             "ARRMOR_RADARR_PROXY_KEY": SONARR_PROXY},
        ]
        for env in bad:
            with self.assertRaises(arrmor.ConfigError, msg=str(env)):
                arrmor.load_config(env)


if __name__ == "__main__":
    unittest.main()
