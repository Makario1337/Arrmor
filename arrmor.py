#!/usr/bin/env python3
"""Arrmor - read-only allow-list proxy between Seerr and Sonarr/Radarr.

Seerr talks to Arrmor with a proxy-only API key. Arrmor checks the key,
allows only GET/HEAD requests to a small set of read-only API endpoints and
forwards them with the real Sonarr/Radarr API key. Everything else is denied.

Configuration happens via environment variables, see README.md.
No third-party dependencies, Python >= 3.10.
"""

from __future__ import annotations

import hmac
import http.client
import ipaddress
import json
import logging
import os
import re
import signal
import ssl
import sys
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.3.0"

log = logging.getLogger("arrmor")

# --------------------------------------------------------------------------
# Allow-list: everything Seerr needs to *display* the library and test the
# connection. Patterns are matched against the full path (after the instance
# prefix has been removed), case-insensitive (like Sonarr/Radarr routing),
# without query string.
# --------------------------------------------------------------------------
_COMMON = [
    r"/api/v3/system/status",  # connection test, version detection
    r"/api/v3/qualityprofile",  # settings dialog
    r"/api/v3/rootfolder",  # settings dialog
    r"/api/v3/tag",  # settings dialog / tag lookup
    r"/api/v3/queue",  # download progress
]

DEFAULT_ALLOW: dict[str, list[str]] = {
    "radarr": _COMMON
    + [
        r"/api/v3/movie",
        r"/api/v3/movie/\d+",
        r"/api/v3/movie/lookup",
    ],
    "sonarr": _COMMON
    + [
        r"/api/v3/series",
        r"/api/v3/series/\d+",
        r"/api/v3/series/lookup",
        r"/api/v3/episode",
        r"/api/v3/episode/\d+",
        r"/api/v3/languageprofile",  # Sonarr v3 only
    ],
}

# Only these headers are passed from Seerr to the upstream ...
REQUEST_HEADERS = ("Accept", "Accept-Encoding", "Accept-Language")
# ... and only these from the upstream back to Seerr.
RESPONSE_HEADERS = (
    "Content-Type",
    "Content-Length",
    "Content-Encoding",
    "Cache-Control",
    "ETag",
    "Last-Modified",
    "Vary",
)

# Query parameters carrying credentials are never forwarded.
CREDENTIAL_PARAMS = {"apikey", "access_token"}

# Strict character set for request paths. No percent-encoding, no dots,
# no backslashes -> no traversal or normalization tricks.
SAFE_PATH = re.compile(r"/[A-Za-z0-9_\-/]*")


class ConfigError(Exception):
    pass


@dataclass
class Instance:
    name: str
    kind: str
    prefix: str
    scheme: str
    host: str
    port: int
    base_path: str
    api_key: str = field(repr=False)
    proxy_key: str = field(repr=False)
    allow: list[re.Pattern] = field(repr=False)

    def allowed(self, path: str) -> bool:
        return any(p.fullmatch(path) for p in self.allow)


@dataclass
class Config:
    host: str
    port: int
    timeout: float
    instances: list[Instance]
    allowed_clients: list = field(default_factory=list)  # empty = everyone
    tls: ssl.SSLContext | None = None  # None = plain HTTP

    def client_allowed(self, ip: str) -> bool:
        if not self.allowed_clients:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return any(addr in net for net in self.allowed_clients)


def load_config(env: dict[str, str]) -> Config:
    names = sorted(
        m.group(1)
        for key in env
        if (m := re.fullmatch(r"ARRMOR_([A-Z0-9]+)_URL", key))
    )
    if not names:
        raise ConfigError(
            "no instances configured - set e.g. ARRMOR_SONARR_URL, "
            "ARRMOR_SONARR_API_KEY and ARRMOR_SONARR_PROXY_KEY"
        )

    instances = []
    seen_proxy_keys: set[str] = set()
    for name in names:
        def get(suffix: str, required: bool = True) -> str:
            value = env.get(f"ARRMOR_{name}_{suffix}", "").strip()
            if required and not value:
                raise ConfigError(f"ARRMOR_{name}_{suffix} is required")
            return value

        kind = get("TYPE", required=False).lower()
        if not kind:
            kind = next((k for k in DEFAULT_ALLOW if name.lower().startswith(k)), "")
        if kind not in DEFAULT_ALLOW:
            raise ConfigError(
                f"ARRMOR_{name}_TYPE must be one of {sorted(DEFAULT_ALLOW)} "
                "(can be omitted if the name starts with SONARR or RADARR)"
            )

        url = urllib.parse.urlsplit(get("URL"))
        if url.scheme not in ("http", "https") or not url.hostname:
            raise ConfigError(f"ARRMOR_{name}_URL must be an http(s) URL")
        if url.query or url.fragment or url.username:
            raise ConfigError(f"ARRMOR_{name}_URL must not contain query, fragment or credentials")

        api_key = get("API_KEY")
        proxy_key = get("PROXY_KEY")
        if len(proxy_key) < 32:
            raise ConfigError(
                f"ARRMOR_{name}_PROXY_KEY must be at least 32 characters "
                "(generate one with: openssl rand -hex 32)"
            )
        if hmac.compare_digest(proxy_key, api_key):
            raise ConfigError(f"ARRMOR_{name}_PROXY_KEY must differ from the real API key")
        if proxy_key in seen_proxy_keys:
            raise ConfigError(f"ARRMOR_{name}_PROXY_KEY is used by another instance")
        seen_proxy_keys.add(proxy_key)

        patterns = list(DEFAULT_ALLOW[kind])
        extra = get("EXTRA_ALLOW", required=False)
        patterns += [p.strip() for p in extra.split(",") if p.strip()]
        try:
            allow = [re.compile(p, re.IGNORECASE) for p in patterns]
        except re.error as e:
            raise ConfigError(f"ARRMOR_{name}_EXTRA_ALLOW contains an invalid regex: {e}")

        instances.append(
            Instance(
                name=name.lower(),
                kind=kind,
                prefix="/" + name.lower(),
                scheme=url.scheme,
                host=url.hostname,
                port=url.port or (443 if url.scheme == "https" else 80),
                base_path=url.path.rstrip("/"),
                api_key=api_key,
                proxy_key=proxy_key,
                allow=allow,
            )
        )

    try:
        port = int(env.get("ARRMOR_PORT", "8080"))
        timeout = float(env.get("ARRMOR_TIMEOUT", "60"))
    except ValueError:
        raise ConfigError("ARRMOR_PORT / ARRMOR_TIMEOUT must be numbers")

    allowed_clients = []
    for entry in env.get("ARRMOR_ALLOWED_CLIENTS", "").split(","):
        if entry := entry.strip():
            try:
                allowed_clients.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                raise ConfigError(f"ARRMOR_ALLOWED_CLIENTS: invalid IP or CIDR {entry!r}")

    tls = None
    cert = env.get("ARRMOR_TLS_CERT", "").strip()
    key = env.get("ARRMOR_TLS_KEY", "").strip()
    if bool(cert) != bool(key):
        raise ConfigError("ARRMOR_TLS_CERT and ARRMOR_TLS_KEY must be set together")
    if cert:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            tls.load_cert_chain(cert, key)
        except (OSError, ssl.SSLError) as e:
            raise ConfigError(f"cannot load TLS certificate/key: {e}")

    return Config(
        host=env.get("ARRMOR_HOST", "0.0.0.0"),
        port=port,
        timeout=timeout,
        instances=instances,
        allowed_clients=allowed_clients,
        tls=tls,
    )


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    config: Config  # set by make_server()

    def version_string(self) -> str:
        return "Arrmor"

    # ---------------------------------------------------------------- helpers
    def _reply(self, status: int, message: str, reason: str | None = None) -> None:
        body = json.dumps({"error": message}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        if reason:
            log.warning("BLOCKED %s %s %s -> %d (%s)",
                        self.client_address[0], self.command, self._log_path(), status, reason)

    def _log_path(self) -> str:
        # Never log the query string - it may contain an API key.
        return self.path.partition("?")[0][:200]

    def log_message(self, fmt: str, *args) -> None:  # silence default logging
        pass

    def log_error(self, fmt: str, *args) -> None:
        log.debug(fmt, *args)

    # ---------------------------------------------------------------- methods
    def do_GET(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle()

    def _deny_method(self) -> None:
        self.close_connection = True  # body (if any) is not read
        if not self.config.client_allowed(self.client_address[0]):
            return self._reply(403, "forbidden", reason="client IP not allowed")
        self._reply(405, "method not allowed", reason="write method")

    do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_TRACE = do_CONNECT = _deny_method

    # ---------------------------------------------------------------- core
    def _handle(self) -> None:
        raw_path, _, raw_query = self.path.partition("?")
        client = self.client_address[0]

        if raw_path == "/healthz" and (
            self.config.client_allowed(client) or ipaddress.ip_address(client).is_loopback
        ):
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            return

        if not self.config.client_allowed(client):
            self.close_connection = True
            return self._reply(403, "forbidden", reason="client IP not allowed")

        if self.headers.get("Content-Length", "0") != "0" or "Transfer-Encoding" in self.headers:
            self.close_connection = True
            return self._reply(400, "request body not allowed", reason="body on GET")

        if not SAFE_PATH.fullmatch(raw_path) or "//" in raw_path:
            return self._reply(400, "invalid path", reason="unsafe path")

        inst = next(
            (i for i in self.config.instances
             if raw_path == i.prefix or raw_path.startswith(i.prefix + "/")),
            None,
        )
        if inst is None:
            return self._reply(404, "unknown instance", reason="unknown prefix")

        # Collect credentials from header and query, drop them from the query.
        presented = []
        if (h := self.headers.get("X-Api-Key")) is not None:
            presented.append(h)
        kept = []
        for pair in raw_query.split("&") if raw_query else []:
            key, _, value = pair.partition("=")
            if urllib.parse.unquote_plus(key).lower() in CREDENTIAL_PARAMS:
                presented.append(urllib.parse.unquote_plus(value))
            else:
                kept.append(pair)

        if not presented or not all(
            hmac.compare_digest(p.encode(), inst.proxy_key.encode()) for p in presented
        ):
            return self._reply(401, "unauthorized", reason=f"bad or missing key for {inst.name}")

        sub_path = raw_path[len(inst.prefix):] or "/"
        if not inst.allowed(sub_path):
            return self._reply(403, "endpoint not allowed", reason=f"not on {inst.kind} allow-list")

        self._forward(inst, sub_path, "&".join(kept))

    def _forward(self, inst: Instance, sub_path: str, query: str) -> None:
        target = inst.base_path + sub_path + (f"?{query}" if query else "")
        headers = {h: v for h in REQUEST_HEADERS if (v := self.headers.get(h))}
        headers["X-Api-Key"] = inst.api_key
        headers["User-Agent"] = f"Arrmor/{VERSION}"

        if inst.scheme == "https":
            conn = http.client.HTTPSConnection(
                inst.host, inst.port, timeout=self.config.timeout,
                context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(inst.host, inst.port, timeout=self.config.timeout)

        try:
            conn.request(self.command, target, headers=headers)
            resp = conn.getresponse()
        except (OSError, http.client.HTTPException) as e:
            conn.close()
            log.error("upstream %s unreachable: %s", inst.name, e)
            return self._reply(502, "upstream unreachable")

        try:
            self.send_response(resp.status)
            for name in RESPONSE_HEADERS:
                if name == "Content-Length":
                    continue
                if (value := resp.getheader(name)) is not None:
                    self.send_header(name, value)
            length = resp.getheader("Content-Length")
            if length is not None and resp.getheader("Transfer-Encoding") is None:
                self.send_header("Content-Length", length)
            elif self.command != "HEAD":
                # Unknown length: stream until EOF, then close the connection.
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()

            if self.command != "HEAD":
                while chunk := resp.read(65536):
                    self.wfile.write(chunk)
            log.info("%s %s %s -> %d", self.client_address[0], self.command,
                     inst.prefix + sub_path, resp.status)
        except (OSError, http.client.HTTPException) as e:
            self.close_connection = True
            log.error("error while relaying response from %s: %s", inst.name, e)
        finally:
            conn.close()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    tls: ssl.SSLContext | None = None

    def finish_request(self, request, client_address) -> None:
        # Runs in the per-connection thread, so a slow TLS handshake never
        # blocks accepting other connections.
        if self.tls is not None:
            request.settimeout(30)
            request = self.tls.wrap_socket(request, server_side=True)
            request.settimeout(None)
        super().finish_request(request, client_address)

    def handle_error(self, request, client_address) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, TimeoutError, ssl.SSLError)):
            log.debug("client %s disconnected: %s", client_address[0], exc)
        else:
            log.exception("unhandled error for client %s", client_address[0])


def make_server(config: Config) -> ThreadingHTTPServer:
    handler = type("ConfiguredHandler", (Handler,), {"config": config})
    server = Server((config.host, config.port), handler)
    server.tls = config.tls
    return server


def healthcheck() -> int:
    port = int(os.environ.get("ARRMOR_PORT", "8080"))
    try:
        if os.environ.get("ARRMOR_TLS_CERT"):
            # Local check only - the certificate is issued for the public address.
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=ctx)
        else:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/healthz")
        ok = conn.getresponse().status == 200
        conn.close()
        return 0 if ok else 1
    except OSError:
        return 1


def main() -> int:
    if "--healthcheck" in sys.argv[1:]:
        return healthcheck()

    logging.basicConfig(
        level=os.environ.get("ARRMOR_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        config = load_config(dict(os.environ))
    except ConfigError as e:
        log.error("configuration error: %s", e)
        return 2

    server = make_server(config)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    log.info("Arrmor %s listening on %s://%s:%d", VERSION,
             "https" if config.tls else "http", config.host, config.port)
    if config.allowed_clients:
        log.info("  allowed clients: %s", ", ".join(map(str, config.allowed_clients)))
    else:
        log.warning("  ARRMOR_ALLOWED_CLIENTS not set - any client with a valid key is accepted")
    for i in config.instances:
        log.info("  %-10s (%s) -> %s://%s:%d%s", i.prefix, i.kind, i.scheme, i.host, i.port, i.base_path)
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
