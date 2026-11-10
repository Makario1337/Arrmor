#!/usr/bin/env python3
"""Arrmor - read-only allow-list proxy between Seerr and Sonarr/Radarr.

Seerr talks to Arrmor with a proxy-only API key. Arrmor checks the key,
allows only GET/HEAD requests to a small set of read-only API endpoints and
forwards them with the real Sonarr/Radarr API key. Everything else is denied.

Configuration happens via environment variables, see README.md.
No third-party dependencies, Python >= 3.10.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import urllib.parse
import zlib
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.0.1"

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
# Accept-Encoding is not forwarded: responses must arrive uncompressed so
# they can be checked for credentials.
REQUEST_HEADERS = ("Accept", "Accept-Language")
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

# JSON fields whose values are redacted in every response (compared
# case-insensitively, ignoring "_" and "-"). Also applies to the *arr
# provider format {"name": "apiKey", "value": "..."}.
SENSITIVE_FIELDS = {
    "apikey", "password", "passphrase", "passkey", "rsskey", "secret", "clientsecret",
    "token", "accesstoken", "refreshtoken", "authtoken", "bearertoken", "apitoken",
    "privatekey", "cookie", "cookies", "sessionid", "authorization", "credentials",
}
REDACTED = "********"

# Query parameters carrying credentials are never forwarded.
CREDENTIAL_PARAMS = {"apikey", "access_token"}

# Strict character set for request paths. No percent-encoding, no dots,
# no backslashes -> no traversal or normalization tricks.
SAFE_PATH = re.compile(r"/[A-Za-z0-9_\-/]*")
# Query strings: URL-safe characters only, limited length.
SAFE_QUERY = re.compile(r"[A-Za-z0-9_\-.~%+=&:,*]*")
MAX_QUERY = 2048

# Cheap pre-check: only parse/redact JSON that has a credential-like key
# ("...key/pass/token...": ) or a provider field {"name": "...key..."}.
_SENSITIVE_HINT = re.compile(
    rb'"[^"]{0,64}(key|pass|secret|token|cookie|session|auth|credential)[^"]{0,64}"\s*:'
    rb'|"name"\s*:\s*"[^"]{0,64}(key|pass|secret|token|cookie|session|auth|credential)',
    re.IGNORECASE)
_UNPRINTABLE = re.compile(r"[^\x21-\x7e]")


class ConfigError(Exception):
    pass


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _has_value(v) -> bool:
    return v not in (None, "", [], {}) and not isinstance(v, bool)


def redact(obj) -> int:
    """Replace values of credential-like fields in a parsed JSON document
    in place. Returns the number of redacted values."""
    count = 0
    if isinstance(obj, dict):
        name = obj.get("name")
        if (isinstance(name, str) and _norm(name) in SENSITIVE_FIELDS
                and _has_value(obj.get("value"))):
            obj["value"] = REDACTED
            count += 1
        for key, value in obj.items():
            if _norm(key) in SENSITIVE_FIELDS and _has_value(value):
                obj[key] = REDACTED
                count += 1
            else:
                count += redact(value)
    elif isinstance(obj, list):
        for value in obj:
            count += redact(value)
    return count


def contains_secret(body: bytes, secrets: list[str]) -> bool:
    """True if any of the secrets appears anywhere in body (case-insensitive)."""
    lowered = body.lower()
    return any(s and s.lower().encode() in lowered for s in secrets)


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


def parse_san(value: str) -> str:
    """Validate a subjectAltName list like 'IP:10.1.5.3,DNS:arrmor.lan'."""
    entries = []
    for entry in value.split(","):
        kind, _, name = entry.strip().partition(":")
        kind, name = kind.strip().upper(), name.strip()
        if kind == "IP":
            try:
                name = str(ipaddress.ip_address(name))
            except ValueError:
                raise ConfigError(f"ARRMOR_TLS_SAN: invalid IP {name!r}")
        elif kind == "DNS":
            if not re.fullmatch(r"(\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?", name):
                raise ConfigError(f"ARRMOR_TLS_SAN: invalid DNS name {name!r}")
        else:
            raise ConfigError(
                f"ARRMOR_TLS_SAN: entries must look like IP:10.1.5.3 or DNS:arrmor.lan, got {entry.strip()!r}")
        entries.append(f"{kind}:{name}")
    return ",".join(entries)


def ensure_self_signed(directory: str, san: str) -> tuple[str, str]:
    """Create a self-signed certificate in `directory` unless a matching one exists.

    The certificate is reused across restarts (so Seerr's trust stays valid)
    and only regenerated when ARRMOR_TLS_SAN changes.
    """
    cert = os.path.join(directory, "arrmor.crt")
    key = os.path.join(directory, "arrmor.key")
    marker = os.path.join(directory, "arrmor.san")
    try:
        with open(marker) as f:
            existing = f.read().strip()
    except OSError:
        existing = None
    if existing == san and os.path.isfile(cert) and os.path.isfile(key):
        log.info("using existing self-signed certificate %s (%s)", cert, san)
        return cert, key

    if not shutil.which("openssl"):
        raise ConfigError("ARRMOR_TLS_SELF_SIGNED needs the openssl binary")
    try:
        os.makedirs(directory, exist_ok=True)
        tmp_cert, tmp_key = cert + ".tmp", key + ".tmp"
        result = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-sha256", "-days", "3650", "-nodes", "-subj", "/CN=arrmor",
             "-addext", f"subjectAltName={san}",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,digitalSignature,keyCertSign",
             "-addext", "extendedKeyUsage=serverAuth",
             "-keyout", tmp_key, "-out", tmp_cert],
            capture_output=True, text=True, umask=0o077,
        )
        if result.returncode != 0:
            raise ConfigError(f"openssl failed: {result.stderr.strip()}")
        os.chmod(tmp_cert, 0o644)
        os.replace(tmp_key, key)
        os.replace(tmp_cert, cert)
        with open(marker, "w") as f:
            f.write(san + "\n")
    except OSError as e:
        raise ConfigError(f"cannot write self-signed certificate to {directory}: {e} "
                          "(is the directory a writable volume owned by uid 65534?)")

    log.warning("generated NEW self-signed certificate %s for %s - "
                "Seerr has to trust this certificate (NODE_EXTRA_CA_CERTS), see README", cert, san)
    return cert, key


def log_certificate(cert_path: str) -> None:
    with open(cert_path) as f:
        pem = f.read()
    der = ssl.PEM_cert_to_DER_cert(pem)
    fp = hashlib.sha256(der).hexdigest().upper()
    log.info("TLS certificate SHA-256 fingerprint: %s", ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)))
    log.info("TLS certificate (copy to the Seerr host as arrmor.crt):\n%s", pem.strip())


@dataclass
class Config:
    host: str
    port: int
    timeout: float
    instances: list[Instance]
    allowed_clients: list = field(default_factory=list)  # empty = everyone
    tls: ssl.SSLContext | None = None  # None = plain HTTP
    tls_cert: str | None = None  # set when self-signed, for logging
    max_response: int = 64 * 1024 * 1024
    max_connections: int = 32
    max_upstream: int = 4

    @property
    def secrets(self) -> list[str]:
        # All real API keys. Very short values are ignored (would match
        # everywhere); real Sonarr/Radarr keys have 32 characters.
        return [i.api_key for i in self.instances if len(i.api_key) >= 8]

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
        max_response = int(float(env.get("ARRMOR_MAX_RESPONSE_MB", "64")) * 1024 * 1024)
        max_connections = int(env.get("ARRMOR_MAX_CONNECTIONS", "32"))
        max_upstream = int(env.get("ARRMOR_MAX_UPSTREAM", "4"))
    except ValueError:
        raise ConfigError("ARRMOR_PORT / ARRMOR_TIMEOUT / ARRMOR_MAX_* must be numbers")
    if min(port, max_response, max_connections, max_upstream) < 0 or timeout <= 0 \
            or min(max_response, max_connections, max_upstream) == 0:
        raise ConfigError("ARRMOR_PORT / ARRMOR_TIMEOUT / ARRMOR_MAX_* must be positive")

    allowed_clients = []
    for entry in env.get("ARRMOR_ALLOWED_CLIENTS", "").split(","):
        if entry := entry.strip():
            try:
                allowed_clients.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                raise ConfigError(f"ARRMOR_ALLOWED_CLIENTS: invalid IP or CIDR {entry!r}")

    tls = None
    tls_cert = None
    cert = env.get("ARRMOR_TLS_CERT", "").strip()
    key = env.get("ARRMOR_TLS_KEY", "").strip()
    self_signed = env.get("ARRMOR_TLS_SELF_SIGNED", "").strip().lower()
    if self_signed not in ("", "false", "0", "no", "true", "1", "yes"):
        raise ConfigError("ARRMOR_TLS_SELF_SIGNED must be true or false")
    if bool(cert) != bool(key):
        raise ConfigError("ARRMOR_TLS_CERT and ARRMOR_TLS_KEY must be set together")
    if self_signed in ("true", "1", "yes"):
        if cert:
            raise ConfigError("use either ARRMOR_TLS_SELF_SIGNED or ARRMOR_TLS_CERT/ARRMOR_TLS_KEY, not both")
        san = env.get("ARRMOR_TLS_SAN", "").strip()
        if not san:
            raise ConfigError("ARRMOR_TLS_SELF_SIGNED needs ARRMOR_TLS_SAN, the address Seerr connects to, "
                              "e.g. IP:10.1.5.3 or DNS:arrmor.lan")
        cert, key = ensure_self_signed(env.get("ARRMOR_TLS_DIR", "/certs"), parse_san(san))
        tls_cert = cert
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
        tls_cert=tls_cert,
        max_response=max_response,
        max_connections=max_connections,
        max_upstream=max_upstream,
    )


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 60  # idle/read timeout per connection (slowloris protection)
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
        # Never log the query string - it may contain an API key. Escape
        # anything unprintable so requests cannot forge log lines.
        return _UNPRINTABLE.sub("?", self.path.partition("?")[0][:200])

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
        if len(raw_query) > MAX_QUERY or not SAFE_QUERY.fullmatch(raw_query):
            return self._reply(400, "invalid query", reason="unsafe query string")

        inst = next(
            (i for i in self.config.instances
             if raw_path == i.prefix or raw_path.startswith(i.prefix + "/")),
            None,
        )
        if inst is None:
            return self._reply(404, "unknown instance", reason="unknown prefix")

        # Collect credentials from header and query, drop them from the query.
        presented = list(self.headers.get_all("X-Api-Key") or [])
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
        headers["Accept-Encoding"] = "identity"

        if inst.scheme == "https":
            conn = http.client.HTTPSConnection(
                inst.host, inst.port, timeout=self.config.timeout,
                context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(inst.host, inst.port, timeout=self.config.timeout)

        # Limit parallel upstream requests: every response is buffered in
        # memory, so this bounds RAM usage and load on Sonarr/Radarr.
        if not self.server.upstream_slots.acquire(timeout=self.config.timeout):
            return self._reply(503, "busy", reason="too many parallel requests")
        try:
            try:
                conn.request(self.command, target, headers=headers)
                resp = conn.getresponse()
                body = b"" if self.command == "HEAD" else resp.read(self.config.max_response + 1)
            except (OSError, http.client.HTTPException) as e:
                log.error("upstream %s unreachable: %s", inst.name, e)
                return self._reply(502, "upstream unreachable")
            finally:
                conn.close()
            return self._relay(inst, sub_path, resp, body)
        finally:
            self.server.upstream_slots.release()

    def _relay(self, inst: Instance, sub_path: str, resp: http.client.HTTPResponse, body: bytes) -> None:

        logged_path = inst.prefix + sub_path

        # Upstream errors: pass the status, but not the body (stack traces,
        # paths, ...). Seerr only looks at the status code.
        if resp.status >= 400:
            if resp.status == 401:
                log.error("%s rejected Arrmor's API key - check ARRMOR_%s_API_KEY",
                          inst.name, inst.name.upper())
            else:
                log.warning("%s %s %s -> upstream %d", self.client_address[0], self.command,
                            logged_path, resp.status)
            status = 502 if resp.status in (401, 403) else resp.status
            return self._reply(status, f"upstream error {resp.status}")
        if 300 <= resp.status < 400:
            log.warning("%s %s -> upstream redirect %d dropped", self.command, logged_path, resp.status)
            return self._reply(502, "unexpected upstream redirect")

        if len(body) > self.config.max_response:
            log.error("response from %s for %s exceeds ARRMOR_MAX_RESPONSE_MB", inst.name, logged_path)
            return self._reply(502, "upstream response too large")

        encoding = (resp.getheader("Content-Encoding") or "identity").lower().strip()
        if encoding in ("gzip", "deflate") and body:
            try:
                d = zlib.decompressobj(zlib.MAX_WBITS | 32)  # gzip or zlib header
                body = d.decompress(body, self.config.max_response + 1)
            except zlib.error as e:
                log.error("cannot decompress response from %s: %s", inst.name, e)
                return self._reply(502, "invalid upstream response")
            if len(body) > self.config.max_response or d.unconsumed_tail:
                return self._reply(502, "upstream response too large")
        elif encoding != "identity":
            log.error("unsupported Content-Encoding %r from %s", encoding, inst.name)
            return self._reply(502, "invalid upstream response")

        # Layer 2: redact credential-like JSON fields.
        if (body and "json" in (resp.getheader("Content-Type") or "").lower()
                and _SENSITIVE_HINT.search(body)):
            try:
                data = json.loads(body)
                n = redact(data)
            except (ValueError, RecursionError):
                data, n = None, 0
            if n:
                body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
                log.warning("REDACTED %d credential field(s) in response %s %s",
                            n, self.command, logged_path)

        # Layer 3: never deliver a response that contains a real API key.
        if contains_secret(body, self.config.secrets):
            log.error("BLOCKED response %s %s: contains an API key", self.command, logged_path)
            return self._reply(502, "response blocked")

        try:
            self.send_response(resp.status)
            for name in RESPONSE_HEADERS:
                if name in ("Content-Length", "Content-Encoding"):
                    continue
                if (value := resp.getheader(name)) is not None:
                    self.send_header(name, value)
            if self.command == "HEAD":
                if (length := resp.getheader("Content-Length")) is not None:
                    self.send_header("Content-Length", length)
            else:
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError as e:
            self.close_connection = True
            log.error("error while sending response for %s: %s", logged_path, e)
            return
        log.info("%s %s %s -> %d", self.client_address[0], self.command, logged_path, resp.status)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    tls: ssl.SSLContext | None = None
    config: Config
    connection_slots: threading.BoundedSemaphore
    upstream_slots: threading.BoundedSemaphore

    def verify_request(self, request, client_address) -> bool:
        # Drop connections from foreign IPs before TLS or HTTP parsing.
        ip = client_address[0]
        if self.config.client_allowed(ip):
            return True
        try:
            if ipaddress.ip_address(ip).is_loopback:  # local healthcheck
                return True
        except ValueError:
            pass
        log.warning("BLOCKED connection from %s (client IP not allowed)", ip)
        return False

    def process_request(self, request, client_address) -> None:
        if not self.connection_slots.acquire(blocking=False):
            log.warning("BLOCKED connection from %s (too many connections)", client_address[0])
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.connection_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connection_slots.release()

    def finish_request(self, request, client_address) -> None:
        # Runs in the per-connection thread, so a slow TLS handshake never
        # blocks accepting other connections.
        if self.tls is None:
            return super().finish_request(request, client_address)
        # wrap_socket() detaches the plain socket, so shutdown_request() would
        # not close the TLS socket - close it here explicitly.
        tls_sock = self.tls.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
        try:
            tls_sock.settimeout(30)
            tls_sock.do_handshake()
            super().finish_request(tls_sock, client_address)
        finally:
            try:
                tls_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            tls_sock.close()

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
    server.config = config
    server.connection_slots = threading.BoundedSemaphore(config.max_connections)
    server.upstream_slots = threading.BoundedSemaphore(config.max_upstream)
    return server


def healthcheck() -> int:
    port = int(os.environ.get("ARRMOR_PORT", "8080"))
    try:
        if os.environ.get("ARRMOR_TLS_CERT") or os.environ.get(
                "ARRMOR_TLS_SELF_SIGNED", "").strip().lower() in ("true", "1", "yes"):
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
    if config.tls_cert:
        log_certificate(config.tls_cert)
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
