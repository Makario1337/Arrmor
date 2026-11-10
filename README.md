# Arrmor

Allow-list proxy between Seerr and Sonarr/Radarr. Seerr gets only the API calls it needs, no deletes, no config access — and never sees the real API keys. Built for DMZ setups where the request frontend is exposed to the internet.

```
          DMZ             │ firewall │            LAN (arr server)
Internet ──► Seerr ───────┼── :8080 ─┼──► Arrmor ──(real key)──► Sonarr / Radarr
             (proxy key)  │ Seerr IP │      │
                          │   only   │      └─ GET/HEAD on allow-listed endpoints only
```

Arrmor runs next to Sonarr/Radarr. The only thing the DMZ can reach is Arrmor's port.

## What it does

- **Read-only.** `POST`, `PUT`, `PATCH`, `DELETE` and everything else are rejected (`405`). Seerr can show what is in the library, but cannot add, request, search, change or delete anything.
  - One exception, answered by Arrmor itself and **never forwarded**: Seerr's *Download Sync* job sends the command `RefreshMonitoredDownloads` every minute and skips reading the download queue if that fails. Arrmor replies `201` to exactly `{"name": "RefreshMonitoredDownloads"}` (valid proxy key required), so download progress keeps working. Sonarr/Radarr run this refresh on their own every minute anyway. Disable with `ARRMOR_STUB_REFRESH_DOWNLOADS=false`.
- **Allow-list, not just "GET only".** Sonarr/Radarr also expose secrets via GET (`/api/v3/config/host` contains the API key, `/api/v3/indexer` and `/api/v3/downloadclient` contain credentials, `/api/v3/system/backup` …). Arrmor only forwards these paths:

  | Sonarr | Radarr |
  |---|---|
  | `/api/v3/system/status` | `/api/v3/system/status` |
  | `/api/v3/qualityprofile` | `/api/v3/qualityprofile` |
  | `/api/v3/rootfolder` | `/api/v3/rootfolder` |
  | `/api/v3/tag` | `/api/v3/tag` |
  | `/api/v3/queue` | `/api/v3/queue` |
  | `/api/v3/series`, `/api/v3/series/{id}` | `/api/v3/movie`, `/api/v3/movie/{id}` |
  | `/api/v3/series/lookup` | `/api/v3/movie/lookup` |
  | `/api/v3/episode`, `/api/v3/episode/{id}` | |
  | `/api/v3/languageprofile` | |

  Anything else returns `403`. Paths with `..`, `%`-encoding, `//`, `;` etc. and query strings with unusual characters or > 2 KB are rejected (`400`).
- **Credential filter on every response.** Even the allowed endpoints are not trusted blindly:
  - JSON fields that look like credentials (`apiKey`, `password`, `token`, `secret`, `passkey`, … — also in the *arr provider format `{"name": "apiKey", "value": …}`) are replaced with `********`.
  - If a real Sonarr/Radarr API key still appears anywhere in a response (any field, any case, JSON or not), the response is not delivered at all (`502`) and an error is logged.
  - For this, responses are fetched uncompressed and checked as a whole before they are sent (limit: `ARRMOR_MAX_RESPONSE_MB`).
- **Separate keys.** Every instance has its own proxy key. Seerr only knows the proxy key; Arrmor swaps it for the real key. Proxy keys from the query string (`?apikey=`) are stripped before forwarding.
- **Client IP allow-list.** With `ARRMOR_ALLOWED_CLIENTS` connections from any other IP are dropped right away, before TLS or HTTP is even parsed — a second layer behind the firewall.
- **No information leaks.** Only a handful of request/response headers are passed through (no cookies, no `Location`, no `Server`). Error pages of Sonarr/Radarr (stack traces, paths) are replaced by a generic error with the same status code; redirects and upstream auth errors become `502`.
- **Resource limits.** A compromised Seerr cannot exhaust the arr server: max. `ARRMOR_MAX_CONNECTIONS` connections, max. `ARRMOR_MAX_UPSTREAM` parallel requests to Sonarr/Radarr (others wait), response size limit, 60 s idle timeout per connection.
- **Logging.** Every blocked request is logged with the reason — handy to see what Seerr tried to do. Query strings are never logged, control characters are escaped.
- **Tiny.** One Python file, standard library only, runs as `nobody` in isolated mode, works with a read-only root filesystem.

### Security model

| If an attacker… | …they can | …they cannot |
|---|---|---|
| owns Seerr (incl. the proxy key) | list your library, quality profiles, root folders, queue | add, request, search, change or delete anything; read API keys, indexer/download client credentials, config, logs or backups; reach Sonarr/Radarr directly (with the firewall rule) |
| sits elsewhere in the DMZ | — | connect at all (`ARRMOR_ALLOWED_CLIENTS`, firewall); sniff the proxy key (with [HTTPS](#https)) |

## Configuration

Each instance is defined by a group of environment variables. `<NAME>` is uppercase letters/digits only and also becomes the URL prefix (`SONARR` → `/sonarr`).

| Variable | Required | Description |
|---|---|---|
| `ARRMOR_<NAME>_URL` | yes | Upstream URL, e.g. `http://sonarr:8989` (may include a base path) |
| `ARRMOR_<NAME>_API_KEY` | yes | Real Sonarr/Radarr API key |
| `ARRMOR_<NAME>_PROXY_KEY` | yes | Key Seerr uses for Arrmor, ≥ 32 chars, unique per instance |
| `ARRMOR_<NAME>_TYPE` | no | `sonarr` or `radarr`; inferred if `<NAME>` starts with one of those |
| `ARRMOR_<NAME>_EXTRA_ALLOW` | no | Comma-separated extra path regexes (GET only), use with care |
| `ARRMOR_ALLOWED_CLIENTS` | no (recommended) | Comma-separated IPs/CIDRs allowed to connect, e.g. `192.168.50.10`. Empty = any client with a valid key |
| `ARRMOR_TLS_CERT` / `ARRMOR_TLS_KEY` | no | Paths to your own certificate and key (PEM) → HTTPS only, see [HTTPS](#https) |
| `ARRMOR_TLS_SELF_SIGNED` | no | `true` = generate and use a self-signed certificate, see [HTTPS](#https). Default `false` |
| `ARRMOR_TLS_SAN` | with self-signed | Address(es) Seerr connects to, e.g. `IP:10.1.5.3,DNS:arrmor.lan` |
| `ARRMOR_TLS_DIR` | no | Where the self-signed certificate is stored, default `/certs` |
| `ARRMOR_PORT` | no | Listen port, default `8080` |
| `ARRMOR_HOST` | no | Listen address, default `0.0.0.0` |
| `ARRMOR_TIMEOUT` | no | Upstream timeout in seconds, default `60` |
| `ARRMOR_MAX_RESPONSE_MB` | no | Maximum upstream response size, default `64` (a library with thousands of titles needs a few MB) |
| `ARRMOR_MAX_CONNECTIONS` | no | Maximum simultaneous client connections, default `32` |
| `ARRMOR_MAX_UPSTREAM` | no | Maximum parallel requests to Sonarr/Radarr, default `4` |
| `ARRMOR_STUB_REFRESH_DOWNLOADS` | no | Answer Seerr's `RefreshMonitoredDownloads` command locally, default `true` (see above) |
| `ARRMOR_LOG_LEVEL` | no | `DEBUG`, `INFO` (default), `WARNING` |

Generate a proxy key with `openssl rand -hex 32`.

Multiple instances (e.g. a 4K Sonarr) are just another group: `ARRMOR_SONARR4K_URL`, … → prefix `/sonarr4k`.

## Usage

Image tags: `latest` = newest release, `1` / `1.1` / `1.1.1` = pinned release, `edge` = current `main`. Images are built for `amd64`, `arm64` and `armv7`.

```sh
docker run -d --name arrmor --read-only \
  -p 192.168.1.10:8080:8080 \
  -e ARRMOR_ALLOWED_CLIENTS=192.168.50.10 \
  -e ARRMOR_SONARR_URL=http://192.168.1.10:8989 \
  -e ARRMOR_SONARR_API_KEY=<real sonarr key> \
  -e ARRMOR_SONARR_PROXY_KEY=<openssl rand -hex 32> \
  -e ARRMOR_RADARR_URL=http://192.168.1.10:7878 \
  -e ARRMOR_RADARR_API_KEY=<real radarr key> \
  -e ARRMOR_RADARR_PROXY_KEY=<openssl rand -hex 32> \
  ghcr.io/makario1337/arrmor:latest
```

See [docker-compose.example.yml](docker-compose.example.yml) for a setup where Arrmor runs in the same compose stack as Sonarr/Radarr. It reads the keys from a `.env` file next to it — copy [.env.example](.env.example) to `.env` and fill it in:

```sh
cp .env.example .env
openssl rand -hex 32   # run twice, once for SONARR_PROXY_KEY and once for RADARR_PROXY_KEY
```

### Seerr settings

In Seerr → Settings → Services → Add Radarr / Add Sonarr. Example for Arrmor running on `10.1.5.3`, port `8080`:

| Field | Radarr | Sonarr | Notes |
|---|---|---|---|
| Hostname or IP | `10.1.5.3` | `10.1.5.3` | **IP or hostname only** — no path, no port, no `http://` |
| Port | `8080` | `8080` | The port Arrmor is reachable on (host side of the port mapping) |
| Use SSL | off | off | On only if you enabled [HTTPS](#https) |
| API Key | `RADARR_PROXY_KEY` | `SONARR_PROXY_KEY` | The **proxy** key from your `.env`, *not* the real Radarr/Sonarr key |
| URL Base | `/radarr` | `/sonarr` | Selects the instance in Arrmor. Lowercase name of `ARRMOR_<NAME>_URL` |
| External URL | optional | optional | Only used for links in your browser, e.g. the real Radarr address |

> **Common mistake:** putting the path into the hostname field (`10.1.5.3/radarr`). Seerr builds the URL as `http(s)://<hostname>:<port><URL base>/api/v3/…`, so the path **must** go into *URL Base* and the hostname field must contain nothing but the IP/hostname.

Then click **Test**. On success, quality profiles, root folders and tags load and the dialog can be saved. Requests that Seerr later tries to send to Sonarr/Radarr will fail — that is the point.

#### Troubleshooting

Watch `docker logs -f arrmor` while clicking **Test**:

| Log line | Cause |
|---|---|
| *(nothing at all)* | Seerr does not reach Arrmor: wrong IP/port, firewall, port not published — or SSL checkbox doesn't match Arrmor's mode |
| `GET / -> 404 (unknown prefix)` | URL Base empty or wrong (or path put into the hostname field) |
| `-> 401 (bad or missing key …)` | Wrong API key — use the proxy key of *this* instance |
| `-> 403 (client IP not allowed)` | `ARRMOR_ALLOWED_CLIENTS` doesn't contain the IP Seerr connects from (the log shows that IP) |
| `POST …/api/v3/command -> 405 (write method)` every minute | Arrmor older than 1.1.0, or `ARRMOR_STUB_REFRESH_DOWNLOADS=false` — download progress in Seerr won't work |
| `-> 403 (not on … allow-list)` | Seerr needs an endpoint Arrmor doesn't allow yet — please open an issue with the log line |
| `upstream … unreachable` | Arrmor can't reach Sonarr/Radarr: check `ARRMOR_<NAME>_URL` |
| `… rejected Arrmor's API key` | The real key in `ARRMOR_<NAME>_API_KEY` is wrong |
| `BLOCKED connection from … (client IP not allowed)` | Same as above, rejected at connection level |
| `BLOCKED connection … (too many connections)` / `503 busy` | Limits reached — raise `ARRMOR_MAX_CONNECTIONS` / `ARRMOR_MAX_UPSTREAM` if this happens in normal use |
| `exceeds ARRMOR_MAX_RESPONSE_MB` | Very large library — raise `ARRMOR_MAX_RESPONSE_MB` |
| `REDACTED n credential field(s) …` | Arrmor removed credential-like fields from a response. Harmless, but please report the endpoint |
| `BLOCKED response … contains an API key` | A response contained a real API key and was dropped — please open an issue |
| `GET /radarr/api/v3/system/status -> 200` | Connection works |

## HTTPS

Optional, but recommended when the traffic between DMZ and LAN could be sniffed. Arrmor then speaks HTTPS only (TLS 1.2+); plain HTTP requests fail. There are two ways — pick **one**:

### Option A: Arrmor generates a self-signed certificate (easiest)

```yaml
  arrmor:
    volumes:
      - arrmor-certs:/certs          # keeps the certificate across restarts/updates
    environment:
      ARRMOR_TLS_SELF_SIGNED: "true"
      ARRMOR_TLS_SAN: IP:10.1.5.3    # the address Seerr connects to
volumes:
  arrmor-certs:
```

- `ARRMOR_TLS_SAN` must contain the IP or DNS name you enter in Seerr's *Hostname* field, e.g. `IP:10.1.5.3` or `IP:10.1.5.3,DNS:arrmor.lan`. Otherwise Seerr rejects the certificate.
- On first start Arrmor creates `arrmor.crt` / `arrmor.key` in `/certs` (ECDSA P-256, valid 10 years). Later starts reuse it; it is only regenerated when `ARRMOR_TLS_SAN` changes.
- Without a volume the certificate is lost whenever the container is recreated, and Seerr has to be updated again. Use a named volume as above; for a bind mount (`./certs:/certs`) run `chown 65534:65534 certs` first, since Arrmor runs as uid 65534.
- The certificate and its SHA-256 fingerprint are printed to the log on every start. Get the file with:
  ```sh
  docker cp arrmor:/certs/arrmor.crt .
  ```

### Option B: bring your own certificate

```sh
mkdir certs
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout certs/arrmor.key -out certs/arrmor.crt \
  -subj "/CN=arrmor" -addext "subjectAltName=IP:10.1.5.3"
chown 65534:65534 certs/arrmor.key && chmod 400 certs/arrmor.key   # container runs as uid 65534
```

```yaml
  arrmor:
    volumes:
      - ./certs:/certs:ro
    environment:
      ARRMOR_TLS_CERT: /certs/arrmor.crt
      ARRMOR_TLS_KEY: /certs/arrmor.key
```

This also works with a certificate from your own CA or Let's Encrypt (use the full chain).

### Make Seerr trust the certificate

Seerr is a Node.js app and **does not trust self-signed certificates** — neither one generated by Arrmor nor one you made yourself. Copy **only `arrmor.crt`** (never the key) to the Seerr host and add it to Node's trust store:

```yaml
  seerr:
    volumes:
      - ./arrmor.crt:/certs/arrmor.crt:ro
    environment:
      NODE_EXTRA_CA_CERTS: /certs/arrmor.crt
```

Recreate the Seerr container, then tick **Use SSL** in the Sonarr/Radarr settings. If Arrmor ever generates a new certificate (log: `generated NEW self-signed certificate`), copy it again and recreate Seerr.

Do **not** use `NODE_TLS_REJECT_UNAUTHORIZED=0` instead — it disables certificate checks for *all* of Seerr's connections (TMDB, Plex, Jellyfin, …).

## Network recommendations

Run Arrmor on the server that hosts Sonarr/Radarr. It only helps if Seerr cannot reach Sonarr/Radarr directly:

- **Firewall between DMZ and LAN:** allow only `Seerr-IP → arr-server:8080`. Make sure `8989`/`7878` (and everything else) stay blocked from the DMZ.
- **Docker bypasses host firewalls** like ufw for published ports. Enforce the rule on the router/firewall between the networks or in the `DOCKER-USER` iptables chain, and bind the port to the LAN IP (`-p 192.168.1.10:8080:8080`).
- **Set `ARRMOR_ALLOWED_CLIENTS`** to the Seerr IP. Docker preserves the client source IP for published ports; if Seerr's traffic is NATed on the way, use the NAT address instead.
- Ideally Sonarr/Radarr don't publish ports at all and are only reachable through the internal Docker network.
- Without [HTTPS](#https), traffic between Seerr and Arrmor is plain HTTP. The proxy key only grants read access, but other hosts on the path could sniff it.
- Rotate the Sonarr/Radarr API keys once after setting up Arrmor, if Seerr knew them before.

## Development

```sh
python3 -m unittest discover -s tests -v
```

## License

GPL-2.0, see [LICENSE](LICENSE).
