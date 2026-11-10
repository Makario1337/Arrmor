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

  Anything else returns `403`. Paths with `..`, `%`-encoding, `//`, `;` etc. are rejected (`400`).
- **Separate keys.** Every instance has its own proxy key. Seerr only knows the proxy key; Arrmor swaps it for the real key. Proxy keys from the query string (`?apikey=`) are stripped before forwarding.
- **Client IP allow-list.** With `ARRMOR_ALLOWED_CLIENTS` only the Seerr host may talk to Arrmor at all (`403` otherwise) — a second layer behind the firewall.
- **Header hygiene.** Only a handful of request/response headers are passed through (no cookies, no `Location`, no `Server`).
- **Logging.** Every blocked request is logged with the reason — handy to see what Seerr tried to do. Query strings are never logged.
- **Tiny.** One Python file, standard library only, runs as `nobody`, works with a read-only root filesystem.

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
| `ARRMOR_PORT` | no | Listen port, default `8080` |
| `ARRMOR_HOST` | no | Listen address, default `0.0.0.0` |
| `ARRMOR_TIMEOUT` | no | Upstream timeout in seconds, default `60` |
| `ARRMOR_LOG_LEVEL` | no | `DEBUG`, `INFO` (default), `WARNING` |

Generate a proxy key with `openssl rand -hex 32`.

Multiple instances (e.g. a 4K Sonarr) are just another group: `ARRMOR_SONARR4K_URL`, … → prefix `/sonarr4k`.

## Usage

Image tags: `latest` = newest release, `0.2.0` / `0.2` = specific release, `edge` = current `main`.

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

See [docker-compose.example.yml](docker-compose.example.yml) for a setup where Arrmor runs in the same compose stack as Sonarr/Radarr.

### Seerr settings

In Seerr → Settings → Services → Sonarr / Radarr:

| Field | Value |
|---|---|
| Hostname or IP | LAN IP of the arr server, e.g. `192.168.1.10` |
| Port | `8080` |
| Use SSL | off |
| URL Base | `/sonarr` (or `/radarr`, `/sonarr4k`, …) |
| API Key | the matching `PROXY_KEY` |

Quality profile and root folder still load, so the dialog can be saved. Requests that Seerr tries to send to Sonarr/Radarr will fail — that is the point.

## Network recommendations

Run Arrmor on the server that hosts Sonarr/Radarr. It only helps if Seerr cannot reach Sonarr/Radarr directly:

- **Firewall between DMZ and LAN:** allow only `Seerr-IP → arr-server:8080`. Make sure `8989`/`7878` (and everything else) stay blocked from the DMZ.
- **Docker bypasses host firewalls** like ufw for published ports. Enforce the rule on the router/firewall between the networks or in the `DOCKER-USER` iptables chain, and bind the port to the LAN IP (`-p 192.168.1.10:8080:8080`).
- **Set `ARRMOR_ALLOWED_CLIENTS`** to the Seerr IP. Docker preserves the client source IP for published ports; if Seerr's traffic is NATed on the way, use the NAT address instead.
- Ideally Sonarr/Radarr don't publish ports at all and are only reachable through the internal Docker network.
- Traffic between Seerr and Arrmor is plain HTTP. The proxy key only grants read access, but other DMZ hosts on the same segment could sniff it.
- Rotate the Sonarr/Radarr API keys once after setting up Arrmor, if Seerr knew them before.

## Development

```sh
python3 -m unittest discover -s tests -v
```

## License

GPL-2.0, see [LICENSE](LICENSE).
