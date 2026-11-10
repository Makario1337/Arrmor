# Arrmor

Allow-list proxy between Seerr and Sonarr/Radarr. Seerr gets only the API calls it needs, no deletes, no config access — and never sees the real API keys. Built for DMZ setups where the request frontend is exposed to the internet.

```
Internet ──► Seerr ──(proxy key)──► Arrmor ──(real key)──► Sonarr / Radarr
                                      │
                                      └─ GET/HEAD on allow-listed endpoints only
```

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
| `ARRMOR_PORT` | no | Listen port, default `8080` |
| `ARRMOR_HOST` | no | Listen address, default `0.0.0.0` |
| `ARRMOR_TIMEOUT` | no | Upstream timeout in seconds, default `60` |
| `ARRMOR_LOG_LEVEL` | no | `DEBUG`, `INFO` (default), `WARNING` |

Generate a proxy key with `openssl rand -hex 32`.

Multiple instances (e.g. a 4K Sonarr) are just another group: `ARRMOR_SONARR4K_URL`, … → prefix `/sonarr4k`.

## Usage

```sh
docker run -d --name arrmor --read-only \
  -e ARRMOR_SONARR_URL=http://sonarr:8989 \
  -e ARRMOR_SONARR_API_KEY=<real sonarr key> \
  -e ARRMOR_SONARR_PROXY_KEY=<openssl rand -hex 32> \
  -e ARRMOR_RADARR_URL=http://radarr:7878 \
  -e ARRMOR_RADARR_API_KEY=<real radarr key> \
  -e ARRMOR_RADARR_PROXY_KEY=<openssl rand -hex 32> \
  ghcr.io/makario1337/arrmor:latest
```

See [docker-compose.example.yml](docker-compose.example.yml) for a setup with separate networks.

### Seerr settings

In Seerr → Settings → Services → Sonarr / Radarr:

| Field | Value |
|---|---|
| Hostname or IP | `arrmor` |
| Port | `8080` |
| Use SSL | off |
| URL Base | `/sonarr` (or `/radarr`, `/sonarr4k`, …) |
| API Key | the matching `PROXY_KEY` |

Quality profile and root folder still load, so the dialog can be saved. Requests that Seerr tries to send to Sonarr/Radarr will fail — that is the point.

## Network recommendations

Arrmor only helps if Seerr cannot reach Sonarr/Radarr directly:

- Put Seerr and Arrmor in a shared network, and Arrmor and the *arr apps in another one. Seerr must not be in the *arr network.
- Do not publish Arrmor's port to the internet.
- Rotate the Sonarr/Radarr API keys once after setting up Arrmor, if Seerr knew them before.

## Development

```sh
python3 -m unittest discover -s tests -v
```

## License

GPL-2.0, see [LICENSE](LICENSE).
