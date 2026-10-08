# tailnetlink

Bridges services across Tailscale networks. Discovers devices by tag (or explicit list) in a source tailnet and exposes them as Tailscale VIP services on a destination tailnet — with optional split-DNS so clients resolve bridged hosts by name.

```
source tailnet                         dest tailnet
┌──────────────────────┐               ┌──────────────────────┐
│  tag:api-server      │               │  svc:tnl-…           │
│  ┌────────────────┐  │               │  ┌────────────────┐  │
│  │ api-0 :8080    │◄─┼───────────────┼──│ VIP 100.x.x.1  │  │
│  │ api-1 :8080    │◄─┼───────────────┼──│ VIP 100.x.x.2  │  │
│  └────────────────┘  │               │  └────────────────┘  │
└──────────────────────┘               └──────────────────────┘
```

## How it works

1. Authenticates to each tailnet with an OAuth client secret or a workload identity token (scopes: `devices:core:read`, `auth_keys`, `services`, `dns`).
2. Spins up a [tsnet](https://pkg.go.dev/tailscale.com/tsnet) node in each tailnet.
3. Polls the Tailscale API for devices matching the configured tag or FQDN list.
4. Creates a Tailscale VIP service in the destination tailnet for each discovered device. Discovery publishes the set of names that should exist. A fixed pool of workers makes the destination match that set, one service name at a time, and retries failures with exponential backoff. A device that comes back with the same name keeps its VIP.
5. Registers the tsnet node as the VIP service host and proxies TCP connections back to the source device through the source tsnet node. Listens on one node run one at a time, and a listen counts only after the service is in that node's advertised set, so concurrent registrations are not lost.
6. Optionally starts an authoritative DNS server and configures split-DNS so `{hostname}.{zone}` resolves to the VIP IP.

No static auth keys are stored. The first start mints an auth key through the OAuth API; after that each node reuses its saved state, so it keeps its identity and its VIP services across restarts.

## Quick start

```bash
cp config.example.json tailnetlink.json
# edit: client ids, and where to read each client secret or id token
go run ./cmd/tailnetlink -data tailnetlink.json
# web UI: http://127.0.0.1:8888   metrics: http://127.0.0.1:9090/healthz
```

Or with make: `make dev`, `make build && make run`. See [CONTRIBUTING.md](CONTRIBUTING.md) for tests and the coverage ratchet.

## Configuration

Config is a JSON file (default: `tailnetlink.json`). One file describes one **border**: one source tailnet bridged into one destination. Run one process per border. The file is the only way to change it: tailnetlink checks it every few seconds and applies changes without a restart. It never writes the file.

Older multi-tailnet configs (`tailnets` / `bridges` / `instance_id`) are no longer read. There is no converter. Rewrite them as a border; see below.

```json
{
  "name": "home-to-work",
  "source": {
    "tailnet": "source-org.ts.net",
    "oauth": {
      "client_id": "...",
      "client_secret_file": "/run/secrets/source-oauth-secret"
    },
    "tags": ["tag:tailnetlink"]
  },
  "dest": {
    "tailnet": "dest-org.ts.net",
    "oauth": {
      "client_id": "...",
      "client_secret_env": "TAILNETLINK_DEST_OAUTH_SECRET"
    },
    "tags": ["tag:tailnetlink"]
  },
  "links": [
    {
      "name": "api-servers",
      "tag": "tag:api-server",
      "ports": [8080, 8443]
    }
  ]
}
```

`links` can start empty (`[]` or left out). tailnetlink still logs both nodes in and reports ready once they are up. It creates no VIP services until a link is added. A later edit to the file is picked up without a restart.

### Ownership

`name` is required. It is the owner written to every VIP service this process creates (`tailnetlink/owner=<name>`), and part of its node hostnames (`tailnetlink-<name>-src`, `tailnetlink-<name>-dst`). 1 to 40 lowercase letters, digits or dashes. Two borders that share a tailnet need different names, and one of them should set `"ui": {"service_name": "svc:..."}` so their UI services don't collide.

tailnetlink only ever changes or deletes a service that carries its own owner annotation. That covers bridged services, the shared DNS VIP, the web UI VIP and local sources. Services made by older versions that only carry `tailnetlink/managed=true` are treated as foreign and never adopted.

### Restarts and node state

Stopping tailnetlink (SIGTERM, a restart, a deploy) does not delete anything in your tailnets. VIP services, the DNS VIP and split-DNS stay in place. tailnetlink only deletes a service when the link or side that made it is removed from the config while it is running.

Each node keeps its state in `node.state_dir/<name>-src` and `<name>-dst` (mode 0700). `state_dir` defaults to a `tailnetlink-state` directory next to the config file. Keep that directory on persistent storage; if it is lost, the next start registers new nodes. Borders must not share a `state_dir`. Set `"node": {"ephemeral": true}` to get a new ephemeral device every start.

To remove everything a border created, stop it and run:

```bash
tailnetlink prune -data data.json -dry-run
tailnetlink prune -data data.json
```

### Link fields

`links` can be empty or left out. The process still joins both tailnets, and a later edit that adds a link is picked up without a restart.

A link has a `name` and exactly one of `tag`, `devices`, `services` or `local`, plus `ports` (not for local).

| Field | Description |
|---|---|
| `name` | Unique name for this link |
| `tag` | Discover devices and VIP services with this ACL tag |
| `devices` | Explicit device specs (`fqdn`, optional `dns_name`, `short_name`) |
| `services` | Explicit VIP service names from the source (`name`, optional DNS fields) |
| `local` | Addresses reachable from the host (`addr`, optional `expose_port`, `dns_name`, `short_name`) |
| `ports` | TCP ports to forward (required except for `local`) |

`short_name` must be a DNS label: 1 to 63 lowercase letters, digits or dashes, not starting or ending with a dash. Two entries that would end up with the same short name are rejected when the config loads. Names tailnetlink generates itself are cut to fit and get a short hash suffix.

When a link discovers by `tag`, it skips anything it made itself: VIP services annotated `tailnetlink/managed=true` and devices whose hostname starts with `tailnetlink-`.

### Authorization

By default every peer that can reach a VIP may use it (`authz.mode` is `off`). Set a border-level default, or override it on a link:

```json
"authz": { "mode": "require_cap" },
"links": [
  {
    "name": "api",
    "tag": "tag:api-server",
    "ports": [8080],
    "authz": { "mode": "require_cap" }
  },
  {
    "name": "open",
    "tag": "tag:status",
    "ports": [80],
    "authz": { "mode": "off" }
  }
]
```

Modes:

- `off` — allow everyone (default)
- `require_cap` — the peer needs app capability `github.com/rajsinghtech/tailnetlink` whose JSON lists this link name or `"*"` in `links`
- `allow_logins` — peer login must be in `allow_logins`
- `allow_tags` — peer must carry one of `allow_tags`

WhoIs runs after the PROXY header and before dial. A deny closes the client; a WhoIs error fails closed for every mode except `off`.

Grant example (destination policy):

```json
{
  "src": ["tag:eng"],
  "dst": ["tag:tailnetlink"],
  "ip": ["*"],
  "app": {
    "github.com/rajsinghtech/tailnetlink": [{ "links": ["api", "*"] }]
  }
}
```

### Optional blocks

| Block | Defaults |
|---|---|
| `node.state_dir` / `node.ephemeral` | next to the config file / false |
| `dns.enabled` | true (shared DNS VIP and split-DNS in dest) |
| `ui.enabled` / `ui.service_name` / `ui.listen_addr` | true / `svc:tailnetlink` / `127.0.0.1:8888` |
| `metrics.listen_addr` | `127.0.0.1:9090` (`off` disables) |
| `poll_interval` / `dial_timeout` / `auth_key_expiry` | `30s` / `10s` / `1h` |

### Split DNS

With DNS on (the default), when an entry sets `dns_name` (or a device has a real FQDN), tailnetlink runs a small authoritative DNS server for the parent zone on a shared VIP, `svc:tnl-dns-<zone>-dns`, in the destination and points split DNS for that zone at it. The server answers over TCP only: a tsnet node does not receive UDP sent to a VIP service address. Clients fall back to TCP after the UDP attempt times out.

### OAuth and workload identity

Client secrets and OIDC tokens never go in the config file. Each side's `oauth` block has a `client_id` and exactly one of:

| Field | Description |
|---|---|
| `client_secret_file` | Path to a file holding the OAuth client secret (surrounding whitespace is ignored). |
| `client_secret_env` | Name of an environment variable holding the OAuth client secret. |
| `id_token_file` | Path to a file holding an OIDC JWT for workload identity federation. |
| `id_token_env` | Name of an environment variable holding that JWT. |

tailnetlink reads the secret or the JWT each time it needs a new API token. It does not cache the JWT, so a sidecar or projected token can replace the file and the next exchange picks it up without a restart. A config with an inline `client_secret` does not load. To move an old config over, write each secret to a file (`chmod 600`) and replace `"client_secret": "..."` with `"client_secret_file": "/path/to/file"`.

With `id_token_file` or `id_token_env`, tailnetlink posts `client_id` and the JWT to Tailscale's token-exchange endpoint and uses the returned API token the same way as an OAuth client credential: minting auth keys, listing devices, writing VIP services and writing split DNS. The API token is cached until it expires (a few seconds early) and then exchanged again from the current file. One HTTP 401 is retried with a fresh exchange. A custom `api_base_url` is used for the exchange as well as the rest of the API.

```json
"oauth": {
  "client_id": "YOUR_FEDERATED_CLIENT_ID",
  "id_token_file": "/var/run/tailscale/id-token"
}
```

The issuer can be anything you have federated with Tailscale. GitHub Actions is one: request an OIDC token whose `aud` is the audience shown for that federated identity, and rewrite the file before the JWT expires (GitHub's tokens last about five minutes).

### Trust credential setup (once per tailnet)

1. Open the Trust credentials page in the admin console.
2. Create an OAuth client, or an OpenID Connect federated identity.
3. Scopes: `devices:core:read`, `auth_keys`, `services`, `dns`.
4. `auth_keys` needs the tag from `tags` on the credential. Auth keys are limited to that tag, or to tags it owns. Add the same tag to the tailnet policy as a tag owner.
5. For federation, put the client ID in `client_id`. The JWT's `aud` must be the audience Tailscale shows for that credential.

## CLI flags

| Flag | Default | Description |
|---|---|---|
| `-data` | `tailnetlink.json` | Path to config JSON file |
| `-version` | | Print the build version and exit |
| `-listen` | `127.0.0.1:8888` | Web UI listen address |
| `-metrics-listen` | `127.0.0.1:9090` | Address for `/healthz`, `/readyz` and `/metrics` (overrides `metrics_addr`); `off` turns it off |
| `-ui` | `true` | `-ui=false` turns the web UI off: no local listener and no `svc:tailnetlink`, whatever the config says |
| `-log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `-shutdown-timeout` | `20s` | How long to wait for a clean shutdown on SIGTERM or SIGINT. A second signal exits at once. |

`tailnetlink prune [-data file] [-dry-run]` deletes this instance's services; see above.

## Docker

Version tags (`v*.*.*`) publish release images. Every push to `main` also publishes `:main` and `:sha-<short>`; pin those by digest. The image runs as UID 65532, expects `/data/tailnetlink.json`, keeps node state under `/data/tailnetlink-state`, and listens for metrics on `:9090` so probes work inside the container. It does not open `/dev/net/tun`. Ephemeral node state stays under the state directory too, so a read-only root filesystem works when that directory is a mounted volume.

```bash
docker pull ghcr.io/rajsinghtech/tailnetlink:vX.Y.Z
docker run -d --name tailnetlink \
  -p 8888:8888 -p 9090:9090 \
  -v "$PWD/tailnetlink.json:/data/tailnetlink.json:ro" \
  -v tailnetlink-state:/data/tailnetlink-state \
  -v "$PWD/secrets:/run/secrets:ro" \
  ghcr.io/rajsinghtech/tailnetlink:vX.Y.Z
curl -sf http://127.0.0.1:9090/healthz
```

See `deploy/` for a compose example. Build locally with `make docker-build` (tag `tailnetlink:local`).


## Health and metrics

`/healthz`, `/readyz` and `/metrics` are served on their own listener, `127.0.0.1:9090` by default (`metrics_addr` in the config or `-metrics-listen`; `off` disables it). They are never on the UI port or the UI service, and they stay up with the UI off. In a container set the address to `:9090` so probes can reach it.

- `/healthz` is 200 while the process is running.
- `/readyz` is 200 once the config has been applied, every configured tailnet's node is up, and every tailnet rule has polled successfully within the last three poll intervals. Otherwise it is 503 with the reason.
- `/metrics` is Prometheus text. Labels only carry rule names, tailnet keys and fixed values, never device names or client addresses.

Each tailnet's admin API client has its own token bucket: 20 requests per second, burst 40. HTTP 429 and 5xx are retried (POST is not retried on 5xx, because creating a key or exchanging a token may already have succeeded). A `Retry-After` header is honored, with a little jitter, and a call gives up after 4 attempts or 30 seconds of waiting.

| Metric | Labels | |
|---|---|---|
| `tailnetlink_bridges` | `status` | Bridges by status (pending, active, error) |
| `tailnetlink_vip_services` | `tailnet`, `state` | VIP services this process has started hosting (`desired`) and verified in the node's advertised set (`advertised`). A gap means a listen did not stick. |
| `tailnetlink_connections_active` | `rule` | Connections being forwarded right now |
| `tailnetlink_connections_total` | `rule` | Connections forwarded |
| `tailnetlink_bytes_total` | `rule`, `direction` | Bytes forwarded; `in` is client to backend |
| `tailnetlink_dial_failures_total` | `rule` | Failed backend dials |
| `tailnetlink_api_errors_total` | `endpoint` | Failed Tailscale API calls (devices, services, keys, dns, oauth, other); 404s are not counted |
| `tailnetlink_api_requests_total` | `endpoint`, `code` | Every API attempt. `code` is the HTTP status, or `error` when there was no response. 429 is its own value, so it can be alerted on. |
| `tailnetlink_api_request_duration_seconds` | `endpoint` | How long one API attempt took |
| `tailnetlink_poll_duration_seconds` | `rule` | Discovery poll time |
| `tailnetlink_poll_errors_total` | `rule` | Failed discovery polls |
| `tailnetlink_ownership_conflicts_total` | `tailnet` | Wanted service names taken by something this instance doesn't own |

Go runtime and process metrics are included too.

## Web UI

The UI is read-only. It is served at `http://localhost:8888` (or the configured `-listen` address), on loopback only by default, and published as `svc:tailnetlink` on TCP:80 in every connected tailnet so you can open it from either side. The UI service goes through the same ownership check as every other service.

It has no write routes at all: every method other than GET and HEAD gets 405, and there is no config, settings, CRUD or detect API. The config it shows leaves out every tailnet's `oauth` block, so no client ID or secret path is served, and the config never holds a secret in the first place. There are no CORS headers.

To turn it off, set `"ui": {"enabled": false}` in the config or run with `-ui=false`. Either way nothing listens locally and no UI service is created. Turning `ui.enabled` off in a running instance deletes the UI services it owns; turning it back on republishes them. The local listener follows the setting tailnetlink started with.

The UI provides:

- **Networks** — tailnet connection status, topology visualization, activity log
- **Services** — live bridge table with VIP addresses, port mapping, connection counts, traffic bytes
- **Connections** — active and recently-closed TCP sessions with source identity (node name / user / tag)
- **Config** — the running config, without the oauth blocks

## Architecture

```
cmd/tailnetlink/        entry point — flag parsing, signal handling
internal/config/        config loading, validation, file watch
internal/state/         in-memory state store + SSE pub/sub
internal/bridge/
  bridge.go             Manager — reconcile loop, tailnet lifecycle
  discoverer.go         polls Tailscale API for matching devices
  queue.go              desired-state reconcile queue and worker pool
  reconciler.go         creates/deletes VIP services in dest tailnet
  forwarder.go          TCP proxy: VIP listener → source device
  dns.go                authoritative DNS server (split-DNS)
  splitdns.go           configures split-DNS on dest tailnet
  naming.go             deterministic VIP service name generation
  listen.go             serialized VIP listens, checked against AdvertiseServices
internal/server/        read-only HTTP API + SSE + embedded web UI
```

## Development

```bash
make deps      # go mod tidy + download
make lint      # go vet
make dev       # run with debug logging (reloads the config file when it changes)
```

## Further reading

- [docs/architecture.md](docs/architecture.md) — one border, VIP forward path, DNS
- [docs/security.md](docs/security.md) — secrets, UI, ownership, authz
- [docs/testing.md](docs/testing.md) — unit / testcontrol / real-tailnet layers
- [CONTRIBUTING.md](CONTRIBUTING.md) — local gates, PRs, coverage ratchet
- [deploy/](deploy/) — compose example (metrics on `:9090`)

Branch protection on `main` (required CI checks) is an owner setting, not a file in this repo.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
