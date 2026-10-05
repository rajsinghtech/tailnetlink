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

1. Authenticates to each tailnet with OAuth credentials (OAuth scopes: `devices:read`, `keys:write`, `vip-services:write`).
2. Spins up a [tsnet](https://pkg.go.dev/tailscale.com/tsnet) node in each tailnet.
3. Polls the Tailscale API for devices matching the configured tag or FQDN list.
4. Creates a Tailscale VIP service in the destination tailnet for each discovered device.
5. Registers the tsnet node as the VIP service host and proxies TCP connections back to the source device through the source tsnet node.
6. Optionally starts an authoritative DNS server and configures split-DNS so `{hostname}.{zone}` resolves to the VIP IP.

No static auth keys are stored. The first start mints an auth key through the OAuth API; after that each node reuses its saved state, so it keeps its identity and its VIP services across restarts.

## Quick start

```bash
cp config.example.json data.json
# edit data.json: OAuth client ids, and where to read each client secret
go run ./cmd/tailnetlink -data data.json
# web UI: http://localhost:8888
```

Or with make:

```bash
make dev           # runs with debug logging
make build && make run
```

## Configuration

Config is a JSON file (default: `data.json`). The file is the only way to change it: tailnetlink checks it every few seconds and applies changes without a restart. It never writes the file.

```json
{
  "instance_id": "home-to-work",
  "tailnets": {
    "source": {
      "oauth": {
        "client_id": "...",
        "client_secret_file": "/run/secrets/source-oauth-secret"
      },
      "tailnet": "source-org.ts.net",
      "tags": ["tag:tailnetlink"]
    },
    "dest": {
      "oauth": {
        "client_id": "...",
        "client_secret_env": "TAILNETLINK_DEST_OAUTH_SECRET"
      },
      "tailnet": "dest-org.ts.net",
      "tags": ["tag:tailnetlink"]
    }
  },
  "bridges": [
    {
      "name": "api-servers",
      "source_tailnet": "source",
      "dest_tailnets": ["dest"],
      "source_tag": "tag:api-server",
      "ports": [8080, 8443]
    }
  ],
  "poll_interval": "30s",
  "dial_timeout": "10s",
  "listen_addr": "127.0.0.1:8888"
}
```

### Ownership

`instance_id` is required once any tailnet is configured. It names this tailnetlink instance: 1 to 63 lowercase letters, digits or dashes. Every VIP service tailnetlink creates carries the annotations `tailnetlink/managed=true` and `tailnetlink/owner=<instance_id>`, and tailnetlink only ever changes or deletes a service that carries its own owner annotation. That covers bridged services, the shared DNS VIP, the web UI VIP and local sources.

If a service with the name tailnetlink wants already exists and isn't ours, tailnetlink leaves it alone, logs an error and marks that bridge `error: name conflict`. The same goes for a `svc:tailnetlink` someone else made: the UI just isn't published in that tailnet. Two instances that share a tailnet need different `instance_id`s, and one of them should set `"ui": {"service_name": "svc:..."}` so their UI services don't collide.

Services made by older versions of tailnetlink only carry `tailnetlink/managed=true`. They are treated as foreign and never adopted. If you ran an older version, delete those services by hand in the admin console.

### Restarts and node state

Stopping tailnetlink (SIGTERM, a restart, a deploy) does not delete anything in your tailnets. VIP services, the DNS VIP and split-DNS stay in place, so clients keep their addresses and DNS keeps resolving while tailnetlink is down for a moment. tailnetlink only deletes a service when the rule or tailnet that made it is removed from the config while it is running.

Each node keeps its state in `state_dir/<tailnet name>` (mode 0700). `state_dir` defaults to a `tailnetlink-state` directory next to the config file. Keep that directory on persistent storage; if it is lost, the next start registers new nodes, and the old devices stay in the admin console until you remove them. If saved state stops working (for example the device was deleted), tailnetlink logs a warning, wipes it and registers a fresh node.

Set `"ephemeral": true` on a tailnet to get the old behavior for that node: no saved state, a new ephemeral device every start, removed by the control plane once it goes offline.

To remove everything an instance created, stop it and run:

```bash
tailnetlink prune -data data.json -dry-run   # show what would go
tailnetlink prune -data data.json
```

`prune` deletes every VIP service owned by this `instance_id` in every configured tailnet and takes their addresses out of split-DNS. Services owned by anything else are left alone. It does not remove the tailnetlink devices themselves.

### Bridge rule fields

| Field | Description |
|---|---|
| `name` | Unique identifier for this rule |
| `source_tailnet` | Key of the tailnet where source devices live |
| `dest_tailnets` | List of tailnet keys where VIP services are created |
| `source_tag` | Discover devices with this ACL tag |
| `source_devices` | Explicit device specs (takes priority over `source_tag`) |
| `source_services` | Explicit VIP service names from the source tailnet |
| `local_sources` | Addresses reachable from the tailnetlink host (`addr`, optional `expose_port`, `dns_name`, `short_name`) |
| `ports` | TCP ports to forward |

`source_devices` entries and `source_services` entries both support optional DNS fields:

| Field | Description |
|---|---|
| `fqdn` / `name` | Device FQDN or VIP service name (`svc:foo`) |
| `dns_name` | Fully-qualified hostname to advertise in split-DNS (e.g. `api-0.api.internal`) |
| `short_name` | Bare VIP service name override (e.g. `api-0` → `svc:api-0`) |

`short_name` must be a DNS label: 1 to 63 lowercase letters, digits or dashes, not starting or ending with a dash. Two entries that would end up with the same short name in the same destination tailnet are rejected when the config loads. Names tailnetlink generates itself are cut to fit and get a short hash suffix, so long hostnames never collide or overflow.

When a rule discovers by `source_tag`, tailnetlink skips anything it made itself: VIP services annotated `tailnetlink/managed=true` and devices whose hostname starts with `tailnetlink-`. Two instances bridging the same tag in opposite directions therefore don't bounce services back and forth.

`local_sources` entries publish something reachable from the machine running tailnetlink (`addr`, e.g. `127.0.0.1:3000` or `nas.lan:445`). The DNS name defaults to the host in `addr` (a localhost or IP `addr` needs `dns_name`), the short name to the first label of the DNS name, lower-cased, and the port to the one in `addr` unless `expose_port` is set.

### Split DNS

When an entry sets `dns_name` (say `api-0.api.internal`), tailnetlink runs a small authoritative DNS server for the parent zone (`api.internal`) on a shared VIP, `svc:tnl-dns-<zone>-dns`, in each destination tailnet and points split DNS for that zone at it. The server answers over TCP only: a tsnet node does not receive UDP sent to a VIP service address. Tailscale clients send split-DNS queries through their local resolver, which retries over TCP when UDP gets no answer, so names still resolve, just with a short delay on the first lookup.

### OAuth client secrets

Client secrets never go in the config file. Each tailnet's `oauth` block names where to read its secret from, with exactly one of:

| Field | Description |
|---|---|
| `client_secret_file` | Path to a file holding the secret (surrounding whitespace is ignored). Works with Docker and Kubernetes secrets. |
| `client_secret_env` | Name of an environment variable holding the secret. |

The secret is read each time tailnetlink needs a new API token, so rotating the file takes effect without a restart. A config with an inline `client_secret` does not load: tailnetlink exits with an error naming the field and the tailnet, before it contacts anything. To move an old config over, write each secret to a file (`chmod 600`) and replace `"client_secret": "..."` with `"client_secret_file": "/path/to/file"`.

### OAuth setup (once per tailnet)

1. Go to `admin.tailscale.com/settings/oauth`
2. Create a client with scopes: `devices:read`, `keys:write`, `vip-services:write`
3. Add the tag you specify in `tags` to your tailnet ACL as an owner tag

## CLI flags

| Flag | Default | Description |
|---|---|---|
| `-data` | `tailnetlink.json` | Path to config/state JSON file |
| `-listen` | `127.0.0.1:8888` | Web UI listen address |
| `-ui` | `true` | `-ui=false` turns the web UI off: no local listener and no `svc:tailnetlink`, whatever the config says |
| `-log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `-shutdown-timeout` | `20s` | How long to wait for a clean shutdown on SIGTERM or SIGINT. A second signal exits at once. |

`tailnetlink prune [-data file] [-dry-run]` deletes this instance's services; see above.

## Docker

```bash
make docker-build
make docker-run       # mounts data.json from current directory and a volume for node state
```

Or manually:

```bash
docker run --rm \
  -p 8080:8080 \
  -v $(pwd)/data.json:/data.json \
  -v $(pwd)/secrets:/run/secrets:ro \
  -v tailnetlink-state:/tailnetlink-state \
  tailnetlink:latest
```

Node state lives in `/tailnetlink-state` (next to `/data.json`) unless `state_dir` says otherwise. Without a volume there, every container start registers new devices.

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
  reconciler.go         creates/deletes VIP services in dest tailnet
  forwarder.go          TCP proxy: VIP listener → source device
  dns.go                authoritative DNS server (split-DNS)
  splitdns.go           configures split-DNS on dest tailnet
  naming.go             deterministic VIP service name generation
internal/server/        read-only HTTP API + SSE + embedded web UI
```

## Development

```bash
make deps      # go mod tidy + download
make lint      # go vet
make dev       # run with debug logging (reloads the config file when it changes)
```

## License

BSD 3-Clause. See [LICENSE](LICENSE).
