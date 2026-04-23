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
2. Spins up an ephemeral [tsnet](https://pkg.go.dev/tailscale.com/tsnet) node in each tailnet.
3. Polls the Tailscale API for devices matching the configured tag or FQDN list.
4. Creates a Tailscale VIP service in the destination tailnet for each discovered device.
5. Registers the tsnet node as the VIP service host and proxies TCP connections back to the source device through the source tsnet node.
6. Optionally starts an authoritative DNS server and configures split-DNS so `{hostname}.{zone}` resolves to the VIP IP.

No static auth keys are stored — a fresh ephemeral key is generated at startup via the OAuth API.

## Quick start

```bash
cp config.example.json data.json
# edit data.json with your OAuth credentials
go run ./cmd/tailnetlink -data data.json
# web UI: http://localhost:8888
```

Or with make:

```bash
make dev           # runs with debug logging
make build && make run
```

## Configuration

Config is stored as JSON (default: `data.json`). The web UI at `:8888` lets you add tailnets and bridge rules without editing the file directly.

```json
{
  "tailnets": {
    "source": {
      "oauth": {
        "client_id": "...",
        "client_secret": "..."
      },
      "tailnet": "source-org.ts.net",
      "tags": ["tag:tailnetlink"]
    },
    "dest": {
      "oauth": {
        "client_id": "...",
        "client_secret": "..."
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
  "listen_addr": ":8888"
}
```

### Bridge rule fields

| Field | Description |
|---|---|
| `name` | Unique identifier for this rule |
| `source_tailnet` | Key of the tailnet where source devices live |
| `dest_tailnets` | List of tailnet keys where VIP services are created |
| `source_tag` | Discover devices with this ACL tag |
| `source_devices` | Explicit device specs (takes priority over `source_tag`) |
| `source_services` | Explicit VIP service names from the source tailnet |
| `ports` | TCP ports to forward |

`source_devices` entries and `source_services` entries both support optional DNS fields:

| Field | Description |
|---|---|
| `fqdn` / `name` | Device FQDN or VIP service name (`svc:foo`) |
| `dns_name` | Fully-qualified hostname to advertise in split-DNS (e.g. `api-0.api.internal`) |
| `short_name` | Bare VIP service name override (e.g. `api-0` → `svc:api-0`) |

### OAuth setup (once per tailnet)

1. Go to `admin.tailscale.com/settings/oauth`
2. Create a client with scopes: `devices:read`, `keys:write`, `vip-services:write`
3. Add the tag you specify in `tags` to your tailnet ACL as an owner tag

## CLI flags

| Flag | Default | Description |
|---|---|---|
| `-data` | `tailnetlink.json` | Path to config/state JSON file |
| `-listen` | `:8888` | Web UI listen address |
| `-log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |

## Docker

```bash
make docker-build
make docker-run       # mounts data.json from current directory
```

Or manually:

```bash
docker run --rm \
  -p 8080:8080 \
  -v $(pwd)/data.json:/data.json \
  tailnetlink:latest
```

## Web UI

Available at `http://localhost:8888` (or the configured `-listen` address). The UI also registers itself as `svc:tailnetlink` on TCP:80 in each connected tailnet, so you can reach it via the Tailscale VIP from within either network.

The UI provides:

- **Networks** — tailnet connection status, topology visualization, activity log
- **Services** — live bridge table with VIP addresses, port mapping, connection counts, traffic bytes
- **Connections** — active and recently-closed TCP sessions with source identity (node name / user / tag)
- **Config** — read-only view of the current JSON config

## Architecture

```
cmd/tailnetlink/        entry point — flag parsing, signal handling
internal/config/        config store (JSON, hot-reload on change)
internal/state/         in-memory state store + SSE pub/sub
internal/bridge/
  bridge.go             Manager — reconcile loop, tailnet lifecycle
  discoverer.go         polls Tailscale API for matching devices
  reconciler.go         creates/deletes VIP services in dest tailnet
  forwarder.go          TCP proxy: VIP listener → source device
  dns.go                authoritative DNS server (split-DNS)
  splitdns.go           configures split-DNS on dest tailnet
  naming.go             deterministic VIP service name generation
internal/server/        HTTP API + SSE + embedded web UI
```

## Development

```bash
make deps      # go mod tidy + download
make lint      # go vet
make dev       # run with debug logging (hot-reloads config on UI changes)
```
