# Operations

## Ownership

`name` is written to every VIP service this process creates as `tailnetlink/owner=<name>`. The service also gets `tailnetlink/managed=true`. A bridge writes `tailnetlink/bridge=<from>/<dest>/<link>`.

Create, update, and delete apply to a service when the owner matches. With a bridge id set, the existing bridge annotation is empty or equal to that id. The three parts of that id are the source node key, the destination node key, and the link name. A service that already names a different bridge is left in place, and the bridge reports a name conflict (`tailnetlink_ownership_conflicts_total`). A service that has only `tailnetlink/managed=true` is left in place.

`prune` deletes every service this process owns, whichever bridge published it. The UI VIP and the DNS VIP use the owner check.

Two processes that share a tailnet use different `name` values. One of them sets `ui.service_name` so the UI VIP names differ.

Removing a bridge or a destination from the file, while the process is running, deletes the VIP services that bridge or destination owns. Devices, routes, and policy stay as they are. Split DNS drops this process's resolver address and leaves every other resolver in place.

## Restarts and state

A stop (SIGTERM, a restart, a deploy) leaves VIP services, the DNS VIP, and split DNS in place. The process deletes a service when the link or the side that created it is removed from the config while the process is running.

Each node keeps state under `node.state_dir`, mode `0700`.

| Shape | Directory name |
|---|---|
| Mesh key `home` | `home` |
| Border source | `<name>-src` |
| Border single `dest` | `<name>-dst` |
| Each `dests` entry | `<name>-dst-` plus four hex characters of a hash of the tailnet name |

The default directory is `tailnetlink-state` next to the config file. Keep it on persistent storage. A lost directory means the next start registers new nodes. Two processes use different state directories.

A saved node that does not come up within one minute is removed and registered again.

`node.ephemeral` true gives that node a new directory under the same state directory on every start, and a new device identity. On a mesh, a top-level true applies to every tailnet. Ephemeral state stays on the state-directory volume, so a read-only root filesystem works when that directory is mounted.

To delete the services a stopped process owns:

```bash
tailnetlink prune -data tailnetlink.json -dry-run
tailnetlink prune -data tailnetlink.json
```

## CLI

| Flag | Default | Meaning |
|---|---|---|
| `-data` | `tailnetlink.json` | Config file |
| `-version` | | Print the build version and exit |
| `-listen` | `127.0.0.1:8888` | Web UI address. Overrides `ui.listen_addr` |
| `-metrics-listen` | `127.0.0.1:9090` | `/healthz`, `/readyz`, and `/metrics`. `off` disables them |
| `-ui` | `true` | `-ui=false` stops the local UI listener and the UI VIP for this process |
| `-log-level` | `info` | `debug`, `info`, `warn`, or `error` |
| `-shutdown-timeout` | `20s` | Time to wait after SIGTERM or SIGINT. A second signal exits at once |

`tailnetlink prune [-data file] [-dry-run]` deletes services owned by the `name` in that file.

## Docker

Version tags (`v*.*.*`) publish release images. A push to `main` publishes `:main` and `:sha-<short>`. Pin those by digest.

The image runs as UID `65532`. It reads `/data/tailnetlink.json`, keeps node state under `/data/tailnetlink-state`, and listens for metrics on `:9090`. It uses userspace networking.

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

`deploy/` has a compose example. `make docker-build` tags `tailnetlink:local`.

## Health and metrics

`/healthz`, `/readyz`, and `/metrics` use their own listener. The default is `127.0.0.1:9090` (`metrics.listen_addr` or `-metrics-listen`). They stay up when the UI is off. In a container, set the address to `:9090`.

- `/healthz` is 200 while the process is running.
- `/readyz` is 200 when the config is applied and a border or a mesh is up, using the rules in [configuration.md](configuration.md). Otherwise it is 503 and the body says why.
- `/metrics` is Prometheus text. Labels carry rule names, tailnet keys, and fixed values.

Each tailnet's API client has its own token bucket: 20 requests per second, burst 40. HTTP 429 and 5xx are retried. A POST on 5xx is sent once, because creating a key or exchanging a token may already have succeeded. `Retry-After` is honored, with a little jitter. A call stops after 4 attempts or 30 seconds of waiting.

| Metric | Labels | Meaning |
|---|---|---|
| `tailnetlink_node_up` | `tailnet` | 1 when this process's node in that tailnet is connected |
| `tailnetlink_bridges` | `status` | Bridges by status (`pending`, `active`, `error`) |
| `tailnetlink_vip_services` | `tailnet`, `state` | VIP services this process has started hosting (`desired`) and verified in the node's advertised set (`advertised`) |
| `tailnetlink_connections_active` | `rule` | Connections being forwarded |
| `tailnetlink_connections_total` | `rule` | Connections forwarded |
| `tailnetlink_bytes_total` | `rule`, `direction` | Bytes forwarded. `in` is client to backend. `out` is backend to client |
| `tailnetlink_dial_failures_total` | `rule` | Failed backend dials |
| `tailnetlink_routed_dial_failures_total` | `rule`, `reason` | Failed `via:tailnet` dials. `no_route`, `denied`, or `error` |
| `tailnetlink_api_errors_total` | `endpoint` | Failed API calls. A 404 is omitted |
| `tailnetlink_api_requests_total` | `endpoint`, `code` | Every API attempt. `code` is the HTTP status, or `error` when there was no response |
| `tailnetlink_api_request_duration_seconds` | `endpoint` | Duration of one API attempt |
| `tailnetlink_poll_duration_seconds` | `rule` | Discovery poll time |
| `tailnetlink_poll_errors_total` | `rule` | Failed discovery polls |
| `tailnetlink_ownership_conflicts_total` | `tailnet` | Wanted service names held by another owner |

Go runtime and process metrics are included.

## Web UI

The UI is read-only. It listens on `127.0.0.1:8888` unless `-listen` or `ui.listen_addr` says otherwise. It is also published as `svc:tailnetlink` on TCP port 80 in every connected tailnet. That service uses the same ownership check as every other service.

GET and HEAD are served. Every other method receives 405. The config view omits each tailnet's `oauth` block. Responses carry no CORS headers.

`"ui": {"enabled": false}` or `-ui=false` turns the UI off. `-ui=false` wins over the file for the life of the process: nothing listens locally and no UI VIP is created. Turning `ui.enabled` off in a running process deletes the UI services it owns. Turning it back on publishes them again. The local listener follows the setting the process started with.

The pages are Networks, Services, Connections, and Config.
