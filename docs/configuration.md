# Configuration

The process reads one JSON file. The default path is `tailnetlink.json`. It checks the file every 3 seconds and applies an edit when the modification time moves. It leaves the file as it is. An edit restarts the exports whose fields changed. A tailnet node restarts only when that tailnet's login or node settings change. A node stops when no target and no export names it.

The file has three parts: `tailnets`, `targets`, and `exports`. `name` is required. It is 1 to 40 characters: lowercase letters, digits, or dashes, and it starts and ends with a letter or digit. The process writes it to `tailnetlink/owner` on every VIP service it creates.

A file that sets `source`, `dest`, `dests`, `bridges`, `links`, `instance_id`, `via`, `expose_port`, or `oauth` is rejected. There is no converter. Any other unknown field is rejected. The error points at this format.

## Tailnets

`tailnets` maps a key to one node and one API login. The key `pod` is reserved. Two keys use different tailnet names.

| Field | Required | Meaning |
|---|---|---|
| `tailnet` | yes | Tailnet name, such as `example.ts.net`, or `-` for the credential's own tailnet |
| `auth.client_id` | yes | OAuth client id or federated client id |
| `auth.client_secret_file` | one of four | File that holds the OAuth client secret |
| `auth.client_secret_env` | one of four | Environment variable that holds the OAuth client secret |
| `auth.id_token_file` | one of four | File that holds an OIDC JWT. It is read again on every exchange |
| `auth.id_token_env` | one of four | Environment variable that holds that JWT |
| `tags` | no | ACL tags for this node and the VIP services it hosts. Default `["tag:tailnetlink"]` |
| `control_url` | no | Control server URL. Empty uses the hosted control plane |
| `api_base_url` | no | API URL. Empty uses the hosted API. Token exchange uses this base too |
| `node.ephemeral` | no | This node gets a new identity on every start |
| `node.hostname` | no | Node hostname. Default `tailnetlink-<key>` |
| `dns` | no | `true` or `false`. `false` turns split DNS off for names published into this tailnet. Default `true` |
| `authz` | no | Overrides export authz for VIP services published into this tailnet |

`ephemeral` at the top of the file applies to every tailnet. A tailnet can also set `node.ephemeral` to true. A top-level true stays on for every tailnet.

`dns` false at the top of the file turns split DNS off in every tailnet. A tailnet's own `dns` false turns it off for names published into that tailnet. A top-level false stays off when a tailnet sets `dns` true.

A tailnet that no target and no export names is not joined.

## Targets

| Field | Meaning |
|---|---|
| `in` | A tailnet key, or `pod` |
| `tag` | Discover devices and VIP services with this ACL tag |
| `device` | One device FQDN |
| `service` | One VIP service name, such as `svc:billing` |
| `addr` | One IP address |
| `host` | One DNS name, with no port |
| `ports` | TCP ports. A list dials the same port. A map sends the VIP port to the backend port |

A target sets exactly one of `tag`, `device`, `service`, `addr`, or `host`. A `pod` target sets `addr` or `host`. `ports` is required. An empty list, a repeated VIP port, or a port outside 1–65535 is rejected when the file loads.

`in` set to `pod` dials the host network. Name lookup uses the process resolver. `in` set to a tailnet key dials through that tsnet node. A hostname resolves with that tailnet's MagicDNS and split DNS, including a nameserver that is reachable only over a subnet route. The node installs the single most specific advertised prefix that covers each address, and the prefix that covers a split-DNS nameserver used to resolve a name. `RouteAll` stays off.

A missing prefix fails the dial before a packet is sent (`tailnetlink_routed_dial_failures_total`, `reason="no_route"`). A grant that drops the packets, and a dial that times out, use `reason="denied"`. Any other failure uses `reason="error"`.

The tailnet policy grants the node tag access to the address:

```text
{"src": ["tag:tailnetlink"], "dst": ["10.20.0.10"], "ip": ["5432"]}
```

## Exports

Each export has `target` and `to`. `to` lists tailnet keys, omits the target's `in`, and lists each key once. `name` defaults to the target key. It is one DNS label: 1 to 63 lowercase letters, digits, or dashes.

An export name is unique among exports into one destination. The file load rejects a second use of that name in that tailnet.

| Target kind | VIP names |
|---|---|
| `tag` | One VIP per device, `svc:<name>-<host>`. `<host>` is the device hostname, or the service label without `svc:`. A label longer than 63 characters is cut and given a short hash |
| `device`, `service`, `addr`, `host` | One VIP, `svc:<name>` |

`dns_name` on a tag export is a template and contains `{host}`, replaced with that same host label. `dns_zone` is the name itself or a parent of the expanded name. Leave `dns_name` unset and each device's own FQDN is published when DNS is on.

`dns_name` on a single endpoint is the full name. An `addr` target requires it. A `host` target uses the hostname when `dns_name` is unset. `dns_zone` equal to `dns_name` registers split DNS for that name only.

```json
{
  "name": "home-work",
  "tailnets": {
    "home": {
      "tailnet": "keiretsu.ts.net",
      "auth": {"client_id": "home-client", "client_secret_file": "/run/secrets/home"}
    },
    "work": {
      "tailnet": "example.ts.net",
      "auth": {"client_id": "work-client", "client_secret_env": "TAILNETLINK_WORK_SECRET"},
      "authz": {"mode": "allow_logins", "allow_logins": ["alice@example.com"]}
    }
  },
  "targets": {
    "api": {"in": "home", "tag": "tag:api-server", "ports": [8080, 8443]},
    "pg": {"in": "home", "device": "pg-0.keiretsu.ts.net", "ports": [5432]}
  },
  "exports": [
    {"target": "api", "to": ["work"], "dns_name": "{host}.api.example.com"},
    {"target": "pg", "to": ["work"], "name": "pg-0", "dns_name": "pg-0.example.com"}
  ]
}
```

## Readiness

`/readyz` is 200 when at least one export is fully up. An export is fully up when the tailnet named by `in` is connected (a `pod` target has no such node), at least one tailnet in `to` is connected, and a tag, device, or service target has polled within three poll intervals. A `pod` target is ready once a destination is up. A destination whose start has already failed stays out of that check. A destination that is still starting does not block a different export that is already up, and it does not block the same export when another destination in `to` is up. With no export fully up, the body is `no bridge is up`, or the first concrete reason.

## Authorization

`authz.mode` defaults to `off`. Every peer that can reach the VIP may use it.

| Mode | Rule |
|---|---|
| `off` | Allow the peer |
| `require_cap` | The peer needs capability `github.com/rajsinghtech/tailnetlink` whose JSON `links` list contains this export name or `"*"` |
| `allow_logins` | The peer login is in `allow_logins` |
| `allow_tags` | The peer carries one tag from `allow_tags` |

Set `authz` on the file to make it the default. An export may set its own. `authz` on the destination tailnet overrides the export for VIP services in that tailnet.

WhoIs runs after the PROXY header and before the dial. A denied peer is closed. A WhoIs error closes the connection for every mode other than `off`.

```json
{
  "name": "home-work",
  "authz": {"mode": "require_cap"},
  "tailnets": {
    "home": {
      "tailnet": "keiretsu.ts.net",
      "auth": {"client_id": "home-client", "client_secret_file": "/run/secrets/home"}
    },
    "work": {
      "tailnet": "example.ts.net",
      "auth": {"client_id": "work-client", "client_secret_env": "TAILNETLINK_WORK_SECRET"}
    }
  },
  "targets": {
    "api": {"in": "home", "tag": "tag:api-server", "ports": [8080]},
    "status": {"in": "home", "tag": "tag:status", "ports": [80]}
  },
  "exports": [
    {"target": "api", "to": ["work"], "authz": {"mode": "require_cap"}},
    {"target": "status", "to": ["work"], "authz": {"mode": "off"}}
  ]
}
```

A destination policy grant for `require_cap` lists the export name:

```text
{
  "src": ["tag:eng"],
  "dst": ["tag:tailnetlink"],
  "ip": ["*"],
  "app": {
    "github.com/rajsinghtech/tailnetlink": [{"links": ["api", "*"]}]
  }
}
```

## Login

The config holds a client id and the place to read a credential. It holds no secret and no JWT. An inline `client_secret` is rejected.

The process reads the secret or the JWT each time it needs a new API token. The JWT is read again on every exchange. The API token is cached until it expires, a few seconds early. One HTTP 401 drops that token and exchanges again.

Scopes: `devices:core:read`, `auth_keys`, `services`, `dns`. The `auth_keys` scope includes the tag from `tags`. Add that tag to the tailnet policy as a tag owner. For federation, the JWT `aud` is the audience shown for that credential.

## Optional fields

| Field | Default |
|---|---|
| `state_dir` | `tailnetlink-state` next to the config file |
| `ephemeral` | false |
| `dns` | true |
| `ui.enabled` | true |
| `ui.service_name` | `svc:tailnetlink` |
| `ui.listen_addr` | `127.0.0.1:8888` |
| `metrics_addr` | `127.0.0.1:9090`. The value `off` disables the listener |
| `poll_interval` | `30s` (minimum `100ms`) |
| `dial_timeout` | `10s` (minimum `100ms`) |
| `auth_key_expiry` | `1h` (minimum `1m`) |

## Split DNS

With DNS left on, a `dns_name` (or a device FQDN) is served by a small DNS server on a shared VIP, `svc:tnl-dns-<zone>-dns`, in the destination. Split DNS for that zone points at the VIP.

Leave `dns_zone` unset and the zone is the parent of the name. `app.corp.example.com` is the label `app` in `corp.example.com`.

Set `dns_zone` to `dns_name` or to a parent of it. When the two are equal, the record is the apex and split DNS is registered for that name only.

The server answers over TCP. The node receives TCP connections for a VIP address. UDP to that address is dropped. Clients retry over TCP.

A split-DNS update adds or removes this process's resolver address. Other resolvers on that zone stay in the list. Other zones stay as they are.
