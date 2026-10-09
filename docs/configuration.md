# Configuration

The process reads one JSON file. The default path is `tailnetlink.json`. It checks the file every 3 seconds and applies an edit when the modification time moves. It leaves the file as it is.

A file is a mesh or a border.

- A mesh sets `tailnets` and `bridges`.
- A border sets `source` and `dest`, or `source` and `dests`.

`name` is required. It is 1 to 40 characters: lowercase letters, digits, or dashes, and it starts and ends with a letter or digit. The process writes it to `tailnetlink/owner` on every VIP service it creates.

A file that sets `instance_id`, or `bridges` without `tailnets`, is the old format. The process rejects it. There is no converter.

## Mesh

`tailnets` maps a key to one tailnet. The key is the node name. Two keys use different tailnet names. `node.state_dir` on a single key is rejected. The process has one state directory.

| Field | Required | Meaning |
|---|---|---|
| `tailnet` | yes | Tailnet name, such as `example.ts.net`, or `-` for the credential's own tailnet |
| `oauth` | yes | Where to read the API credential. See [OAuth](#oauth-and-workload-identity) |
| `tags` | yes | ACL tags for this node and the VIP services it hosts |
| `control_url` | no | Control server URL. Empty uses the hosted control plane |
| `api_base_url` | no | API URL. Empty uses the hosted API. Token exchange uses this base too |
| `node.ephemeral` | no | This node gets a new identity on every start |
| `dns.enabled` | no | `false` turns split DNS off for VIP services published into this tailnet |
| `authz` | no | Overrides link authz for VIP services published into this tailnet |

`bridges` is a list. Each entry has `from` (one key), `to` (one or more other keys), and `links` (one or more). `to` omits `from` and lists each key once. An empty `bridges` list is allowed. The nodes still join.

A link uses the same fields as a border link. The rule name is `<from>/<link>`.

`node.ephemeral` at the top of the file applies to every tailnet. A tailnet can also set its own `node.ephemeral` to true. A top-level true stays on for every tailnet.

`dns.enabled` false at the top of the file turns split DNS off in every tailnet. A tailnet's own `dns.enabled` false turns it off for names published into that tailnet.

## Border

`source` and `dest` are each a tailnet side: `tailnet`, `oauth`, and `tags`, plus optional `control_url` and `api_base_url`.

`dest` and `dests` are separate. Set one of them. `dests` is a list of one or more destinations. Each destination may set `authz` and `dns`. A repeated tailnet name in `dests` is rejected.

`links` may be empty or left out. The nodes still join. A later edit that adds a link is picked up from the file.

The source node key is `<name>-src`. One `dest` uses `<name>-dst`. Every `dests` entry, including a list of one, uses `<name>-dst-` plus four hex characters of a hash of the lowercased tailnet name. Adding or removing a destination leaves the other keys as they are.

One source publishes the same links into every destination. The source is polled once. Each destination reconciles on its own queue.

`/readyz` is 200 when the config is applied, the source node is up, at least one destination is up, and each non-local link has polled within three poll intervals. A destination whose start has already failed stays out of that check. A destination that is still starting keeps the process unready. When every destination has failed, the process is unready.

```json
{
  "name": "home-to-many",
  "source": {
    "tailnet": "keiretsu.ts.net",
    "oauth": {"client_id": "home-client", "client_secret_file": "/run/secrets/home"},
    "tags": ["tag:tailnetlink"]
  },
  "dests": [
    {
      "tailnet": "example.ts.net",
      "oauth": {"client_id": "work-client", "client_secret_file": "/run/secrets/work"},
      "tags": ["tag:tailnetlink"],
      "authz": {"mode": "allow_logins", "allow_logins": ["alice@example.com"]}
    },
    {
      "tailnet": "partner.example.com",
      "oauth": {"client_id": "partner-client", "client_secret_env": "TAILNETLINK_PARTNER_SECRET"},
      "tags": ["tag:tailnetlink"],
      "dns": {"enabled": false}
    }
  ],
  "links": [
    {"name": "api", "tag": "tag:api-server", "ports": [8080, 8443]}
  ]
}
```

## Mesh readiness

`/readyz` is 200 when at least one bridge is fully up. A bridge is fully up when its source node is connected, at least one destination is connected, and a non-local link has polled within three poll intervals. A local link that dials the host network is ready once a destination is up. A local link has a source node in that check when any entry sets `via` to `tailnet`. A destination that has already failed stays out of the check for a destination that is up. A tailnet that is still starting leaves a different bridge that is already up in the ready set. With no bridge fully up, the body says why. An empty `bridges` list reports that no bridge is up.

## Link fields

A link has a `name` and exactly one of `tag`, `devices`, `services`, or `local`.

| Field | Meaning |
|---|---|
| `name` | Unique on this bridge, or unique in the border file |
| `tag` | Discover devices and VIP services with this ACL tag |
| `devices` | Explicit devices: `fqdn`, optional `dns_name`, `dns_zone`, `short_name` |
| `services` | Explicit VIP services in the source: `name`, optional DNS fields |
| `local` | Addresses this process dials. See [Local targets](#local-targets) |
| `ports` | TCP ports to forward. Required for `tag`, `devices`, and `services` |
| `authz` | Who may dial this link. See [Authorization](#authorization) |

`short_name` is one DNS label: 1 to 63 lowercase letters, digits, or dashes, and it starts and ends with a letter or digit. Two entries that would publish the same short name into one destination are rejected when the file loads. A generated name that is too long is cut and given a short hash suffix.

Tag discovery also lists VIP services that carry the tag. It skips a service annotated `tailnetlink/managed=true` and a device whose hostname starts with `tailnetlink-`. An explicit `devices` list matches the FQDN in the file.

```json
{
  "name": "home-to-work",
  "source": {
    "tailnet": "keiretsu.ts.net",
    "oauth": {"client_id": "home-client", "client_secret_file": "/run/secrets/home"},
    "tags": ["tag:tailnetlink"]
  },
  "dest": {
    "tailnet": "example.ts.net",
    "oauth": {"client_id": "work-client", "client_secret_env": "TAILNETLINK_WORK_SECRET"},
    "tags": ["tag:tailnetlink"]
  },
  "links": [
    {
      "name": "databases",
      "devices": [
        {"fqdn": "pg-0.keiretsu.ts.net", "short_name": "pg-0", "dns_name": "pg-0.example.com"}
      ],
      "ports": [5432]
    }
  ]
}
```

## Local targets

One local entry is one VIP service: one DNS name and one short name.

`addr` as `host:port` dials that socket. `expose_port` is the VIP port when it differs from the port in `addr`.

To put several ports on that service, give `addr` as a host with no port and set `ports`. A list exposes each number and dials the same number. An object maps the VIP port to the backend port. Leave `expose_port` unset, and leave the port out of `addr`.

An empty `ports` value, a repeated VIP port, a port outside 1–65535, or a port in `addr` together with `ports` is rejected when the file loads.

`dns_name` is required when the host is an IP or `localhost`. Otherwise the host in `addr` is the DNS name. `short_name` defaults to the first label of that name.

See the README for a two-port list and a port map in one file.

## Dial path

`via` is set on each local entry.

Leave `via` out, or set `"pod"`. The process dials the host network. Name lookup uses the process resolver, which is what an in-cluster name needs.

`"via": "tailnet"` dials through the tsnet node of the tailnet the bridge leaves. On a border that node is the source. On a mesh it is the `from` key. A hostname resolves as a client of that tailnet. MagicDNS names come from the node. Any other name is queried with that tailnet's split DNS, through the userspace network, including a nameserver that is reachable over a subnet route.

The process approves no routes on other devices. It writes no policy and no tailnet DNS settings. `RouteAll` stays off. The node installs, in its userspace WireGuard config, the single most specific advertised prefix that covers each configured address. It also installs the prefix that covers a split-DNS nameserver used to resolve a name. A Tailscale address needs no subnet prefix. Removing the entry, or stopping the node, removes the prefixes this process installed.

A missing prefix fails the dial before a packet is sent (`tailnetlink_routed_dial_failures_total`, `reason="no_route"`). A grant that drops the packets, and a dial that times out, use `reason="denied"`. Any other failure uses `reason="error"`.

The source policy grants the node tag access to the address. A grant looks like this:

```text
{"src": ["tag:tailnetlink"], "dst": ["10.20.0.10"], "ip": ["5432"]}
```

## Authorization

`authz.mode` defaults to `off`. Every peer that can reach the VIP may use it.

| Mode | Rule |
|---|---|
| `off` | Allow the peer |
| `require_cap` | The peer needs capability `github.com/rajsinghtech/tailnetlink` whose JSON `links` list contains this link name or `"*"` |
| `allow_logins` | The peer login is in `allow_logins` |
| `allow_tags` | The peer carries one tag from `allow_tags` |

Set `authz` on the file to make it the default. A link may set its own. On a border, a destination's `authz` overrides the link for VIP services in that destination. On a mesh, `authz` on the destination tailnet does the same.

WhoIs runs after the PROXY header and before the dial. A denied peer is closed. A WhoIs error closes the connection for every mode other than `off`.

```json
{
  "name": "home-to-work",
  "authz": {"mode": "require_cap"},
  "source": {
    "tailnet": "keiretsu.ts.net",
    "oauth": {"client_id": "home-client", "client_secret_file": "/run/secrets/home"},
    "tags": ["tag:tailnetlink"]
  },
  "dest": {
    "tailnet": "example.ts.net",
    "oauth": {"client_id": "work-client", "client_secret_env": "TAILNETLINK_WORK_SECRET"},
    "tags": ["tag:tailnetlink"]
  },
  "links": [
    {"name": "api", "tag": "tag:api-server", "ports": [8080], "authz": {"mode": "require_cap"}},
    {"name": "status", "tag": "tag:status", "ports": [80], "authz": {"mode": "off"}}
  ]
}
```

A destination policy grant for `require_cap`:

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

## OAuth and workload identity

The config holds a client id and the place to read a credential. It holds no secret and no JWT. An inline `client_secret` is rejected.

Set exactly one of:

| Field | Meaning |
|---|---|
| `client_secret_file` | File that holds the OAuth client secret. Surrounding whitespace is ignored |
| `client_secret_env` | Environment variable that holds the OAuth client secret |
| `id_token_file` | File that holds an OIDC JWT for workload identity federation |
| `id_token_env` | Environment variable that holds that JWT |

The process reads the secret or the JWT each time it needs a new API token. The JWT is read again on every exchange. A replaced file is picked up on the next exchange. The API token is cached until it expires, a few seconds early. One HTTP 401 drops that token and exchanges again.

Scopes: `devices:core:read`, `auth_keys`, `services`, `dns`. The `auth_keys` scope includes the tag from `tags`. Add that tag to the tailnet policy as a tag owner. For federation, the JWT `aud` is the audience shown for that credential.

## Optional blocks

| Block | Default |
|---|---|
| `node.state_dir` | `tailnetlink-state` next to the config file |
| `node.ephemeral` | false |
| `dns.enabled` | true |
| `ui.enabled` | true |
| `ui.service_name` | `svc:tailnetlink` |
| `ui.listen_addr` | `127.0.0.1:8888` |
| `metrics.listen_addr` | `127.0.0.1:9090`. The value `off` disables the listener |
| `poll_interval` | `30s` (minimum `100ms`) |
| `dial_timeout` | `10s` (minimum `100ms`) |
| `auth_key_expiry` | `1h` (minimum `1m`) |

## Split DNS

With `dns.enabled` left on, a `dns_name` (or a device FQDN) is served by a small DNS server on a shared VIP, `svc:tnl-dns-<zone>-dns`, in the destination. Split DNS for that zone points at the VIP.

Leave `dns_zone` unset and the zone is the parent of the name. `app.corp.example.com` is the label `app` in `corp.example.com`.

Set `dns_zone` to `dns_name` or to a parent of it. When the two are equal, the record is the apex and split DNS is registered for that name only. `dns_zone` requires `dns_name`.

The server answers over TCP. The node receives TCP connections for a VIP address. UDP to that address is dropped. Clients retry over TCP.

A split-DNS update adds or removes this process's resolver address. Other resolvers on that zone stay in the list. Other zones stay as they are.
