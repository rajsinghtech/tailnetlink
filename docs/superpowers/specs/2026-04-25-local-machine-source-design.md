# Local Machine Source — Design Spec

**Date:** 2026-04-25  
**Status:** Approved

## Overview

Add a `local` source type to bridge rules. Instead of dialing through a source tsnet node, tailnetlink dials the host machine's network directly (via plain `net.DialContext`). This allows services running on `localhost` or elsewhere on the host's LAN/DNS to be exposed as VIP services in destination tailnets — with the same split-DNS registration that existing Tailscale-source bridges use.

## Config Shape

A new `local_sources` array on `BridgeRule` replaces the source tailnet entirely for local rules. No `source_tailnet`, `source_tag`, `source_devices`, or `source_services` fields are used when `local_sources` is present.

```go
type LocalSourceSpec struct {
    Addr       string `json:"addr"`                  // "host:port" to dial on host machine
    ExposePort int    `json:"expose_port,omitempty"` // VIP port; defaults to addr's port
    DNSName    string `json:"dns_name,omitempty"`    // FQDN to register in dest tailnet
    ShortName  string `json:"short_name,omitempty"`  // VIP svc:name override
}
```

`BridgeRule` gets:
```go
LocalSources []LocalSourceSpec `json:"local_sources,omitempty"`
```

A rule is a **local rule** if `len(rule.LocalSources) > 0`. Local rules must not set `source_tailnet`, `source_tag`, `source_devices`, or `source_services`.

### Example config

```json
{
  "name": "local-services",
  "local_sources": [
    {
      "addr": "localhost:11434",
      "expose_port": 80,
      "dns_name": "ollama.dest-org.ts.net"
    },
    {
      "addr": "localhost:8080",
      "dns_name": "myapp.dest-org.ts.net"
    },
    {
      "addr": "ai.localtailnet.ts.net:8080"
    },
    {
      "addr": "local.app.custom.domain:80"
    }
  ],
  "dest_tailnets": ["dest"]
}
```

Note: `ports` at the rule level is unused for local rules — each `local_source` is fully self-contained (backend port is in `addr`, VIP port is `expose_port`).

## DNS Derivation Rules

| `addr` hostname | `dns_name` required? | Auto-derivation |
|---|---|---|
| `localhost` | **Yes — validation error** | none |
| `127.0.0.1` (or any bare IP) | **Yes — validation error** | none |
| Real FQDN (e.g. `ai.localtailnet.ts.net`) | No | `dns_name` = addr hostname |
| Real FQDN (e.g. `local.app.custom.domain`) | No | `dns_name` = addr hostname |

When `dns_name` is auto-derived or explicitly set:
- Split-DNS is configured in the dest tailnet for the parent zone (same as existing device DNS logic)
- VIP service name = first label of `dns_name` unless overridden by `short_name`
- e.g. `ollama.dest-org.ts.net` → `svc:ollama`; `ai.localtailnet.ts.net` → `svc:ai`

## Architecture

### No Discoverer for Local Rules

Local sources are static — there is no polling loop. `runRule` detects a local rule and skips `Discoverer` creation entirely. Each `LocalSourceSpec` is treated as an immediately-available "device" and processed directly.

### Forwarder Changes (Approach A)

`Forwarder` gets a `localAddr string` field. When set, `handle()` dials via `net.DialContext` instead of `dialSrv.Dial`. The `dialSrv` field is nil for local forwarders.

```
// local rule traffic path:
dest tailnet client → VIP IP:expose_port
  → dest tsnet (ListenService)
  → LocalForwarder.handle(): net.DialContext("tcp", localAddr)
  → host machine's network
```

The `srcSrv` (source tsnet) is not started or referenced for local rules.

### VIP service naming

Uses existing `ServiceName()` / `Reconciler.Ensure()` — same as device bridges — with the derived short name and a synthetic `Device` struct. The `sourceTailnet` argument to `ServiceName()` is `"local"` (sentinel string). `dev.IP` is left as zero value since it's not used for dial targeting in local mode. `BridgeEntry.SourceIP` is set to the local `addr` string (e.g. `"localhost:11434"`) for display in the services table.

### Validation (server-side, `handleBridgeRules`)

For local rules:
- `source_tailnet` must be empty
- Each `LocalSourceSpec.Addr` must be parseable as `host:port`
- Addr port must be > 0
- If host is `localhost`, `127.0.0.1`, or an IP literal → `dns_name` must be set (400 error)
- `expose_port`, if set, must be > 0
- `dest_tailnets` must still reference valid configured tailnets
- Short name conflict check extended to cover local sources (`checkShortNameConflicts` in `server.go` must iterate `local_sources` in addition to `source_devices`/`source_services`)

For non-local rules:
- Existing validation unchanged

## UI Changes

### Bridge Rule Modal

Add a **source type toggle** at the top of the Add/Edit Bridge Rule modal:

```
[ Tailscale network ]  [ Local machine ]
```

**Tailscale network mode** (existing behavior): source network dropdown + source picker (tag/device/service tabs) + ports field.

**Local machine mode**:
- Source network dropdown hidden
- Source picker hidden
- Ports field hidden
- Replace with **local endpoints builder**: a dynamic list of endpoint rows. Each row:
  - `addr` input (monospace, placeholder `localhost:8080` or `hostname:port`)
  - `expose_port` input (optional, placeholder = addr's port, shown inline)
  - `dns_name` input (auto-populated from addr hostname for real FQDNs; required indicator + inline error for localhost/IP)
- "Add endpoint" button to append a new empty row
- Remove (×) button per row
- Live preview below each row: "→ svc:name in dest tailnet" derived from dns_name/short_name
- Inline validation: warn immediately when addr is localhost/IP and dns_name is empty

### Bridge Rule Cards (Networks view)

Local rules display a `local` badge (gray/neutral) where the source tailnet name normally appears. The device list shows endpoint addrs (`localhost:11434`, `ai.localtailnet.ts.net:8080`, etc.) instead of device FQDNs.

### Services Table

- **Source host** column: shows the local `addr` (e.g. `localhost:11434`)
- **Source IP** column: shows `local` label or left blank
- **Route** column: shows `local → dest-tailnet-name`

### API Changes

`POST/PUT /api/bridge-rules` validation extended as described above. The bridge rule serialisation/deserialisation is transparent since `LocalSources` is a new JSON field with `omitempty`.

## Error Handling

- Dial failure on a local source: logged as warn, connection dropped (same behavior as tsnet dial failure)
- If `dns_name` is required but missing: caught at config validation before the bridge starts, logged as error, rule does not start
- DNS setup failure for a local source: logged as warn, bridge still starts (VIP accessible by IP; DNS just won't resolve by name)

## Out of Scope

- UDP forwarding (not supported for any rule type today)
- Port remapping per-source beyond `expose_port` (single port per local_source)
- Health checking of local endpoints
- Dynamic discovery of local services
