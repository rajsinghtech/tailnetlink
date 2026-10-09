# Architecture

One process reads one file. The file is a mesh or a border.

A mesh joins each tailnet once. The same tsnet node dials for bridges that leave that tailnet and hosts VIP services for bridges that arrive. Links that leave one tailnet share one poll. Each destination of a link has its own reconcile queue.

A border joins one source and one destination, or one source and the list in `dests`. The source node dials. Each destination node hosts its own VIP services, split DNS, and authz.

## Path of one connection

1. OAuth client credentials or a workload-identity JWT mint an auth key, or the node reuses its saved state.
2. Discovery finds backends by tag, by device FQDN, by VIP service name, or from local addresses. A local entry is one VIP service. `via` defaults to the host network. `via` set to `tailnet` dials through the source node's userspace stack.
3. For each backend, the destination gets a VIP service owned by this process. Workers make the destination match that set and retry failures. A failed poll removes nothing. A name is removed after it has been missing for 3 polls or 2 minutes, at most 50 names per poll.
4. The destination node hosts the VIP and listens on each advertised port. Listens on one node are serialized and checked against the node's advertised set. The forwarder reads PROXY v1, runs WhoIs when authz asks for it, then dials the backend.
5. Optional split DNS publishes bridged names into the destination. The server is TCP on a shared DNS VIP. The zone is the parent of the name unless the source sets `dns_zone`.

A `via:tailnet` dial installs only the advertised subnet prefixes that cover the configured addresses, plus a prefix that covers a split-DNS nameserver used for a name. `RouteAll` stays off. The host routing table is unchanged. The node has no TUN device.

Shutdown leaves VIP services in place. `tailnetlink prune` removes the ones this process owns. Removing a bridge from the running config deletes what that bridge owned.

## Files

```
cmd/tailnetlink/          flags, signals, prune
internal/config/
  config.go               compiled config, Load, file watch
  border.go               source plus dest or dests
  mesh.go                 tailnets plus bridges
  localports.go           several ports on one local VIP
  validate.go             link and short-name checks
  dns.go                  SplitHost for dns_zone
  routes.go               local IPs on bridges that leave a tailnet
internal/bridge/
  bridge.go               node lifecycle, reconcile, readiness
  poller.go               one device list and one service list per tailnet
  discoverer.go           tag, device, and service selection
  queue.go                per-destination reconcile queue
  reconciler.go           create and delete VIP services
  forwarder.go            TCP proxy from a VIP to a backend
  local.go                local entries and via:tailnet dials
  scope.go                most specific advertised subnet prefix
  routes.go               dial through the source node
  listen.go               serialized VIP listens
  naming.go               VIP service names
  dns.go                  authoritative DNS server
  splitdns.go             split-DNS resolver addresses
  authz.go                WhoIs and link grants
  helpers.go              owner and bridge annotations
  prune.go                delete services this process owns
internal/state/           in-memory bridge table and event stream
internal/server/          read-only HTTP UI
internal/metrics/         Prometheus metrics and health
internal/tsapi/           API client, token exchange, rate limit
```

`internal/config/routes.go` lists local addresses written as `host:port` when the host is an IP, for bridges that leave a tailnet key. The dialer takes its prefixes from `internal/bridge/scope.go` when a `via:tailnet` target needs them.
