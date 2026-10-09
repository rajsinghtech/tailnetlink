# Architecture

One process reads one file. The file names tailnets, targets, and exports.

Each tailnet key that a target or an export names is one tsnet node. The same node dials for targets whose `in` is that key and hosts VIP services for exports whose `to` lists that key. Targets that share an `in` tailnet share one poll. Each destination of an export has its own reconcile queue.

A target with `in` set to `pod` dials the host network. The process does not join a tailnet for that dial.

## Path of one connection

1. OAuth client credentials or a workload-identity JWT mint an auth key, or the node reuses its saved state.
2. Discovery finds backends by tag, by device FQDN, or by VIP service name. An `addr` or `host` target is one address. `ports` is a list or a map from VIP port to backend port.
3. For each backend, each destination gets a VIP service owned by this process. A tag target creates one VIP per device, named `<export name>-<host>`. Any other target creates one VIP, named with the export name. Workers make the destination match that set and retry failures. A failed poll removes nothing. A name is removed after it has been missing for 3 polls or 2 minutes, at most 50 names per poll.
4. The destination node hosts the VIP and listens on each advertised port. Listens on one node are serialized and checked against the node's advertised set. The forwarder reads PROXY v1, runs WhoIs when authz asks for it, then dials the backend port for that VIP port.
5. Optional split DNS publishes the export's `dns_name` into the destination. A tag export's `dns_name` is a template with `{host}`. The server is TCP on a shared DNS VIP.

An `addr` or `host` target whose `in` is a tailnet installs only the advertised subnet prefixes that cover the configured addresses, plus a prefix that covers a split-DNS nameserver used for a name. `RouteAll` stays off. The host routing table is unchanged. The node has no TUN device.

Shutdown leaves VIP services in place. `tailnetlink prune` removes the ones this process owns. Removing an export from the running config deletes what that export owned.

## Files

```
cmd/tailnetlink/          flags, signals, prune
internal/config/
  config.go               compiled config, Load, file watch
  file.go                 tailnets, targets, and exports
  border.go               authz modes and the UI block
  localports.go           VIP port to backend port
  validate.go             link and short-name checks
  dns.go                  SplitHost for dns_zone
  routes.go               local IPs on targets that leave a tailnet
internal/bridge/
  bridge.go               node lifecycle, reconcile, readiness
  poller.go               one device list and one service list per tailnet
  discoverer.go           tag, device, and service selection
  queue.go                per-destination reconcile queue
  reconciler.go           create and delete VIP services
  forwarder.go            TCP proxy from a VIP to a backend
  local.go                addr and host targets
  scope.go                most specific advertised subnet prefix
  routes.go               dial through a tailnet node
  listen.go               serialized VIP listens
  naming.go               VIP service names, including tag labels
  dns.go                  authoritative DNS server
  splitdns.go             split-DNS resolver addresses
  authz.go                WhoIs and export grants
  helpers.go              owner and export annotations
  prune.go                delete services this process owns
internal/state/           in-memory export table and event stream
internal/server/          read-only HTTP UI
internal/metrics/         Prometheus metrics and health
internal/tsapi/           API client, token exchange, rate limit
```

`internal/config/routes.go` lists local addresses written as an IP for targets that leave a tailnet key. The dialer takes its prefixes from `internal/bridge/scope.go` when an `addr` or `host` target needs them.
