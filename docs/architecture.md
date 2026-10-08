# Architecture

One process is one **border**: source tailnet → destination tailnet.

1. OAuth client credentials or workload identity federation mints (or reuses) auth keys for a tsnet node on each side.
2. Discovery (tag, devices, services, or local addresses) finds backends. A local entry is one VIP: `host:port`, or a host plus `ports`. `via` defaults to the host network. `via: tailnet` dials through the source node's userspace netstack, resolving names with that tailnet's MagicDNS and split DNS, and installing only the advertised subnet prefixes that cover the configured addresses. Nothing is written to other devices, to policy, or to tailnet DNS. Links on one tailnet share a single device list and a single service list each interval.
3. For each backend, the destination gets a VIP service owned by this border (`tailnetlink/owner=<name>`). Workers reconcile the set of names that should exist and retry failures. A failed poll does not remove anything. A name is dropped only after it has been missing for 3 polls or 2 minutes, at most 50 per poll, and a name is not added and removed at the same time.
4. The destination node hosts the VIP and listens on every advertised port. Listens on one node are serialized and checked against its advertised set, so concurrent registrations are not lost. The forwarder reads PROXY v1, optionally WhoIs/authz, then dials the backend for that port. Tag, device, and service links dial the discovered tailscale IP through the source node. A local entry dials the host network unless `via` is `tailnet`, in which case the dial and the name lookup both go through the source node.
5. Optional split-DNS publishes bridged names into the destination (TCP on the DNS VIP; UDP to VIP addresses is not delivered by tsnet today). The zone is the parent of the name unless a source sets `dns_zone`.

Shutdown does not delete VIP services. Use `tailnetlink prune` when you intend to remove them.
