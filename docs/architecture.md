# Architecture

One process is one **border**: source tailnet → destination tailnet.

1. OAuth client credentials or workload identity federation mints (or reuses) auth keys for a tsnet node on each side.
2. Discovery (tag, devices, services, or local addresses) finds backends. A local entry is one VIP: `host:port`, or a host plus `ports` so several TCP ports share that name. Links on one tailnet share a single device list and a single service list each interval.
3. For each backend, the destination gets a VIP service owned by this border (`tailnetlink/owner=<name>`). Workers reconcile the set of names that should exist and retry failures. A failed poll does not remove anything. A name is dropped only after it has been missing for 3 polls or 2 minutes, at most 50 per poll, and a name is not added and removed at the same time.
4. The destination node hosts the VIP and listens on every advertised port. Listens on one node are serialized and checked against its advertised set, so concurrent registrations are not lost. The forwarder reads PROXY v1, optionally WhoIs/authz, then dials the backend for that port: through the source node, or directly for a local target.
5. Optional split-DNS publishes bridged names into the destination (TCP on the DNS VIP; UDP to VIP addresses is not delivered by tsnet today). The zone is the parent of the name unless a source sets `dns_zone`.

Shutdown does not delete VIP services. Use `tailnetlink prune` when you intend to remove them.
