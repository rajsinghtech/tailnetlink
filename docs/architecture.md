# Architecture

One process is one **border** (source tailnet to one or more destinations) or one **mesh**. A mesh joins each tailnet once. The same node dials for bridges that leave and hosts VIPs for bridges that arrive. Links that leave one tailnet share a single poll. Each direction has its own reconcile queue.

1. OAuth client credentials or workload identity federation mints (or reuses) auth keys for a tsnet node on each side.
2. Discovery (tag, devices, services, or local `host:port`) finds backends on the source. Links on one tailnet share a single device list and a single service list each interval.
3. For each backend, the destination gets a VIP service owned by this border (`tailnetlink/owner=<name>`). Workers reconcile the set of names that should exist and retry failures. A failed poll does not remove anything. A name is dropped only after it has been missing for 3 polls or 2 minutes, at most 50 per poll, and a name is not added and removed at the same time.
4. The destination node hosts the VIP. Listens on one node are serialized and checked against its advertised set, so concurrent registrations are not lost. The forwarder reads PROXY v1, optionally WhoIs/authz, then dials through the source node.
5. Optional split-DNS publishes bridged names into the destination (TCP on the DNS VIP; UDP to VIP addresses is not delivered by tsnet today). The zone is the parent of the name unless a source sets `dns_zone`.

VIP services this process creates carry `tailnetlink/owner` and, for a bridge, `tailnetlink/bridge=<from>/<to>/<link>`. Create, update and delete apply only to those services. Split-DNS updates add or remove this process's resolver addresses and leave every other zone alone. Devices, routes and policy are not changed. Removing a bridge or a tailnet from the running config deletes what that bridge owned and nothing else. A name that already belongs to someone else, including the same short name a link would publish, is a conflict and is left in place.

`config.AcceptedRouteAddrs` is the union of parseable local IPs on bridges that leave a tailnet. It is recomputed after every config reload without restarting the node. The default route hook does not program the node. A later change can replace `acceptNodeRoutes` so the node accepts only advertised routes that cover those addresses. `LocalSourceSpec` is unchanged so that change can add ports beside `addr`.

Shutdown does not delete VIP services. Use `tailnetlink prune` when you intend to remove them, or remove the bridge from the config while tailnetlink is running.
