# Architecture

One process is one **border**: source tailnet → destination tailnet.

1. OAuth client credentials or workload identity federation mints (or reuses) auth keys for a tsnet node on each side.
2. Discovery (tag, devices, services, or local `host:port`) finds backends on the source.
3. For each backend, the destination gets a VIP service owned by this border (`tailnetlink/owner=<name>`).
4. The destination node hosts the VIP; the forwarder reads PROXY v1, optionally WhoIs/authz, then dials through the source node.
5. Optional split-DNS publishes bridged names into the destination (TCP on the DNS VIP; UDP to VIP addresses is not delivered by tsnet today).

Shutdown does not delete VIP services. Use `tailnetlink prune` when you intend to remove them.
