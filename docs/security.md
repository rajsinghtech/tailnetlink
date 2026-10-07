# Security model

- OAuth client secrets and workload-identity JWTs come from files or env vars (`client_secret_file`, `client_secret_env`, `id_token_file`, `id_token_env`), never from the config JSON and never from the UI. Exactly one of those four is set. The JWT is read again on each token exchange and is not cached.
- The container runs as uid 65532. Node state, including ephemeral nodes, stays under `state_dir` on a mounted volume. tsnet uses userspace networking, so a locked-down pod does not need `/dev/net/tun`, extra capabilities, or a writable root filesystem.
- The web UI is read-only: no write API, secrets omitted from the config view, published as `svc:tailnetlink` in connected tailnets (disable with `ui.enabled` / `-ui=false`).
- Metrics and health listen separately (default `127.0.0.1:9090`); deploy examples bind `:9090` so container probes work.
- Ownership annotations stop one border from updating or deleting another border's VIP services.
- Optional `authz` (`require_cap`, `allow_logins`, `allow_tags`) runs after PROXY/WhoIs and before dial; WhoIs errors fail closed when authz is on.
