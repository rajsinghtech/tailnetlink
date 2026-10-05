# Security model

- OAuth client secrets come from files or env vars, never from the config JSON and never from the UI.
- The web UI is read-only: no write API, secrets omitted from the config view, published as `svc:tailnetlink` in connected tailnets (disable with `ui.enabled` / `-ui=false`).
- Metrics and health listen separately (default `127.0.0.1:9090`); deploy examples bind `:9090` so container probes work.
- Ownership annotations stop one border from updating or deleting another border's VIP services.
- Optional `authz` (`require_cap`, `allow_logins`, `allow_tags`) runs after PROXY/WhoIs and before dial; WhoIs errors fail closed when authz is on.
