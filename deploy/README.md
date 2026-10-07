# Deploy examples

Run one process per border. The image is non-root (`65532`), expects the
config at `/data/tailnetlink.json`, and listens for metrics on `:9090` so
probes inside the container work.

```bash
cp ../config.example.json ./tailnetlink.json
# fill in OAuth client ids and secret paths under ./secrets/
docker compose up -d
curl -sf http://127.0.0.1:9090/healthz
```

Version tags (`v*.*.*`) publish release images. Pushes to `main` publish `:main` and `:sha-<short>`; pin by digest.
