# Testing

## Layers

1. **Unit** — packages under `internal/` and `cmd/`
2. **testcontrol e2e** — `internal/e2e/` spins fake control servers and real tsnet nodes
3. **Real tailnets** — `go test -tags e2e ./test/e2e/...` with org federated identity in CI (`e2e-real.yml`)

## Coverage ratchet

`scripts/coverage.sh` compares total coverage to `.coverage-baseline`. Raise the floor when you gain a point or more.

## Real e2e cleanup

Every run creates `tailnetlink-ci-<run>-<attempt>-<role>` tailnets and must delete them with `confirmed gone`. The hourly janitor deletes stale CI names older than ~2h. Roles may include digits (`dst2`); ParseName must accept them or cleanup will miss the tailnet.
