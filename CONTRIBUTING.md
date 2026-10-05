# Contributing

## Development

```bash
go test ./...
go vet ./...
go vet -tags e2e ./test/...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
./scripts/coverage.sh
```

`./scripts/coverage.sh` fails if total coverage drops below `.coverage-baseline`. The long-term target is 85%; the ratchet keeps us from sliding backwards. When coverage rises a full point or more above the floor, raise the baseline in the same PR.

## Tests

- Unit and package tests under `internal/` and `cmd/`
- In-process e2e against `testcontrol` in `internal/e2e/`
- Real-tailnet e2e (`-tags e2e ./test/e2e/...`) runs on `main` after merge; it creates throwaway CI tailnets and must delete them (`confirmed gone`)

## Pull requests

- One focused change per PR
- Plain commit messages; no force-pushes to shared branches
- Images publish only from version tags via `release.yml` — do not push images from PR CI
- Do not create release tags in a normal feature PR

## Style

gofmt the Go you touch. Prefer small, readable diffs over clever ones.

## Repository settings

Branch protection on `main` (required status checks) is configured by the owner in GitHub settings, not via files in this repository.
