## Summary
<!-- What changed and why. -->

## Test plan
- [ ] `gofmt`, `go vet ./...`, `go vet -tags e2e ./test/...`, `staticcheck ./...`
- [ ] `./scripts/coverage.sh`
- [ ] CI green
- [ ] If this touches bridging or teardown: after merge, real e2e green and `confirmed gone` for every CI tailnet
