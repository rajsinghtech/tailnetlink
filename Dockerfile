# Compile on the build machine's platform and cross-compile for the target,
# so multi-arch builds don't run the Go toolchain under QEMU.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:738d1cf061836894ff6bb8c33881080ac66de8cf0586615012a0c8f592649cfa AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
  -ldflags "-s -w -X main.Version=${VERSION}" \
  -o /tailnetlink ./cmd/tailnetlink

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates \
  && addgroup -S -g 65532 nonroot \
  && adduser -S -u 65532 -G nonroot nonroot \
  && mkdir -p /data /data/tailnetlink-state \
  && chown -R nonroot:nonroot /data
COPY --from=build /tailnetlink /usr/local/bin/tailnetlink
USER 65532:65532
WORKDIR /data
EXPOSE 8888 9090
VOLUME ["/data"]
# Probes need a reachable metrics address; deploy examples bind :9090.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:9090/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/tailnetlink"]
CMD ["-data", "/data/tailnetlink.json", "-listen", "127.0.0.1:8888", "-metrics-listen", ":9090"]
