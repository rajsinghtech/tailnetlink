# Compile on the build machine's platform and cross-compile for the target,
# so multi-arch builds don't run the Go toolchain under QEMU.
# mirror.gcr.io serves the same Docker Hub digests. Hub itself answers 429
# often enough to fail CI before the build starts.
FROM --platform=$BUILDPLATFORM mirror.gcr.io/library/golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
  -ldflags "-s -w -X main.Version=${VERSION}" \
  -o /tailnetlink ./cmd/tailnetlink

FROM mirror.gcr.io/library/alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
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
