# Compile on the build machine's platform and cross-compile for the target,
# so multi-arch builds don't run the Go toolchain under QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags "-s -w" -o /tailnetlink ./cmd/tailnetlink

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /tailnetlink /usr/local/bin/tailnetlink
ENTRYPOINT ["/usr/local/bin/tailnetlink"]
CMD ["-data", "/data.json", "-listen", ":8080"]
