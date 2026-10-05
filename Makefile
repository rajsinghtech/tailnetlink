.PHONY: build run dev clean deps lint docker-build docker-run version

BINARY := tailnetlink
DATA ?= tailnetlink.json
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

deps:
	go mod tidy
	go mod download

build: deps
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BINARY) ./cmd/tailnetlink

version: build
	./$(BINARY) -version

run: build
	./$(BINARY) -data $(DATA)

dev:
	go run -ldflags "-X main.Version=$(VERSION)" ./cmd/tailnetlink -data $(DATA) -log-level debug

lint:
	go vet ./...

clean:
	rm -f $(BINARY)

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t tailnetlink:local .

docker-run:
	docker run --rm \
		-p 8888:8888 -p 9090:9090 \
		-v $(PWD)/tailnetlink.json:/data/tailnetlink.json:ro \
		-v tailnetlink-state:/data/tailnetlink-state \
		tailnetlink:local
