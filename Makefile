.PHONY: build run dev clean deps lint

BINARY := tailnetlink
DATA ?= data.json

deps:
	go mod tidy
	go mod download

build: deps
	CGO_ENABLED=0 go build -ldflags "-s -w" -o $(BINARY) ./cmd/tailnetlink

run: build
	./$(BINARY) -data $(DATA) -listen :8888

dev:
	go run ./cmd/tailnetlink -data $(DATA) -listen :8888 -log-level debug

lint:
	go vet ./...

clean:
	rm -f $(BINARY)

# Docker
docker-build:
	docker build -t tailnetlink:latest .

docker-run:
	docker run --rm \
		-p 8080:8080 \
		-v $(PWD)/data.json:/data.json \
		tailnetlink:latest
