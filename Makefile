BINARY := ratbox
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/ratbox

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

.PHONY: build test vet fmt
