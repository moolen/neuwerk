
CLANG ?= clang
STRIP ?= llvm-strip
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

.PHONY: generate
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...

lint:
	golangci-lint run --fix

build: generate
	mkdir -p bin
	CGO_ENABLED=0 go build -ldflags='-s -w -extldflags=-static' -o bin/neuwerk main.go
	CGO_ENABLED=0 ginkgo build ./e2e

test.e2e: build
	ginkgo run -v ./e2e