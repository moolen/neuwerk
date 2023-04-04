
CLANG ?= clang
STRIP ?= llvm-strip
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

.PHONY: generate
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...

build: generate
	mkdir -p bin
	CGO_ENABLED=0 go build -ldflags='-extldflags=-static' -o bin/neuwerk main.go
