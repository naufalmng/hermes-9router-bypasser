SHELL := /bin/bash
VERSION ?= 0.1.0
PIN ?=
SERVERID ?=
GOFLAGS := -trimpath
LDFLAGS := -s -w -X main.pin=$(PIN) -X main.serverID=$(SERVERID) -X main.clientVersion=$(VERSION)
GARBLE_VER := v0.12.1
GARBLE := $(shell command -v garble 2>/dev/null || echo $(HOME)/go/bin/garble)
HOSTARCH := $(shell go env GOARCH)

# garble @latest requires Go >= 1.27; this project targets Go 1.22, so the
# version is pinned. `go install mvdan.cc/garble@latest` silently replaces the
# working binary with one that refuses to run — hence this target.
garble-install:
	go install mvdan.cc/garble@$(GARBLE_VER)
	@$(GARBLE) version | head -1

BIN := bin
DIST := dist
# Windows and Linux only. macOS is not sold: the 9router chunks live in a
# Homebrew prefix that differs per machine, and shipping a target we cannot test
# on is how a customer ends up with a silent no-op.
TARGETS := linux/amd64 linux/arm64 windows/amd64

.PHONY: all build test vet fmt payload check release clean install-cli garble-install

all: build

## build — plain binaries, for your own machines
build:
	@mkdir -p $(BIN)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN)/h9bd ./cmd/h9bd
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN)/h9b  ./cmd/h9b
	@ls -la $(BIN)

## test — unit tests plus the payload parser
test:
	go test ./...
	$(BIN)/h9bd payload check -dir ./payloads

vet:
	go vet ./...

fmt:
	gofmt -l -w .

## payload — regenerate recipes from a pristine 9router tarball
##   make payload R9VER=0.5.95
R9VER ?= 0.5.95
payload:
	@rm -rf /tmp/h9b-r9 && mkdir -p /tmp/h9b-r9
	cd /tmp/h9b-r9 && npm pack 9router@$(R9VER) >/dev/null 2>&1 && tar xzf *.tgz
	python3 tools/build_router9_payload.py \
	  --pristine /tmp/h9b-r9/package/app/.next-cli-build/server/chunks \
	  --patched  /usr/lib/node_modules/9router/app/.next-cli-build/server/chunks \
	  --version  $(R9VER) \
	  --out      payloads/router9-disarm.v1.json
	python3 tools/build_hermes_payload.py --out payloads/hermes-guardrail.v1.json
	$(BIN)/h9bd payload check -dir ./payloads

## release — obfuscated cross-compiled client + plain server, with checksums
release:
	@if [ ! -x "$(GARBLE)" ]; then \
	  echo "garble missing: make garble-install"; exit 1; fi
	@if [ -z "$(SERVERID)" ]; then \
	  echo "SERVERID required: make release SERVERID=<ed25519-pub-b64>"; \
	  echo "  (a build without it warns at runtime and does NOT authenticate the server)"; \
	  exit 1; fi
	@mkdir -p $(DIST)
	@rm -f $(DIST)/*
	@for t in $(TARGETS); do \
	  os=$${t%/*}; arch=$${t#*/}; ext=""; \
	  [ "$$os" = "windows" ] && ext=".exe"; \
	  echo "  -> $$os/$$arch"; \
	  GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GARBLE) -tiny -literals \
	    build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
	    -o $(DIST)/h9b-$$os-$$arch$$ext ./cmd/h9b || exit 1; \
	done
	env GOOS=linux CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "-s -w" \
	  -o $(DIST)/h9bd-linux-$(HOSTARCH) ./cmd/h9bd
	cd $(DIST) && sha256sum * > SHA256SUMS && cat SHA256SUMS

## install-cli — put the server binary on PATH
install-cli: build
	sudo install -m755 $(BIN)/h9bd /usr/local/bin/h9bd

clean:
	rm -rf $(BIN) $(DIST)
