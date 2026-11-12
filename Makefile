# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 SukramJ.

GO               ?= go
GOFUMPT          ?= gofumpt
GOLANGCI_LINT    ?= golangci-lint
GOLANGCI_TIMEOUT ?= 15m
GOVULNCHECK      ?= govulncheck

# Pinned on purpose, and to the same versions .github/workflows/ci.yml uses.
# Bump deliberately: raise both, run the linter locally, fix what it finds,
# in one commit.
GOFUMPT_VERSION       ?= v0.12.0
GOLANGCI_LINT_VERSION ?= v2.14.0

# govulncheck is deliberately NOT pinned: a newly published advisory should
# turn the scan red without a commit, because the code it indicts has not
# changed but its risk has.

.PHONY: help
help: ## show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: ## install the developer tooling (lint pinned, govulncheck floating)
	$(GO) install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest

.PHONY: build
build: ## compile every package and the server binary into bin/
	$(GO) build ./...
	CGO_ENABLED=0 $(GO) build -o bin/ha-airlock ./cmd/ha-airlock

.PHONY: vet
vet: ## run go vet
	$(GO) vet ./...

.PHONY: test
test: ## run the test suite
	$(GO) test -count=1 ./...

.PHONY: race
race: ## run the test suite under the race detector (needs CGO)
	CGO_ENABLED=1 $(GO) test -race -count=1 ./...

.PHONY: vuln
vuln: ## report known vulnerabilities on code paths this module actually calls
	$(GOVULNCHECK) ./...

.PHONY: fmt
fmt: ## format with gofumpt
	$(GOFUMPT) -w .

.PHONY: lint
lint: ## gofumpt check + golangci-lint + module hygiene
	@# .claude/worktrees holds agent worktrees: other branches' files, not this tree's.
	@out=$$($(GOFUMPT) -l . | grep -v '^\.claude/' || true); \
		test -z "$$out" || { echo "$$out"; echo "gofumpt: files need formatting (run 'make fmt')"; exit 1; }
	$(GOLANGCI_LINT) config verify
	$(GOLANGCI_LINT) run --timeout=$(GOLANGCI_TIMEOUT) ./...
	$(GO) mod tidy -diff
	$(GO) mod verify

.PHONY: tidy
tidy: ## tidy go.mod / go.sum
	$(GO) mod tidy

.PHONY: ci
ci: build vet test lint ## everything the pipeline's merge path runs
