GO        ?= go
BIN       ?= bin
PKG       := ./...
COMPOSE   := docker compose -f deploy/compose/docker-compose.yaml

.DEFAULT_GOAL := build

.PHONY: build
build: ## Build qw and qwproxy into ./bin
	$(GO) build -o $(BIN)/qw ./cmd/qw
	$(GO) build -o $(BIN)/qwproxy ./cmd/qwproxy

.PHONY: test
test: ## Vet + unit tests with race detector
	$(GO) vet $(PKG)
	$(GO) test -race -count=1 $(PKG)

.PHONY: cover
cover: ## Tests with coverage report
	$(GO) test -race -covermode=atomic -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: fmt
fmt: ## Format code
	$(GO) fmt $(PKG)

.PHONY: fmt-check
fmt-check: ## Fail if code is not gofmt-clean
	@out=$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*')); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

.PHONY: lint
lint: ## Run golangci-lint (install with `make tools`)
	golangci-lint run

.PHONY: tools
tools: ## Install dev tooling
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

.PHONY: check
check: fmt-check test ## The full pre-PR gate (CI runs this)

.PHONY: tidy
tidy: ## go mod tidy
	$(GO) mod tidy

.PHONY: sim-up
sim-up: ## Bring up the local simulation stack (keycloak + quickwit + postgres + qwproxy)
	$(COMPOSE) up -d --build
	@echo "Waiting for stack to become healthy..."
	$(COMPOSE) ps

.PHONY: sim-down
sim-down: ## Tear down the local simulation stack + volumes
	$(COMPOSE) down -v

.PHONY: sim-logs
sim-logs: ## Follow simulation stack logs
	$(COMPOSE) logs -f

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN) dist coverage.out

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
