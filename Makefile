.PHONY: all build test test-v test-integration test-all test-race vet lint fmt fmt-check tidy cover cover-integration cover-html clean ci help

# This repository is a multi-module workspace: the core lives in the root
# module, each web-framework adapter is its own module so consumers only pull
# in the framework they actually use, and the runnable example is its own
# module (it depends on every adapter). Most targets iterate every module.
MODULES = . middleware/ginmw middleware/echomw example

# Default target
all: fmt tidy vet test

## Build

build: ## Build all packages (all modules)
	@for d in $(MODULES); do echo "== build $$d =="; (cd $$d && go build ./...) || exit 1; done

## Testing

test: ## Run unit tests (all modules)
	@for d in $(MODULES); do echo "== test $$d =="; (cd $$d && go test ./...) || exit 1; done

test-v: ## Run unit tests (verbose, all modules)
	@for d in $(MODULES); do echo "== test $$d =="; (cd $$d && go test -v ./...) || exit 1; done

test-integration: ## Run integration tests (requires network, all modules)
	@for d in $(MODULES); do echo "== integration $$d =="; (cd $$d && go test -tags integration -run Integration ./...) || exit 1; done

test-all: ## Run all tests (unit + integration, all modules)
	@for d in $(MODULES); do echo "== test-all $$d =="; (cd $$d && go test -tags integration ./...) || exit 1; done

test-race: ## Run unit tests with race detector (all modules)
	@for d in $(MODULES); do echo "== test-race $$d =="; (cd $$d && go test -race ./...) || exit 1; done

## Code Quality

vet: ## Run go vet (all modules)
	@for d in $(MODULES); do echo "== vet $$d =="; (cd $$d && go vet ./...) || exit 1; done

lint: ## Run staticcheck (install: go install honnef.co/go/tools/cmd/staticcheck@latest)
	@for d in $(MODULES); do echo "== lint $$d =="; (cd $$d && staticcheck ./...) || exit 1; done

fmt: ## Format code
	gofmt -w .

fmt-check: ## Check formatting (fails if unformatted)
	@test -z "$$(gofmt -l .)" || { echo "Files need formatting:"; gofmt -l .; exit 1; }

## Dependencies

tidy: ## Tidy module dependencies (all modules)
	@for d in $(MODULES); do echo "== tidy $$d =="; (cd $$d && go mod tidy) || exit 1; done

## Coverage

COVER_PROFILE ?= coverage.out

cover: ## Generate coverage report (all modules)
	@for d in $(MODULES); do echo "== cover $$d =="; (cd $$d && go test -coverprofile=$(COVER_PROFILE) -covermode=atomic ./... && go tool cover -func=$(COVER_PROFILE)) || exit 1; done

cover-integration: ## Generate coverage report including integration tests (all modules)
	@for d in $(MODULES); do echo "== cover $$d =="; (cd $$d && go test -tags integration -coverprofile=$(COVER_PROFILE) -covermode=atomic ./... && go tool cover -func=$(COVER_PROFILE)) || exit 1; done

cover-html: ## Open root-module coverage report in browser
	go test -coverprofile=$(COVER_PROFILE) -covermode=atomic ./...
	go tool cover -html=$(COVER_PROFILE)

## Maintenance

clean: ## Remove build artifacts and coverage files
	go clean -testcache
	rm -f coverage.out coverage.html *.coverprofile *.test
	rm -f middleware/ginmw/coverage.out middleware/echomw/coverage.out example/coverage.out

## CI (runs everything a CI pipeline would)

ci: fmt-check tidy vet test-race ## Run all CI checks

## Help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
