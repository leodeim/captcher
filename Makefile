.PHONY: all build test test-integration test-all vet lint fmt tidy cover cover-html clean help

# Default target
all: fmt tidy vet test

## Build

build: ## Build all packages
	go build ./...

## Testing

test: ## Run unit tests
	go test ./...

test-v: ## Run unit tests (verbose)
	go test -v ./...

test-integration: ## Run integration tests (requires network)
	go test -tags integration -run Integration ./...

test-all: ## Run all tests (unit + integration)
	go test -tags integration ./...

test-race: ## Run unit tests with race detector
	go test -race ./...

## Code Quality

vet: ## Run go vet
	go vet ./...

lint: ## Run staticcheck (install: go install honnef.co/go/tools/cmd/staticcheck@latest)
	staticcheck ./...

fmt: ## Format code
	gofmt -w .

fmt-check: ## Check formatting (fails if unformatted)
	@test -z "$$(gofmt -l .)" || { echo "Files need formatting:"; gofmt -l .; exit 1; }

## Dependencies

tidy: ## Tidy module dependencies
	go mod tidy

## Coverage

COVER_PROFILE ?= coverage.out

cover: ## Generate coverage report
	go test -coverprofile=$(COVER_PROFILE) -covermode=atomic ./...
	go tool cover -func=$(COVER_PROFILE)

cover-integration: ## Generate coverage report including integration tests
	go test -tags integration -coverprofile=$(COVER_PROFILE) -covermode=atomic ./...
	go tool cover -func=$(COVER_PROFILE)

cover-html: cover ## Open coverage report in browser
	go tool cover -html=$(COVER_PROFILE)

## Maintenance

clean: ## Remove build artifacts and coverage files
	go clean -testcache
	rm -f coverage.out coverage.html *.coverprofile *.test

## CI (runs everything a CI pipeline would)

ci: fmt-check tidy vet test-race ## Run all CI checks

## Help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
