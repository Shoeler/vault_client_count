BINARY     := vault-csv-normalizer
CMD        := ./cmd/vault-csv-normalizer
BUILD_DIR  := ./bin

.PHONY: all build test lint clean help

all: build

## build: compile the binary to ./bin/
build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) $(CMD)
	@echo "Built $(BUILD_DIR)/$(BINARY)"

## test: run all unit tests
test:
	go test ./... -v

## test-short: run tests without verbose output
test-short:
	go test ./...

## lint: run go vet (install staticcheck separately if desired)
lint:
	go vet ./...

## clean: remove build artifacts
clean:
	rm -rf $(BUILD_DIR)

## help: show this message
help:
	@grep -E '^##' $(MAKEFILE_LIST) | sed 's/## //'
