BINARY     := vault-csv-normalizer
CMD        := ./cmd/vault-csv-normalizer
BUILD_DIR  := ./bin

.PHONY: all build install test lint clean help install-hooks

all: build

## build: compile the binary to ./bin/
build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) $(CMD)
	@echo "Built $(BUILD_DIR)/$(BINARY)"

## install: build and copy the binary to ~/bin
install: build
	@mkdir -p $(HOME)/bin
	cp $(BUILD_DIR)/$(BINARY) $(HOME)/bin/
	@echo "Installed $(HOME)/bin/$(BINARY)"

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

## install-hooks: enable the gitleaks pre-commit hook (scripts/git-hooks)
install-hooks:
	git config core.hooksPath scripts/git-hooks
	@echo "Git hooks enabled (requires gitleaks: brew install gitleaks)"

## help: show this message
help:
	@grep -E '^##' $(MAKEFILE_LIST) | sed 's/## //'
