# vault-csv-normalizer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A CLI tool that reads one or more **HashiCorp Vault client export CSV files**,
normalizes their data (consistent column names, types, and values across Vault
versions), and displays a summary of client counts by mount path and type.

## Features

- Accepts **multiple CSV files** via `-f file1.csv file2.csv ...` or repeated `-f` flags
- Handles **column name variants** across Vault versions:
  - `timestamp` → `token_creation_time` (Vault < 1.17)
  - `namespace` → `namespace_path`
  - `type` → `client_type`
  - and more (see [Supported Column Aliases](#supported-column-aliases))
- Normalizes **client types** (`non_entity`, `Non-Entity Client`, etc. → `non-entity`)
- Normalizes **namespace paths** (empty/`root` → `[root]`, ensures trailing `/`)
- Normalizes **mount paths** (ensures trailing `/`)
- Normalizes **timestamps** to UTC across all common Vault timestamp formats
- **Deduplicates** clients across files by `client_id` (disable with `-d`)
- **Filters** by namespace (substring) or client type
- **Sorts** by any column
- Prints a **summary** with counts broken down by mount path and client type
- Optionally **partitions ACME/PKI clients** (`-p`) into a separate summary, identified by `client_type=acme`
- Skips blank/summary rows (rows with no `client_id`) silently

## Installation

```bash
git clone https://github.com/your-org/vault-csv-normalizer
cd vault-csv-normalizer
make build
# Binary is at ./bin/vault-csv-normalizer
```

Requires **Go 1.22+**. No external dependencies — pure standard library.

## Usage

```
vault-csv-normalizer -f <file1.csv> [file2.csv ...] [options]
vault-csv-normalizer -f <file1.csv> -f <file2.csv> [options]

OPTIONS:
  -f string
        One or more Vault client export CSV files. May be specified multiple
        times or followed by multiple paths.
  -sort string
        Column to sort by: namespace_path, client_type, token_creation_time,
        client_first_usage_time, mount_accessor, mount_path, auth_method, source
        (default "namespace_path")
  -namespace string
        Filter rows by namespace path (substring match)
  -type string
        Filter rows by client type: entity, non-entity, acme, secret-sync
  -p    Partition and report ACME/PKI clients (client_type=acme) separately
  -legacy-pki
        Use legacy PKI detection: match mount_accessor prefix 'auth_cert'
        instead of client_type=acme (for older Vault exports)
  -d    Disable deduplication (count duplicate client IDs separately)
  -per-file
        Print a summary for each input file before the combined summary
  -debug
        Print a table of all records with no mount path
  -help
        Show usage information
```

### Examples

```bash
# Single file, default sort (namespace_path)
vault-csv-normalizer -f export-2024-01.csv

# Multiple months — pass files after one -f flag
vault-csv-normalizer -f jan.csv feb.csv mar.csv

# Or use repeated -f flags
vault-csv-normalizer -f jan.csv -f feb.csv -f mar.csv

# Sort by client type
vault-csv-normalizer -f export.csv --sort client_type

# Show only the education namespace and children
vault-csv-normalizer -f export.csv --namespace education/

# Show only entity clients
vault-csv-normalizer -f export.csv --type entity

# Partition PKI clients into a separate summary
vault-csv-normalizer -f export.csv -p

# PKI/ACME report across multiple months
vault-csv-normalizer -f jan.csv feb.csv -p

# Use legacy PKI detection (older Vault exports)
vault-csv-normalizer -f export.csv -p -legacy-pki

# Per-file breakdown before the combined summary
vault-csv-normalizer -f jan.csv feb.csv --per-file

# Debug: show all records with no mount path
vault-csv-normalizer -f export.csv --debug

# Count all records without deduplication
vault-csv-normalizer -f jan.csv feb.csv -d

# Combine filters and multiple files
vault-csv-normalizer -f jan.csv feb.csv --namespace finance/ --type non-entity
```

### Sample Output

```
Summary
-------
  Mount Path      Client Type  Count
  ----------      -----------  -----
  auth/approle/   entity           3
                  subtotal:        3

  auth/ldap/      non-entity       1
                  subtotal:        1

  auth/userpass/  non-entity       1
                  subtotal:        1

  pki/            acme             1
                  subtotal:        1
  ----------      -----------  -----
                  TOTAL:           6
```

With `-p`, two summaries are printed — one for non-PKI clients and one for
ACME/PKI clients (`client_type=acme`). Use `-legacy-pki` to instead identify
PKI clients by `mount_accessor` prefix `auth_cert` (for older Vault exports):

```
Non-PKI Client Summary
----------------------
  Mount Path      Client Type  Count
  ...

PKI Client Summary
------------------
  Mount Path      Client Type  Count
  ...
```

## CSV Format

The tool expects CSVs exported from the Vault activity export API
(`GET /v1/sys/internal/counters/activity/export?format=csv`) or the Vault UI
**Export attribution data** button.

### Expected Columns

| Canonical Column         | Required | Description                                      |
|--------------------------|----------|--------------------------------------------------|
| `client_id`              | ✅ Yes   | Unique client identifier                         |
| `namespace_id`           | No       | Internal namespace ID (`root` for root)          |
| `namespace_path`         | No       | Human-readable namespace path                    |
| `mount_accessor`         | No       | Accessor of the auth mount                       |
| `mount_path`             | No       | Path of the auth mount                           |
| `mount_type`             | No       | Type of the auth mount (approle, ldap, etc.)     |
| `auth_method`            | No       | Auth method name                                 |
| `client_type`            | No       | Type of client (entity, non-entity, acme, etc.)  |
| `token_creation_time`    | No       | RFC3339 timestamp of token creation              |
| `client_first_usage_time`| No       | RFC3339 timestamp of first authenticated call    |

### Supported Column Aliases

The tool automatically maps legacy and alternate column names:

| File Column           | Maps To                  | Vault Version / Source     |
|-----------------------|--------------------------|----------------------------|
| `timestamp`           | `token_creation_time`    | Vault < 1.17               |
| `first_seen`          | `client_first_usage_time`| Some third-party exports   |
| `namespace`           | `namespace_path`         | Some UI exports            |
| `mount`               | `mount_path`             | Alternate naming           |
| `auth_backend`        | `auth_method`            | Older Vault versions       |
| `type`                | `client_type`            | Shortened column name      |

Column names are matched **case-insensitively**.

### Normalized Client Types

| Raw Values                                        | Normalized To  |
|---------------------------------------------------|----------------|
| `entity`, `Entity`, `Entity Client`               | `entity`       |
| `non-entity`, `non_entity`, `Non-Entity Client`   | `non-entity`   |
| `acme`, `acme client`                             | `acme`         |
| `secret-sync`, `secret_sync`, `secrets sync`      | `secret-sync`  |
| (empty)                                           | `unknown`      |

## Project Structure

```
vault-csv-normalizer/
├── cmd/
│   └── vault-csv-normalizer/
│       └── main.go          # CLI entrypoint, flag parsing
├── internal/
│   ├── parser/
│   │   ├── parser.go        # CSV reading, column mapping
│   │   └── parser_test.go
│   ├── normalizer/
│   │   ├── normalizer.go    # Value normalization, filtering, sorting
│   │   └── normalizer_test.go
│   └── renderer/
│       ├── renderer.go      # Pretty-print table and summary
│       └── renderer_test.go
├── testdata/
│   ├── export-2024-01.csv           # Modern Vault export format
│   └── export-2024-02-legacy.csv    # Legacy format (timestamp column)
├── go.mod
├── Makefile
└── README.md
```

## Development

```bash
# Run all tests
make test

# Run vet
make lint

# Build
make build

# Clean
make clean
```
