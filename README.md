# vault-csv-normalizer

A CLI tool that reads one or more **HashiCorp Vault client export CSV files**,
normalizes their data (consistent column names, types, and values across Vault
versions), and displays the results as a pretty-printed terminal table.

## Features

- Accepts **multiple CSV files** via repeated `-f` flags
- Handles **column name variants** across Vault versions:
  - `timestamp` → `token_creation_time` (Vault < 1.17)
  - `namespace` → `namespace_path`
  - `type` → `client_type`
  - and more (see [Supported Column Aliases](#supported-column-aliases))
- Normalizes **client types** (`non_entity`, `Non-Entity Client`, etc. → `non-entity`)
- Normalizes **namespace paths** (empty/`root` → `[root]`, ensures trailing `/`)
- Normalizes **mount paths** (ensures trailing `/`)
- Normalizes **timestamps** to UTC across all common Vault timestamp formats
- **Filters** by namespace (substring) or client type
- **Sorts** by any column
- Prints a **summary footer** with counts per client type
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
vault-csv-normalizer -f <file1.csv> [-f <file2.csv> ...] [options]

OPTIONS:
  -f string
        Path to a Vault client export CSV file. May be specified multiple times.
  -sort string
        Column to sort by: namespace_path, client_type, token_creation_time,
        client_first_usage_time, mount_accessor, mount_path, auth_method, source
        (default "namespace_path")
  -namespace string
        Filter rows by namespace path (substring match)
  -type string
        Filter rows by client type: entity, non-entity, acme, secret-sync
  -help
        Show usage information
```

### Examples

```bash
# Single file, default sort (namespace_path)
vault-csv-normalizer -f export-2024-01.csv

# Multiple months merged into one view
vault-csv-normalizer -f jan.csv -f feb.csv -f mar.csv

# Sort by client type
vault-csv-normalizer -f export.csv --sort client_type

# Show only the education namespace and children
vault-csv-normalizer -f export.csv --namespace education/

# Show only entity clients, sorted by first usage time
vault-csv-normalizer -f export.csv --type entity --sort client_first_usage_time

# Combine filters and multiple files
vault-csv-normalizer -f jan.csv -f feb.csv --namespace finance/ --type non-entity
```

### Sample Output

```
Namespace Path      Client Type   Auth Method   Mount Path      Token Created          First Usage            Client ID                             Source File
----------------    ------------  ------------  ------------    ---------------------- ---------------------- ------------------------------------  -----------
[root]              entity        approle       auth/approle/   2024-01-05 08:12:34Z   2024-01-05 09:00:00Z   a1b2c3d4-0001-0001-0001-000000000001  export-2024-01.csv
[root]              acme          acme          pki/            2024-01-22 00:00:00Z   2024-01-22 00:00:00Z   a1b2c3d4-0001-0001-0001-000000000006  export-2024-01.csv
education/          non-entity    userpass      auth/userpass/  2024-01-12 09:00:00Z   —                      a1b2c3d4-0001-0001-0001-000000000003  export-2024-01.csv
education/training/ entity        approle       auth/approle/   2024-01-15 11:30:00Z   2024-01-15 12:00:00Z   a1b2c3d4-0001-0001-0001-000000000004  export-2024-01.csv
finance/            non-entity    ldap          auth/ldap/      2024-01-20 16:45:00Z   2024-01-20 17:00:00Z   a1b2c3d4-0001-0001-0001-000000000005  export-2024-01.csv

Total records: 5
  entity:        3
  non-entity:    2
  acme:          1
  secret-sync:   1
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
| `acme`, `certificate`, `cert`                     | `acme`         |
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
