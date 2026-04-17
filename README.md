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
- **Deduplicates** clients across files by `client_id` when `-d` is set, or by normalized `entity_alias_name` (`--dedup-alias`), which strips domain suffixes (`@corp.com`) and tier suffixes (`-t0`/`-t1`/`-t2`)
- **Filters** by namespace (substring) or client type
- **Sorts** by any column
- Prints a **summary** with counts broken down by mount path and client type
- Optionally **partitions PKI/cert clients** (`-p`) into a separate summary, identified by `client_type=acme` or `mount_accessor` prefix `auth_cert`
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
  -since string
        Exclude records whose token_creation_time is before this value.
        Accepts any Vault timestamp format: "2024-01-01", "2024-01-01T00:00:00Z", etc.
        Records with no token_creation_time are always kept.
  -p    Partition and report PKI/cert clients separately.
        A client is considered PKI if client_type=acme (ACME protocol clients
        from the PKI secrets engine) OR mount_accessor starts with auth_cert
        (cert auth method clients). Both types are reported together as "PKI".
  -since-file filename=date
        Apply a since filter to one specific file only. May be specified
        multiple times for different files. The filename is matched against
        the base name (e.g. jan.csv=2024-01-15).
  -d    Deduplicate records by client_id across all input files.
  -dedup-alias
        Deduplicate by entity_alias_name within the same auth method across all
        input files. Two records are considered the same client if they share
        the same normalized alias AND the same mount type, regardless of mount
        accessor or source file. Normalization strips the domain suffix (at '@')
        and any trailing tier suffix (-t0, -t1, -t2), so "sbishop",
        "sbishop-t0" in one file, and "sbishop-t1" in another are treated as
        one LDAP client — but a JWT record for "sbishop@corp.com" is left
        untouched (different mount type). Use --dedup-jwt to additionally
        collapse across auth methods.
        Duplicate groups are printed as a table before the summary.
        Records without an alias are always kept. May be combined with -d.
  -dedup-jwt
        Drop JWT records whose normalized alias matches a non-JWT record across
        any input file. Uses the same normalization as --dedup-alias (strips
        '@domain' and '-t0'/'-t1'/'-t2'). Prevents the same person from being
        counted twice when they authenticate via both LDAP/OIDC and JWT.
        Records without an alias are always kept. May be combined with
        --dedup-alias and/or -d.
  -per-file
        Print a summary for each input file before the combined summary
  -debug
        Print all records grouped by mount path, with a full record table under
        each mount. Records with no mount path are grouped as "(no mount)".
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

# PKI/cert report across multiple months
vault-csv-normalizer -f jan.csv feb.csv -p

# Apply --since only to jan.csv (e.g. it starts mid-month)
vault-csv-normalizer -f jan.csv feb.csv --since-file jan.csv=2024-01-15

# Per-file since filters on multiple files
vault-csv-normalizer -f jan.csv feb.csv \
  --since-file jan.csv=2024-01-15 \
  --since-file feb.csv=2024-02-01

# Per-file breakdown before the combined summary
vault-csv-normalizer -f jan.csv feb.csv --per-file

# Debug: show all records grouped by mount path
vault-csv-normalizer -f export.csv --debug

# Deduplicate client_ids across files
vault-csv-normalizer -f jan.csv feb.csv -d

# Deduplicate by entity alias — strips domain (@corp.com) and tier (-t0/-t1/-t2)
# "alice", "alice-t0", "alice-t1", "alice@corp.com" → counted as one client per file
vault-csv-normalizer -f jan.csv feb.csv --dedup-alias

# Combine both: alias dedup collapses tier/domain variants within each file,
# then -d deduplicates the same client_id appearing across multiple files
vault-csv-normalizer -f jan.csv feb.csv --dedup-alias -d

# Drop JWT records where the same person already appears via LDAP or OIDC
vault-csv-normalizer -f export.csv --dedup-jwt

# Full dedup: collapse tiers, dedup client_ids, then drop redundant JWT records
vault-csv-normalizer -f jan.csv feb.csv --dedup-alias -d --dedup-jwt

# Exclude records created before 2024-06-01
vault-csv-normalizer -f export.csv --since 2024-06-01

# Combine date filter with namespace filter
vault-csv-normalizer -f export.csv --since 2024-01-01T00:00:00Z --namespace finance/

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
PKI/cert clients (matched by `client_type=acme` or `mount_accessor` prefix `auth_cert`):

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
| `entity_alias_name`      | No       | Human-readable alias for the entity (used by `--dedup-alias`; domain and tier suffixes are stripped during normalization) |

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
| `alias_name`          | `entity_alias_name`      | Alternate naming           |
| `entity_alias`        | `entity_alias_name`      | Alternate naming           |

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
