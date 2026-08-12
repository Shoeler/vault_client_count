# vault-csv-count

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Disclaimer:** This is an unofficial, community-provided tool. It is not
> created, endorsed, or supported by HashiCorp or IBM. Use at your own risk.
> No warranty is provided. For official Vault client counting guidance, refer
> to the [HashiCorp Vault documentation](https://developer.hashicorp.com/vault/docs).

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
- **Deduplicates** clients within each file by alias within explicit auth-method groups (`--dedup-methods-per-file ldap,oidc`); alias normalization strips domain suffixes (`@corp.com`)
- **Filters** by namespace (substring) or client type
- **Sorts** by any column
- Prints a **summary** with counts broken down by mount path and client type
- Optionally **partitions PKI/cert clients** (`-p`) into a separate summary, identified by `client_type=acme` or `mount_accessor` prefix `auth_cert`
- Skips blank/summary rows (rows with no `client_id`) silently

## Installation

```bash
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
  -dedup-methods-per-file method1,method2,...
        Deduplicate by alias for records whose auth method appears in the
        specified comma-separated group, scoped to each input file
        independently. Records in different files with the same alias are NOT
        collapsed — only within-file duplicates are removed. Normalization
        strips domain suffixes (at '@') only; tier suffixes (-t0/-t1/-t2) are
        kept. Records whose auth method is not in any group pass through
        unchanged.

        The flag is repeatable; each use defines one independent group:

          -dedup-methods-per-file ldap,oidc
              Within each file, collapse LDAP and OIDC records that share the
              same alias. "alice" (LDAP) and "alice@corp.com" (OIDC) in the
              same file normalize to "alice" and are counted once. A user in
              jan.csv and feb.csv is NOT collapsed — counted once per file.

          -dedup-methods-per-file ldap,oidc,jwt
              Treat LDAP, OIDC, and JWT as one group within each file.

          -dedup-methods-per-file ldap,oidc -dedup-methods-per-file jwt,saml
              Two independent per-file groups.

        Duplicate groups are printed as a table before the summary. Records
        without an alias and PKI clients are always kept.
  -remove-abandoned-clients
        Remove abandoned clients where entity_name and entity_alias_name are
        both blank. This includes records with no auth mount (mount_path
        empty) and merged/deleted entities (mount_path present). Applied after
        all deduplication steps.
  -generate-tf
        Generate Terraform HCL stubs for entity clients with no alias in the
        export. Requires --dedup-methods-per-file. A client is targeted when
        entity_alias_name is blank and mount_accessor is non-empty. For each
        such client, vault_identity_entity and vault_identity_entity_alias
        resources are written to vault-aliases.tf. Mount accessors are emitted
        as Terraform variables. Does not affect counts or summary output.
  -per-file
        Print a summary for each input file before the combined summary
  -debug
        Print all records grouped by mount path, with a full record table under
        each mount. Records with no mount path are grouped as "(no mount)".
      Also prints how many records were removed by
      --remove-abandoned-clients when that flag is enabled, split into
      no-mount and merged/deleted buckets.
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

# Remove abandoned clients from final totals
vault-csv-normalizer -f export.csv --remove-abandoned-clients

# Generate Terraform stubs for unaliased LDAP/OIDC clients
vault-csv-normalizer -f export.csv --dedup-methods-per-file ldap,oidc --generate-tf

# Same as above, with debug count output for removed rows
vault-csv-normalizer -f export.csv --remove-abandoned-clients --debug

# Within each file, collapse LDAP and OIDC records with the same alias
vault-csv-normalizer -f jan.csv feb.csv --dedup-methods-per-file ldap,oidc

# Treat LDAP, OIDC, and JWT as one group within each file
vault-csv-normalizer -f jan.csv feb.csv --dedup-methods-per-file ldap,oidc,jwt

# Two independent per-file groups: {ldap,oidc} and {jwt,saml}
vault-csv-normalizer -f jan.csv feb.csv --dedup-methods-per-file ldap,oidc --dedup-methods-per-file jwt,saml

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

## Alias-based deduplication

Vault can record the same human as multiple clients when they authenticate via
different auth methods (e.g. LDAP in one session and OIDC in another).
`--dedup-methods-per-file` collapses these into a single count within each file.

### How deduplication works

Each auth method stores a different value as the entity alias in Vault:

| Auth method | What Vault stores as `entity_alias_name` |
|---|---|
| `ldap` | Bare username: `alice` |
| `oidc` | Bare username (from `entity_alias_metadata.username`): `alice` |
| `jwt` | Full email address: `alice@corp.com` |

The tool normalizes all three to a common base by stripping the domain suffix
(`alice@corp.com` → `alice`), then matches records within the same file that
share the same normalized alias and belong to the same method group.

**This only works when the same string is used as the identity across all auth
methods.** If `alice` logs in via LDAP as `alice` and via JWT as
`alice@corp.com`, the normalization produces `alice` for both — they collapse.
If the LDAP username and the JWT email prefix do not match (e.g. `asmith` vs
`alice.smith@corp.com`), the records will not be collapsed.

### Required conditions for cross-method dedup

All of the following must be true for two records to be deduplicated:

1. Both records are in the **same source file** — records across files are never collapsed.
2. Both records' auth methods appear in the **same comma-separated list** passed to `--dedup-methods-per-file`. With `--dedup-methods-per-file ldap,oidc,jwt`, an LDAP and a JWT record can collapse. With `--dedup-methods-per-file ldap,oidc --dedup-methods-per-file jwt,saml`, an LDAP and a JWT record will never collapse — they are in separate groups.
3. Both records have a **non-empty `entity_alias_name`** (or `entity_alias_metadata.username` for OIDC).
4. The **normalized alias matches** — after stripping the domain suffix, the alias strings are identical.
5. Neither record is a **PKI client** (`client_type=acme` or `mount_accessor` prefix `auth_cert`).

If any condition is not met, both records pass through unchanged.

### Alias normalization

`--dedup-methods-per-file` applies one normalization step before comparing:

**Strip domain suffix** — everything from `@` onward is removed.
`alice@corp.com` → `alice`

This lets JWT records (which use full email addresses) match LDAP/OIDC records
(which use bare usernames), provided the local part of the email is the same
as the LDAP/OIDC username.

### Auth methods reference

| `mount_type` / `auth_method` | Typical users | Notes |
|---|---|---|
| `ldap` | Humans | Aliases are bare usernames (`alice`) |
| `oidc` | Humans | Aliases are bare usernames from `entity_alias_metadata.username` (`alice`) |
| `jwt` | Humans or services | Aliases are full email addresses (`alice@corp.com`); domain is stripped to match LDAP/OIDC |
| `approle` | Service accounts | Not human; not typically alias-deduped |
| `kubernetes` | Service accounts | Not human; not typically alias-deduped |
| `aws` / `gcp` | Service accounts | Not human; not typically alias-deduped |
| `cert` | Services or devices | PKI clients; excluded from all alias dedup |
| `acme` | Devices (ACME protocol) | PKI clients (`client_type=acme`); excluded from all alias dedup |

PKI clients (cert auth with `mount_accessor` prefix `auth_cert`, or
`client_type=acme`) are **always excluded** from alias dedup and always kept.
Use `-p` to count them separately.

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
| `entity_alias_name`      | No       | Human-readable alias for the entity (used by `--dedup-methods-per-file`; domain suffix is stripped during normalization) |

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
