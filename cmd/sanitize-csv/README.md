# sanitize-csv

Go port of `scripts/sanitize_csv.py`. It pseudonymizes Vault client-activity
export CSVs so they can be shared, without needing Python. Standard library
only.

The behaviour (preserved and changed columns, salt handling, safety checks,
residual risks) is specified in [`scripts/README.md`](../../scripts/README.md)
and is the same here. For the same salt file and options, the Go and Python
versions produce byte-identical sanitized files and mapping files.

## Build and run

```bash
go build -o /path/to/sanitize-csv ./cmd/sanitize-csv

sanitize-csv export.csv -o export.sanitized.csv
sanitize-csv jan.csv feb.csv -o out/ --save-salt customer.salt
sanitize-csv mar.csv -o out/ --salt-file customer.salt
sanitize-csv jan.csv feb.csv -o out/ --keep-filenames
sanitize-csv jan.csv -o out/ --salt-file customer.salt --mapping-out customer.mapping.csv
```

With a directory as `-o` (or more than one input), each output is written as
`export-<hex>.sanitized.csv`, a keyed pseudonym of the input name (see
`scripts/README.md`), or as `<name>.sanitized.csv` with `--keep-filenames`. An
explicit single output file is used as given. Two inputs that would produce the
same output path are an error, reported before anything is written, and so is
an output, `--save-salt` or `--mapping-out` path that names an input, an output
or each other (compared after resolving symlinks, by file identity, and
case-insensitively on a case-folding filesystem; see `scripts/README.md`).
Flags may appear before, between or after the input files.

Name mapping files `<something>.mapping.csv`: `.gitignore` ignores
`*mapping*.csv`, `*.map` and `*.salt` anywhere in the repository.

## Options

| Option | Purpose |
|---|---|
| `-o`, `--output` | Output directory, or an output file path for a single input (required). |
| `--salt-file PATH` | Read the secret salt (hex or raw, at least 16 bytes). |
| `--save-salt PATH` | Save the generated salt (mode 0600). |
| `--mapping-out PATH` | Write an original-to-pseudonym mapping (mode 0600), including `filename` rows for renamed outputs. Sensitive. |
| `--keep-columns a,b` | Pass the named unrecognized columns through unchanged. |
| `--keep-filenames` | Name derived outputs `<name>.sanitized.csv` instead of pseudonymizing the name. |
| `--round-timestamps-to-day` | Truncate parseable timestamps to midnight UTC. |

Go's `flag` package also accepts the single-dash spellings (`-salt-file`).

Exit codes: 0 success, 1 bad input or failed safety check (the output file is
deleted and the leaked value is never printed), 2 usage error.

## Tests

```bash
go test ./internal/sanitizer
```

The tests are a port of `scripts/test_sanitize_csv.py`.

## Known differences from the Python script

Output files are identical for valid UTF-8 input. Differences are limited to
stderr wording of OS errors, and to edge cases listed in the implementation
notes (non-ASCII digits in timestamps, rare Unicode case-folding, invalid UTF-8
in `--mapping-out` ordering).
