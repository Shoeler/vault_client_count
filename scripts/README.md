# scripts/

## sanitize_csv.py

Sanitizes Vault client-activity export CSVs so they can be shared (bug reports,
test fixtures) without exposing customer identifiers, while keeping the data
analytically equivalent for `vault-csv-normalizer`. Running the tool on the
sanitized files gives the same counts, the same `-d`, `--dedup-alias`,
`--dedup-methods`, `--dedup-methods-per-file` and `--dedup-jwt` results, the
same PKI partition (`-p`), the same abandoned-client counts and the same
monthly output as on the originals. Only mount path labels in the summary
differ (they are pseudonymized), so summary rows may sort in a different order.

Python 3 standard library only.

### Usage

```bash
# One file, one output file
python3 scripts/sanitize_csv.py export.csv -o export.sanitized.csv

# Several files from one customer, saving the salt for later runs
python3 scripts/sanitize_csv.py jan.csv feb.csv -o out/ --save-salt customer.salt

# A later file from the same customer, mapped consistently with the first run
python3 scripts/sanitize_csv.py mar.csv -o out/ --salt-file customer.salt
```

With a directory as `-o` (or more than one input), each output is written as
`<name>.sanitized.csv`.

| Option | Purpose |
|---|---|
| `--salt-file PATH` | Read the secret salt (hex, at least 16 bytes). Needed to map files from separate runs consistently. |
| `--save-salt PATH` | Save the randomly generated salt (mode 0600). |
| `--mapping-out PATH` | Write an original-to-pseudonym mapping (mode 0600). **Sensitive**: it contains every original identifier. Off by default. |
| `--keep-columns a,b` | Pass the named unrecognized columns through unchanged. |
| `--round-timestamps-to-day` | Truncate parseable timestamps to midnight UTC. |

The script exits non-zero with a message on bad input (missing file, no
`client_id` column, CSV parse error) or a failed safety check.

### Salt handling

All pseudonyms are HMAC-SHA256 values keyed by a secret salt. Without
`--salt-file`, a random 32-byte salt is generated and used for every file in
that run, so files sanitized together are always consistent. To sanitize more
files from the same customer later, save the salt with `--save-salt` and pass it
back with `--salt-file`. Keep the salt private: anyone with the salt can test
guesses ("is `alice` in this file?"). Never share it with the sanitized files.

### What is preserved and what is changed

| Column (and legacy names) | Treatment |
|---|---|
| `client_id` | Keyed hash. UUIDs stay UUID-shaped; other IDs become hex of similar length. |
| `entity_name` | `entity-<hex>`. Blank stays blank (drives abandoned-client logic). |
| `entity_alias_name`, `entity_alias_metadata.username` | Split into core name, tier suffix and domain: `alice-t0@corp.com` becomes `u<hex>-t0@domain-<hex>.example`. The core hash is case-sensitive and shared by both columns, so `alice`, `alice-t0`, `alice@corp.com` and the OIDC metadata username `alice` keep their equality relationships after `BaseAlias` / `StripTierSuffix`, and `Alice` stays different from `alice`. UUID subjects become different UUIDs. |
| `namespace_path` | Each segment becomes `ns-<hex>`; `[root]`, `root`, blank and trailing slashes are unchanged, so parent/child structure is kept. |
| `namespace_id` | `nsid-<hex>`; `root` and blank are unchanged. |
| `mount_path` | Well-known type segments (`auth`, `ldap`, `oidc`, `jwt`, `approle`, `cert`, `pki`, `kv`, ...) are kept; other segments become `mnt-<hex>`. Blank and trailing slashes are unchanged. |
| `mount_accessor` | Prefix words such as `auth_cert_` / `auth_ldap_` are kept; the unique suffix becomes keyed hex. The `auth_cert` prefix (PKI detection) is always preserved. |
| `mount_type`, `auth_method`, `client_type` | Unchanged (Vault vocabulary the tool depends on). |
| `token_creation_time`, `client_first_usage_time`, `client_first_used_time` | Unchanged unless `--round-timestamps-to-day`. |
| `local_entity_alias` | Unchanged when boolean; anything else becomes `redacted`. |
| Any other column | Dropped (names are listed on stderr) unless named in `--keep-columns`. |

Header handling follows the Go parser: UTF-8 BOM stripped for matching (and
written back), case-insensitive trimmed names, the same legacy column names.
Original header text and column order are kept; short rows stay short.

### Safety checks

After writing each file, the script re-reads the output and fails (deleting the
output) if:

* any cell, or any alphanumeric token in a cell, matches an original value from
  a pseudonymized column (tokens of 4+ characters; Vault vocabulary and
  pass-through values excepted), or
* the output row count differs from the input row count.

The failure message names only the row and column, never the value.

### Residual risks

Sanitized files are pseudonymized, not anonymized. Be aware that they still
contain:

* **Exact timestamps** (unless `--round-timestamps-to-day`), which reveal
  activity patterns and could be correlated with other data.
* **Row counts and frequency distributions**: number of clients, how many
  clients share an alias, mount or namespace.
* **Namespace hierarchy shape**: depth and parent/child relationships. The
  `--namespace` substring filter still works on the pseudonymized segment
  names, but not with the original names.
* **Mount and auth method types**, `client_type`, and well-known mount path
  segments. A custom plugin name in `mount_type` passes through unchanged.
* **Structure of aliases**: whether an alias has a domain, a tier suffix, or is
  a UUID subject.
* Columns passed with `--keep-columns` are not pseudonymized; the leak check
  fails if they share values with pseudonymized columns.

### Tests

```bash
python3 scripts/test_sanitize_csv.py
```
