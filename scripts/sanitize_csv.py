#!/usr/bin/env python3
"""Sanitize Vault client-activity export CSVs so they can be shared.

The output is analytically equivalent for vault-csv-normalizer: every value the
tool compares (client IDs, alias names, mount paths, accessors, namespaces) is
replaced with a keyed pseudonym that preserves equality, blankness, and the
specific structure the tool's logic relies on (alias '@' domain split, -t0/-t1/-t2
tier suffixes, the auth_cert accessor prefix, root namespace forms, trailing
slashes). Vault vocabulary (mount_type, auth_method, client_type) and
timestamps pass through unchanged. Unrecognized columns are dropped.

Only the Python 3 standard library is used. Run with --help for usage.
"""

import argparse
import csv
import datetime
import hashlib
import hmac
import itertools
import os
import re
import secrets
import stat
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Column recognition (mirrors knownColumns in internal/parser/parser.go)
# ---------------------------------------------------------------------------

KNOWN_COLUMNS = {
    "client_id": "client_id",
    "entity_name": "entity_name",
    "namespace_id": "namespace_id",
    "namespace_path": "namespace_path",
    "mount_accessor": "mount_accessor",
    "mount_path": "mount_path",
    "mount_type": "mount_type",
    "auth_method": "auth_method",
    "client_type": "client_type",
    "token_creation_time": "token_creation_time",
    "client_first_usage_time": "client_first_usage_time",
    "entity_alias_name": "entity_alias_name",
    "entity_alias_metadata.username": "entity_alias_metadata_username",
    # Legacy / alternative column names.
    "timestamp": "token_creation_time",
    "first_seen": "client_first_usage_time",
    "namespace": "namespace_path",
    "mount": "mount_path",
    "auth_backend": "auth_method",
    "type": "client_type",
    "alias_name": "entity_alias_name",
    "entity_alias": "entity_alias_name",
}

# Vault export columns that vault-csv-normalizer does not read but that carry
# no customer identifiers. They are kept so the sanitized file stays close to
# a real export. Values are still validated (see Sanitizer.sanitize_cell).
EXTRA_SAFE_COLUMNS = {
    "client_first_used_time": "extra_timestamp",
    "local_entity_alias": "extra_boolean",
}

# Policy per canonical column name.
POLICY = {
    "client_id": "client_id",
    "entity_name": "entity_name",
    "namespace_id": "namespace_id",
    "namespace_path": "namespace_path",
    "mount_accessor": "mount_accessor",
    "mount_path": "mount_path",
    "mount_type": "passthrough",
    "auth_method": "passthrough",
    "client_type": "passthrough",
    "token_creation_time": "timestamp",
    "client_first_usage_time": "timestamp",
    "entity_alias_name": "alias",
    "entity_alias_metadata_username": "alias",
    "extra_timestamp": "timestamp",
    "extra_boolean": "boolean",
}

PSEUDONYMIZED_POLICIES = {
    "client_id", "entity_name", "namespace_id", "namespace_path",
    "mount_accessor", "mount_path", "alias",
}

# Well-known Vault auth method and secrets engine type names. Mount path and
# mount accessor segments that exactly match one of these (case-insensitive)
# are preserved; every other segment is pseudonymized.
WELL_KNOWN_MOUNT_WORDS = frozenset("""
auth secret secrets sys identity cubbyhole token
ldap oidc jwt approle kubernetes k8s aws gcp azure cert userpass github okta
radius saml kerberos oci cf alicloud spiffe scep
pki acme kv transit database ssh totp consul nomad rabbitmq terraform ad
openldap kmip transform keymgmt gcpkms mongodbatlas
""".split())

# Words that may legitimately appear in output cells because the sanitizer
# emits them itself (pseudonym prefixes, preserved root forms). They are
# excluded from the leak check.
FORMAT_WORDS = frozenset(
    {"root", "entity", "domain", "example", "nsid", "mnt", "acc", "redacted"}
)

BOOLEAN_VALUES = frozenset({"", "true", "false", "0", "1", "t", "f", "yes", "no"})

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
TIER_RE = re.compile(r"-t[0-2]$")  # case-sensitive, like StripTierSuffix
TOKEN_SPLIT_RE = re.compile(r"[^0-9a-z]+")
LEAK_MIN_LEN = 4

# Hex lengths for keyed tokens. Long enough that collisions are negligible for
# millions of distinct values; collisions are still detected and reported.
HEX_LEN_LONG = 16
HEX_LEN_SHORT = 12


class SanitizeError(Exception):
    """Raised for bad input or a failed safety check."""


def canonical_column(header_cell):
    key = header_cell.strip().lower()
    if key in KNOWN_COLUMNS:
        return KNOWN_COLUMNS[key]
    return EXTRA_SAFE_COLUMNS.get(key)


def _tokens(value):
    """Lowercased alphanumeric tokens of value, used by the leak check."""
    return [t for t in TOKEN_SPLIT_RE.split(value.lower()) if len(t) >= LEAK_MIN_LEN]


# ---------------------------------------------------------------------------
# Timestamp rounding (only formats vault-csv-normalizer's ParseTime accepts)
# ---------------------------------------------------------------------------

_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})([T ])(\d{2}):(\d{2}):(\d{2})(\.\d+)?(.*)$"
)
_OFFSET_RE = re.compile(r"^([+-])(\d{2}):(\d{2})$")


def round_timestamp_to_day(value):
    """Truncate a parseable timestamp to midnight UTC, keeping its layout.

    Values the Go tool cannot parse (and date-only values) are returned
    unchanged. Timestamps with a numeric offset are converted to UTC first and
    emitted with a 'Z' suffix, so the UTC calendar date (and therefore the
    month bucket) is the same as in the original.
    """
    raw = value.strip()
    m = _TS_RE.match(raw)
    if not m:
        return value
    year, month, day, sep, hh, mi, ss, _frac, tail = m.groups()
    try:
        dt = datetime.datetime(int(year), int(month), int(day), int(hh), int(mi), int(ss))
    except ValueError:
        return value
    if sep == "T":
        if tail == "Z":
            new_tail = "Z"
        elif tail == "":
            new_tail = ""
        else:
            om = _OFFSET_RE.match(tail)
            if not om:
                return value
            sign, oh, omin = om.groups()
            if int(oh) > 23 or int(omin) > 59:
                return value
            offset = datetime.timedelta(hours=int(oh), minutes=int(omin))
            dt = dt - offset if sign == "+" else dt + offset
            new_tail = "Z"
    else:
        if tail not in ("Z", " +0000 UTC"):
            return value
        new_tail = tail
    return "%04d-%02d-%02d%s00:00:00%s" % (dt.year, dt.month, dt.day, sep, new_tail)


# ---------------------------------------------------------------------------
# Pseudonymization
# ---------------------------------------------------------------------------


class Sanitizer:
    """Keyed, consistent pseudonymization shared across all files in a run."""

    def __init__(self, salt, round_timestamps=False):
        if len(salt) < 16:
            raise SanitizeError("salt must be at least 16 bytes")
        self._salt = salt
        self.round_timestamps = round_timestamps
        self._cache = {}       # (category, original) -> pseudonym
        self._reverse = {}     # (category, pseudonym) -> original
        # Leak-check state (all lowercased).
        self.original_wholes = set()
        self.original_tokens = set()
        self.generated = set()  # generated pseudonyms and their tokens
        self.allowed = set(WELL_KNOWN_MOUNT_WORDS) | set(FORMAT_WORDS)
        self.allowed.update({"[root]"})

    # -- primitives ---------------------------------------------------------

    def _digest(self, category, value):
        msg = (category + "\x00" + value).encode("utf-8", "surrogateescape")
        return hmac.new(self._salt, msg, hashlib.sha256).hexdigest()

    def _record(self, category, original, pseudonym):
        prev = self._reverse.get((category, pseudonym))
        if prev is not None and prev != original:
            raise SanitizeError(
                "pseudonym collision in category %r; rerun with a different salt" % category
            )
        self._reverse[(category, pseudonym)] = original
        self._cache[(category, original)] = pseudonym
        low = original.lower()
        self.original_wholes.add(low)
        self.original_tokens.update(_tokens(low))
        plow = pseudonym.lower()
        self.generated.add(plow)
        self.generated.update(_tokens(plow))

    def _hashed(self, category, value, builder):
        key = (category, value)
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        pseudonym = builder(self._digest(category, value))
        self._record(category, value, pseudonym)
        return pseudonym

    @staticmethod
    def _uuid_from_hex(h):
        # UUID-shaped, with version 4 and RFC 4122 variant bits set.
        variant = "89ab"[int(h[16], 16) & 3]
        return "%s-%s-4%s-%s%s-%s" % (h[0:8], h[8:12], h[13:16], variant, h[17:20], h[20:32])

    def _preserve_word(self, word):
        """Keep a Vault vocabulary word as-is and mark it as allowed."""
        self.allowed.add(word.lower())
        return word

    # -- column policies ----------------------------------------------------

    def client_id(self, v):
        if UUID_RE.match(v):
            return self._hashed("client_id", v, self._uuid_from_hex)
        n = min(max(len(v), HEX_LEN_LONG), 64)
        return self._hashed("client_id", v, lambda h: h[:n])

    def entity_name(self, v):
        return self._hashed("entity_name", v, lambda h: "entity-" + h[:HEX_LEN_LONG])

    def namespace_id(self, v):
        if v.lower() == "root":
            return v
        return self._hashed("namespace_id", v, lambda h: "nsid-" + h[:HEX_LEN_SHORT])

    def namespace_path(self, v):
        if v == "[root]" or v.lower() == "root":
            return v
        hit = self._cache.get(("namespace_path", v))
        if hit is not None:
            return hit
        out = []
        for seg in v.split("/"):
            if seg == "":
                out.append(seg)
            else:
                out.append(self._hashed("ns_segment", seg, lambda h: "ns-" + h[:HEX_LEN_SHORT]))
        result = "/".join(out)
        self._record("namespace_path", v, result)
        return result

    def mount_path(self, v):
        hit = self._cache.get(("mount_path", v))
        if hit is not None:
            return hit
        out = []
        for seg in v.split("/"):
            if seg == "":
                out.append(seg)
            elif seg.lower() in WELL_KNOWN_MOUNT_WORDS:
                out.append(self._preserve_word(seg))
            else:
                out.append(self._hashed("mount_segment", seg, lambda h: "mnt-" + h[:HEX_LEN_SHORT]))
        result = "/".join(out)
        self._record("mount_path", v, result)
        return result

    def mount_accessor(self, v):
        key = ("mount_accessor", v)
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        h = self._digest("mount_accessor", v)
        parts = v.split("_")
        if len(parts) >= 2:
            prefix = []
            for part in parts[:-1]:
                if part.lower() in WELL_KNOWN_MOUNT_WORDS:
                    prefix.append(self._preserve_word(part))
                elif part == "":
                    prefix.append(part)
                else:
                    prefix.append(self._hashed("accessor_part", part, lambda d: "x" + d[:8]))
            n = min(max(len(parts[-1]), HEX_LEN_SHORT), 64)
            result = "_".join(prefix + [h[:n]])
        else:
            result = "acc_" + h[:HEX_LEN_SHORT]
        # PKI detection (prefix "auth_cert", case-insensitive) must not change.
        orig_pki = v.lower().startswith("auth_cert")
        if orig_pki != result.lower().startswith("auth_cert"):
            if orig_pki:
                result = self._preserve_word(v[:4]) + "_" + v[5:9] + "_" + h[:HEX_LEN_SHORT]
                self.allowed.add(v[5:9].lower())
            else:
                result = "acc_" + h[:HEX_LEN_SHORT]
        self._record("mount_accessor", v, result)
        return result

    def _alias_core(self, core):
        if core == "":
            return core
        if UUID_RE.match(core):
            return self._hashed("alias", core, self._uuid_from_hex)
        return self._hashed("alias", core, lambda h: "u" + h[:HEX_LEN_LONG])

    def alias(self, v):
        """Pseudonymize an alias while preserving BaseAlias/StripTierSuffix.

        alias = base ['@' domain]; base = core [tier]. The core is mapped with
        a keyed, case-sensitive hash shared by entity_alias_name and
        entity_alias_metadata.username, the tier suffix is kept literally, and
        the domain becomes a separate consistent token. Equality of the full
        alias, of BaseAlias(), and of StripTierSuffix(BaseAlias()) is preserved.
        """
        key = ("alias_full", v)
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        base, at, domain = v.partition("@")
        tier = ""
        if TIER_RE.search(base):
            base, tier = base[:-3], base[-3:]
        result = self._alias_core(base) + tier
        if at:
            if domain:
                result += "@" + self._hashed(
                    "domain", domain, lambda h: "domain-" + h[:HEX_LEN_SHORT] + ".example"
                )
            else:
                result += "@"
        self._record("alias_full", v, result)
        return result

    def sanitize_cell(self, policy, value):
        v = value.strip()
        if policy == "passthrough":
            low = v.lower()
            self.allowed.add(low)
            self.allowed.update(_tokens(low))
            return v
        if policy == "timestamp":
            low = v.lower()
            self.allowed.add(low)
            self.allowed.update(_tokens(low))
            return round_timestamp_to_day(v) if self.round_timestamps else v
        if policy == "boolean":
            if v.lower() in BOOLEAN_VALUES:
                return v
            return "redacted"
        if v == "":
            return v
        return getattr(self, policy)(v)

    def mapping_rows(self):
        for (category, original), pseudonym in sorted(self._cache.items()):
            yield category, original, pseudonym


# ---------------------------------------------------------------------------
# File processing
# ---------------------------------------------------------------------------


def _open_private(path):
    """Create or truncate path with mode 0600 and return a text file object."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8", newline="")


def _read_text(path):
    return open(path, "r", encoding="utf-8", errors="surrogateescape", newline="")


def plan_columns(headers, keep_extra):
    """Return (kept indices, policies for kept indices, dropped header names)."""
    kept, policies, dropped = [], [], []
    for i, h in enumerate(headers):
        canonical = canonical_column(h)
        if canonical is not None:
            kept.append(i)
            policies.append(POLICY[canonical])
        elif h.strip().lower() in keep_extra:
            kept.append(i)
            policies.append("kept")
        else:
            dropped.append(h)
    return kept, policies, dropped


def _raise_field_limit():
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


def sanitize_file(sanitizer, in_path, out_path, keep_extra, log=None):
    """Sanitize one CSV, verify it, and atomically move it into place."""
    if log is None:
        log = sys.stderr
    started = time.monotonic()
    with _read_text(in_path) as f:
        first = f.readline()
        if not first.strip():
            raise SanitizeError("%s: file is empty or has no header row" % in_path)
        has_bom = first.startswith("﻿")
        if has_bom:
            first = first[1:]
        terminator = "\r\n" if first.endswith("\r\n") else "\n"
        reader = csv.reader(itertools.chain([first], f), skipinitialspace=True, strict=False)
        try:
            headers = next(reader)
        except csv.Error as e:
            raise SanitizeError("%s: cannot parse header: %s" % (in_path, e))
        canon = {canonical_column(h) for h in headers}
        if "client_id" not in canon:
            raise SanitizeError(
                "%s: required column 'client_id' not found; is this a Vault client export?" % in_path
            )
        kept, policies, dropped = plan_columns(headers, keep_extra)
        if dropped:
            log.write(
                "%s: dropping %d unrecognized column(s) (may contain customer data): %s\n"
                % (in_path, len(dropped), ", ".join(h.strip() for h in dropped))
            )
            log.write("%s: dropped columns are also removed from the header; use "
                      "--keep-columns to pass specific columns through unchanged\n" % in_path)
        out_dir = os.path.dirname(os.path.abspath(out_path))
        fd, tmp_path = tempfile.mkstemp(prefix=".sanitize-", suffix=".csv", dir=out_dir)
        rows_in = 0
        extra_fields_rows = 0
        try:
            with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape", newline="") as out:
                if has_bom:
                    out.write("﻿")
                writer = csv.writer(out, lineterminator=terminator)
                writer.writerow([headers[i] for i in kept])
                n_header = len(headers)
                try:
                    for row in reader:
                        if not row:
                            continue  # blank line; the Go csv reader skips these too
                        rows_in += 1
                        if len(row) > n_header:
                            extra_fields_rows += 1
                        out_row = []
                        for i, policy in zip(kept, policies):
                            if i >= len(row):
                                break  # short row: keep it short
                            if policy == "kept":
                                out_row.append(row[i])
                            else:
                                out_row.append(sanitizer.sanitize_cell(policy, row[i]))
                        writer.writerow(out_row)
                except csv.Error as e:
                    raise SanitizeError("%s: CSV parse error near data row %d: %s"
                                        % (in_path, rows_in + 1, e))
            if extra_fields_rows:
                log.write("%s: %d row(s) had more fields than the header; extra fields "
                          "were dropped\n" % (in_path, extra_fields_rows))
            rows_out = verify_output(sanitizer, tmp_path, [headers[i] for i in kept])
            if rows_out != rows_in:
                raise SanitizeError("%s: row count mismatch (input %d, output %d)"
                                    % (in_path, rows_in, rows_out))
            # mkstemp creates 0600; give the shareable output normal permissions.
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(tmp_path, 0o666 & ~umask)
            os.replace(tmp_path, out_path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    elapsed = time.monotonic() - started
    size = os.path.getsize(in_path)
    log.write("%s -> %s: %d data rows, %d columns kept, %d dropped, %.2fs (%.1f MB/s)\n"
              % (in_path, out_path, rows_in, len(kept), len(dropped), elapsed,
                 size / 1e6 / elapsed if elapsed > 0 else 0.0))
    return rows_in


def verify_output(sanitizer, path, out_headers):
    """Re-scan a sanitized file for original values. Returns the data row count.

    Each output cell is checked as a whole and as alphanumeric tokens (split on
    '/', '@', '-', '_', '.', whitespace and other punctuation) against the set
    of original values seen in pseudonymized columns. Vault vocabulary,
    passthrough column values and tokens the sanitizer generated itself are
    exempt. Offending values are never printed, only their location.
    """
    wholes = sanitizer.original_wholes
    tokens = sanitizer.original_tokens
    exempt_allowed = sanitizer.allowed
    exempt_generated = sanitizer.generated
    leaks = []
    rows = 0
    with open(path, "r", encoding="utf-8", errors="surrogateescape", newline="") as f:
        reader = csv.reader(f, skipinitialspace=True, strict=False)
        next(reader, None)  # header
        for row in reader:
            if not row:
                continue
            rows += 1
            for col, cell in enumerate(row):
                low = cell.strip().lower()
                if not low:
                    continue
                if (low in wholes and len(low) >= LEAK_MIN_LEN
                        and low not in exempt_allowed and low not in exempt_generated):
                    leaks.append((rows, col))
                    continue
                for tok in TOKEN_SPLIT_RE.split(low):
                    if (len(tok) >= LEAK_MIN_LEN and tok in tokens
                            and tok not in exempt_allowed and tok not in exempt_generated):
                        leaks.append((rows, col))
                        break
            if len(leaks) > 1000:
                break
    if leaks:
        where = ", ".join(
            "row %d column %r" % (r, out_headers[c] if c < len(out_headers) else c)
            for r, c in leaks[:10]
        )
        raise SanitizeError(
            "leak check FAILED: %d cell(s) still contain an original value (%s%s). "
            "The output file was deleted. If a --keep-columns column is listed, it "
            "shares values with pseudonymized columns; drop it."
            % (len(leaks), where, ", ..." if len(leaks) > 10 else "")
        )
    return rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def load_salt(path):
    try:
        st = os.stat(path)
        with open(path, "rb") as f:
            data = f.read().strip()
    except OSError as e:
        raise SanitizeError("cannot read salt file %s: %s" % (path, e))
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        sys.stderr.write("warning: salt file %s is readable by group/other; "
                         "chmod 600 it\n" % path)
    try:
        salt = bytes.fromhex(data.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        salt = data
    if len(salt) < 16:
        raise SanitizeError("salt file %s must contain at least 16 bytes (32 hex chars)" % path)
    return salt


def save_salt(path, salt):
    with _open_private(path) as f:
        f.write(salt.hex() + "\n")


def output_paths(inputs, out):
    if len(inputs) == 1 and not os.path.isdir(out) and not out.endswith(os.sep):
        return [out]
    os.makedirs(out, exist_ok=True)
    paths = []
    for p in inputs:
        base = os.path.basename(p)
        stem = base[:-4] if base.lower().endswith(".csv") else base
        paths.append(os.path.join(out, stem + ".sanitized.csv"))
    return paths


def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="sanitize_csv.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Sanitize Vault client-activity export CSVs for sharing.\n\n"
            "Identifiers (client_id, entity_name, alias names, metadata usernames,\n"
            "namespace paths/IDs, mount paths, mount accessors) are replaced with\n"
            "keyed HMAC-SHA256 pseudonyms. Equality, blankness, alias '@' domain\n"
            "splits, -t0/-t1/-t2 tier suffixes, the auth_cert accessor prefix, root\n"
            "namespace forms and well-known mount type names are preserved, so\n"
            "vault-csv-normalizer reports the same counts, dedup results, PKI\n"
            "partition, abandoned-client counts and monthly output.\n\n"
            "mount_type, auth_method, client_type and timestamps pass through.\n"
            "Unrecognized columns are dropped unless named in --keep-columns.\n"
            "Each output is re-scanned for original values before it is kept."
        ),
        epilog=(
            "examples:\n"
            "  sanitize_csv.py export.csv -o export.sanitized.csv\n"
            "  sanitize_csv.py jan.csv feb.csv -o out/ --save-salt customer.salt\n"
            "  sanitize_csv.py mar.csv -o out/ --salt-file customer.salt\n\n"
            "Use the same salt for every file from one customer so values map\n"
            "consistently across files. Keep the salt secret: anyone holding the\n"
            "salt can confirm guesses of original values."
        ),
    )
    p.add_argument("inputs", nargs="+", metavar="INPUT.csv", help="Vault client export CSV file(s)")
    p.add_argument("-o", "--output", required=True, metavar="OUTPUT",
                   help="output directory (files are written as <name>.sanitized.csv), "
                        "or an output file path when there is a single input")
    p.add_argument("--salt-file", metavar="PATH",
                   help="read the secret salt from PATH (hex or raw, at least 16 bytes); "
                        "required to map several runs consistently")
    p.add_argument("--save-salt", metavar="PATH",
                   help="save the generated salt to PATH (mode 0600) for later runs")
    p.add_argument("--mapping-out", metavar="PATH",
                   help="write a reversible original->pseudonym mapping CSV to PATH "
                        "(mode 0600). SENSITIVE: it contains every original value")
    p.add_argument("--keep-columns", metavar="a,b", default="",
                   help="comma-separated unrecognized columns to pass through unchanged")
    p.add_argument("--round-timestamps-to-day", action="store_true",
                   help="truncate parseable timestamps to midnight UTC (month buckets are "
                        "unchanged; --since results can shift by up to one day)")
    return p


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    _raise_field_limit()
    try:
        for path in args.inputs:
            if not os.path.isfile(path):
                raise SanitizeError("input file not found: %s" % path)
        if args.salt_file and args.save_salt:
            raise SanitizeError("--save-salt is only valid when the salt is generated "
                                "(without --salt-file)")
        salt = load_salt(args.salt_file) if args.salt_file else secrets.token_bytes(32)
        if not args.salt_file:
            if args.save_salt:
                save_salt(args.save_salt, salt)
                sys.stderr.write("salt saved to %s (mode 0600); keep it secret\n" % args.save_salt)
            elif len(args.inputs) == 1:
                sys.stderr.write("note: a random salt was used; pass --save-salt to sanitize "
                                 "other files from this customer consistently later\n")
        keep_extra = set()
        for name in args.keep_columns.split(","):
            name = name.strip().lower()
            if not name:
                continue
            if canonical_column(name) is not None:
                sys.stderr.write("warning: --keep-columns %s ignored: it is a recognized "
                                 "column and is always sanitized\n" % name)
                continue
            keep_extra.add(name)

        outputs = output_paths(args.inputs, args.output)
        in_real = {os.path.realpath(p) for p in args.inputs}
        for o in outputs:
            if os.path.realpath(o) in in_real:
                raise SanitizeError("output %s would overwrite an input file" % o)
        if len(set(map(os.path.realpath, outputs))) != len(outputs):
            raise SanitizeError("two inputs share a base name; their outputs would collide")

        sanitizer = Sanitizer(salt, round_timestamps=args.round_timestamps_to_day)
        for in_path, out_path in zip(args.inputs, outputs):
            sanitize_file(sanitizer, in_path, out_path, keep_extra)

        if args.mapping_out:
            with _open_private(args.mapping_out) as f:
                w = csv.writer(f)
                w.writerow(["category", "original", "pseudonym"])
                for row in sanitizer.mapping_rows():
                    w.writerow(row)
            sys.stderr.write(
                "WARNING: %s contains every ORIGINAL identifier and reverses the "
                "sanitization. Treat it as confidential customer data; never share it "
                "alongside the sanitized files.\n" % args.mapping_out
            )
    except SanitizeError as e:
        sys.stderr.write("error: %s\n" % e)
        return 1
    except OSError as e:
        sys.stderr.write("error: %s\n" % e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
