#!/usr/bin/env python3
"""Unit tests for sanitize_csv.py. Run: python3 scripts/test_sanitize_csv.py"""

import csv
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sanitize_csv as sc  # noqa: E402

SALT_A = bytes(range(32))
SALT_B = bytes(range(1, 33))

# Legacy names (alias_name, namespace, mount, type, timestamp) mixed with
# current names, a BOM, an unknown column, and one short row.
HEADER = ("﻿client_id,entity_name,alias_name,entity_alias_metadata.username,"
          "namespace_id,namespace,mount_accessor,mount,mount_type,type,timestamp,secret_note")
ROWS = [
    # 0 LDAP alice
    "c-0001-alice-ldap,alice-entity,alice,,root,[root],auth_ldap_1a2b3c4d,auth/ldap/,ldap,entity,2024-01-05T08:12:34Z,hunter2-note",
    # 1 LDAP alice-t0 (tier suffix)
    "c-0002-alice-t0,alice-entity,alice-t0,,root,[root],auth_ldap_1a2b3c4d,auth/ldap/,ldap,entity,2024-01-06T08:12:34Z,note-two",
    # 2 JWT alice@corp.com
    "c-0003-alice-jwt,,alice@corp.com,,abc12,engineering/,auth_jwt_9f8e7d6c,auth/jwt-corp/,jwt,entity,2024-02-01T00:00:00-05:00,x",
    # 3 LDAP Alice (different case)
    "c-0004-Alice,,Alice,,abc12,engineering/,auth_ldap_1a2b3c4d,auth/ldap/,ldap,entity,2024-02-02T10:00:00Z,x",
    # 4 OIDC with blank alias and metadata username
    "c-0005-oidc-blank,,,alice,def34,engineering/team-a/,auth_oidc_55aa66bb,auth/oidc/,oidc,entity,2024-02-03T10:00:00Z,x",
    # 5 OIDC with UUID subject alias and metadata username
    "c-0006-oidc-sub,,0f8fad5b-d9cb-469f-a165-70867728950e,alice,def34,engineering/team-a/,auth_oidc_55aa66bb,auth/oidc/,oidc,entity,2024-02-03T11:00:00Z,x",
    # 6 abandoned entity: blank entity name and alias, blank mount
    "c-0007-abandoned,,,,root,,,,,entity,2024-03-01T00:00:00Z,x",
    # 7 cert auth (PKI by accessor prefix)
    "c-0008-cert,certbox-entity,certbox.corp.com,,root,[root],auth_cert_77cc88dd,auth/cert/,cert,entity,2024-03-02T00:00:00Z,x",
    # 8 ACME client
    "0f8fad5b-d9cb-469f-a165-70867728950f,,,,root,root,,pki_int/,pki,pki-acme,2024-03-03T00:00:00Z,x",
    # 9 short row (trailing columns missing)
    "c-0010-short,shorty-entity,bob@corp.com,,root,[root],auth_ldap_1a2b3c4d",
    # 10 same client as row 0 (duplicate client id)
    "c-0001-alice-ldap,alice-entity,alice,,root,[root],auth_ldap_1a2b3c4d,auth/ldap/,ldap,entity,2024-01-07T08:12:34Z,x",
]
ORIGINAL_SECRETS = [
    "c-0001-alice-ldap", "alice-entity", "alice", "Alice", "corp.com", "abc12",
    "def34", "engineering", "team-a", "1a2b3c4d", "9f8e7d6c", "jwt-corp",
    "0f8fad5b-d9cb-469f-a165-70867728950e", "certbox", "77cc88dd", "pki_int",
    "shorty-entity", "hunter2-note", "c-0010-short",
]


def write(path, header=HEADER, rows=ROWS):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(header + "\n" + "\n".join(rows) + "\n")


def read(path):
    with open(path, "r", encoding="utf-8", newline="") as f:
        text = f.read()
    rows = list(csv.reader(io.StringIO(text.lstrip("﻿"))))
    return text, rows[0], rows[1:]


class SanitizeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.log = io.StringIO()

    def tearDown(self):
        self.tmp.cleanup()

    def run_one(self, salt=SALT_A, name="in.csv", rows=ROWS, keep=(), sanitizer=None, **kw):
        src = os.path.join(self.dir, name)
        write(src, rows=rows)
        dst = os.path.join(self.dir, name + ".out")
        s = sanitizer or sc.Sanitizer(salt, **kw)
        sc.sanitize_file(s, src, dst, set(keep), log=self.log)
        return read(dst)

    def col(self, header, name):
        return header.index(name)

    def test_bom_and_header_preserved_unknown_dropped(self):
        text, header, rows = self.run_one()
        self.assertTrue(text.startswith("﻿"))
        self.assertNotIn("secret_note", header)
        self.assertEqual(header[:3], ["client_id", "entity_name", "alias_name"])
        self.assertIn("secret_note", self.log.getvalue())
        self.assertEqual(len(rows), len(ROWS))

    def test_keep_columns(self):
        _, header, _ = self.run_one(rows=[r.replace("hunter2-note", "zz") for r in ROWS],
                                    keep={"secret_note"})
        self.assertIn("secret_note", header)

    def test_alias_relationships(self):
        _, h, rows = self.run_one()
        a = self.col(h, "alias_name")
        u = self.col(h, "entity_alias_metadata.username")
        alice, alice_t0, alice_jwt, cap_alice = rows[0][a], rows[1][a], rows[2][a], rows[3][a]
        # Tier suffix kept literally; StripTierSuffix(alice-t0) == alice.
        self.assertTrue(alice_t0.endswith("-t0"))
        self.assertEqual(alice_t0[:-3], alice)
        # BaseAlias(alice@corp.com) == alice.
        self.assertIn("@", alice_jwt)
        self.assertEqual(alice_jwt.split("@", 1)[0], alice)
        self.assertNotIn("corp", alice_jwt)
        # Case difference preserved.
        self.assertNotEqual(cap_alice, alice)
        # Metadata username equals the LDAP alias.
        self.assertEqual(rows[4][u], alice)
        self.assertEqual(rows[5][u], alice)
        # Blank alias stays blank; UUID subject becomes a different UUID.
        self.assertEqual(rows[4][a], "")
        self.assertTrue(sc.UUID_RE.match(rows[5][a]))
        self.assertNotEqual(rows[5][a], "0f8fad5b-d9cb-469f-a165-70867728950e")

    def test_blanks_and_root_forms_preserved(self):
        _, h, rows = self.run_one()
        en, ns, nsid, mp, ma = (self.col(h, c) for c in
                                ("entity_name", "namespace", "namespace_id", "mount", "mount_accessor"))
        self.assertEqual(rows[2][en], "")
        self.assertEqual(rows[6][en], "")
        self.assertEqual(rows[6][mp], "")
        self.assertEqual(rows[6][ma], "")
        self.assertEqual(rows[6][ns], "")
        self.assertEqual(rows[0][ns], "[root]")
        self.assertEqual(rows[8][ns], "root")
        self.assertEqual(rows[0][nsid], "root")
        self.assertTrue(rows[0][en])

    def test_namespace_hierarchy(self):
        _, h, rows = self.run_one()
        ns = self.col(h, "namespace")
        parent, child = rows[2][ns], rows[4][ns]
        self.assertTrue(parent.endswith("/"))
        self.assertTrue(child.startswith(parent))
        self.assertEqual(child.count("/"), 2)
        self.assertNotIn("engineering", child)

    def test_mount_path_and_accessor_structure(self):
        _, h, rows = self.run_one()
        mp, ma = self.col(h, "mount"), self.col(h, "mount_accessor")
        self.assertEqual(rows[0][mp], "auth/ldap/")
        self.assertTrue(rows[2][mp].startswith("auth/mnt-"))
        self.assertTrue(rows[8][mp].endswith("/"))
        self.assertTrue(rows[7][ma].startswith("auth_cert_"))
        self.assertNotEqual(rows[7][ma], "auth_cert_77cc88dd")
        self.assertTrue(rows[0][ma].startswith("auth_ldap_"))
        self.assertEqual(rows[0][ma], rows[1][ma])
        self.assertNotEqual(rows[0][ma], rows[4][ma])

    def test_passthrough_and_client_ids(self):
        _, h, rows = self.run_one()
        cid, ty, mt, ts = (self.col(h, c) for c in ("client_id", "type", "mount_type", "timestamp"))
        self.assertEqual(rows[8][ty], "pki-acme")
        self.assertEqual(rows[2][mt], "jwt")
        self.assertEqual(rows[0][ts], "2024-01-05T08:12:34Z")
        self.assertEqual(rows[0][cid], rows[10][cid])
        self.assertNotEqual(rows[0][cid], rows[1][cid])
        self.assertTrue(sc.UUID_RE.match(rows[8][cid]))

    def test_short_row_kept_short(self):
        _, h, rows = self.run_one()
        self.assertEqual(len(rows[9]), 7)

    def test_round_timestamps(self):
        _, h, rows = self.run_one(round_timestamps=True)
        ts = self.col(h, "timestamp")
        self.assertEqual(rows[0][ts], "2024-01-05T00:00:00Z")
        # -05:00 offset: UTC date is 2024-02-01.
        self.assertEqual(rows[2][ts], "2024-02-01T00:00:00Z")
        self.assertEqual(sc.round_timestamp_to_day("2024-01-31T23:30:00-05:00"), "2024-02-01T00:00:00Z")
        self.assertEqual(sc.round_timestamp_to_day("2024-01-05 08:00:00 +0000 UTC"),
                         "2024-01-05 00:00:00 +0000 UTC")
        self.assertEqual(sc.round_timestamp_to_day("1706745600"), "1706745600")
        self.assertEqual(sc.round_timestamp_to_day("2024-01-05"), "2024-01-05")

    def test_same_salt_consistent_across_files(self):
        s = sc.Sanitizer(SALT_A)
        _, h, r1 = self.run_one(name="a.csv", sanitizer=s)
        _, _, r2 = self.run_one(name="b.csv", sanitizer=s)
        self.assertEqual(r1, r2)
        _, _, r3 = self.run_one(name="c.csv", salt=SALT_A)  # fresh run, same salt
        self.assertEqual(r1, r3)

    def test_different_salt_differs(self):
        _, h, r1 = self.run_one(name="a.csv", salt=SALT_A)
        _, _, r2 = self.run_one(name="b.csv", salt=SALT_B)
        cid = self.col(h, "client_id")
        self.assertNotEqual(r1[0][cid], r2[0][cid])
        self.assertNotEqual(r1[0][self.col(h, "alias_name")], r2[0][self.col(h, "alias_name")])

    def test_no_original_value_remains(self):
        text, _, _ = self.run_one()
        body = text.split("\n", 1)[1]
        for secret in ORIGINAL_SECRETS:
            self.assertNotIn(secret, body, secret)

    def test_leak_check_fails_and_removes_output(self):
        rows = [r.replace(",hunter2-note", ",alice-entity") for r in ROWS]
        src = os.path.join(self.dir, "leak.csv")
        write(src, rows=rows)
        dst = os.path.join(self.dir, "leak.out")
        with self.assertRaises(sc.SanitizeError):
            sc.sanitize_file(sc.Sanitizer(SALT_A), src, dst, {"secret_note"}, log=self.log)
        self.assertFalse(os.path.exists(dst))
        self.assertEqual([f for f in os.listdir(self.dir) if f.startswith(".sanitize-")], [])

    def test_missing_client_id_rejected(self):
        src = os.path.join(self.dir, "bad.csv")
        write(src, header="foo,bar", rows=["1,2"])
        with self.assertRaises(sc.SanitizeError):
            sc.sanitize_file(sc.Sanitizer(SALT_A), src, src + ".out", set(), log=self.log)

    def test_cli(self):
        src = os.path.join(self.dir, "x.csv")
        write(src)
        out = os.path.join(self.dir, "out")
        salt = os.path.join(self.dir, "salt")
        mapping = os.path.join(self.dir, "map.csv")
        err = io.StringIO()
        old = sys.stderr
        sys.stderr = err
        try:
            rc = sc.main([src, "-o", out + os.sep, "--save-salt", salt, "--mapping-out", mapping, "--keep-filenames"])
            rc2 = sc.main([os.path.join(self.dir, "missing.csv"), "-o", out])
        finally:
            sys.stderr = old
        self.assertEqual(rc, 0)
        self.assertNotEqual(rc2, 0)
        self.assertTrue(os.path.exists(os.path.join(out, "x.sanitized.csv")))
        self.assertEqual(os.stat(salt).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(mapping).st_mode & 0o777, 0o600)
        self.assertIn("WARNING", err.getvalue())


class FilenameTests(unittest.TestCase):
    """Output file name pseudonyms. Known-answer values are shared with
    internal/sanitizer/filename_test.go so the two ports stay in step."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.salt = os.path.join(self.dir, "salt.hex")
        with open(self.salt, "w") as f:
            f.write(SALT_A.hex() + "\n")
        os.chmod(self.salt, 0o600)

    def tearDown(self):
        self.tmp.cleanup()

    def main(self, argv):
        err = io.StringIO()
        old = sys.stderr
        sys.stderr = err
        try:
            rc = sc.main(argv)
        finally:
            sys.stderr = old
        return rc, err.getvalue()

    def filename_rows(self, mapping):
        with open(mapping, newline="") as f:
            return [r for r in csv.reader(f) if r and r[0] == "filename"]

    def test_filename_pseudonym(self):
        import hashlib
        import hmac
        s = sc.Sanitizer(SALT_A)
        want = "export-" + hmac.new(SALT_A, b"filename\x00acme-export", hashlib.sha256).hexdigest()[:12]
        self.assertEqual(s.filename("acme-export"), want)
        self.assertEqual(want, "export-9e4ebd54df0c")
        self.assertEqual(s.filename("Acme-Export"), "export-25d317be975f")  # case-sensitive
        self.assertNotEqual(sc.Sanitizer(SALT_B).filename("acme-export"), want)
        self.assertEqual(s.original_wholes, set())
        self.assertEqual(s.original_tokens, set())

    def test_derived_names_pseudonymized(self):
        a = os.path.join(self.dir, "acme-export.csv")
        b = os.path.join(self.dir, "x.CSV")
        write(a)
        write(b)
        out = os.path.join(self.dir, "out")
        keep = os.path.join(self.dir, "keep")
        mapping = os.path.join(self.dir, "map.csv")
        rc, err = self.main([a, b, "-o", out, "--salt-file", self.salt, "--mapping-out", mapping])
        self.assertEqual(rc, 0, err)
        want = ["export-9e4ebd54df0c.sanitized.csv", "export-daa4318cd009.sanitized.csv"]
        self.assertEqual(sorted(os.listdir(out)), want)
        self.assertIn(a + " -> " + os.path.join(out, want[0]) + ": 11 data rows", err)
        rc, err = self.main([a, b, "-o", keep, "--salt-file", self.salt, "--keep-filenames"])
        self.assertEqual(rc, 0, err)
        for p, k in zip(want, ["acme-export.sanitized.csv", "x.sanitized.csv"]):
            with open(os.path.join(out, p), "rb") as f1, open(os.path.join(keep, k), "rb") as f2:
                self.assertEqual(f1.read(), f2.read())
        self.assertEqual(self.filename_rows(mapping), [
            ["filename", "acme-export", "export-9e4ebd54df0c"],
            ["filename", "x", "export-daa4318cd009"],
        ])

    def test_single_input_to_directory_pseudonymized(self):
        src = os.path.join(self.dir, "acme-export.csv")
        write(src)
        out = os.path.join(self.dir, "out")
        rc, err = self.main([src, "-o", out + os.sep, "--salt-file", self.salt])
        self.assertEqual(rc, 0, err)
        self.assertEqual(os.listdir(out), ["export-9e4ebd54df0c.sanitized.csv"])

    def test_explicit_output_file_name_kept(self):
        src = os.path.join(self.dir, "acme-export.csv")
        write(src)
        dst = os.path.join(self.dir, "my-choice.csv")
        mapping = os.path.join(self.dir, "map.csv")
        rc, err = self.main([src, "-o", dst, "--salt-file", self.salt, "--mapping-out", mapping])
        self.assertEqual(rc, 0, err)
        self.assertTrue(os.path.isfile(dst))
        self.assertEqual(self.filename_rows(mapping), [])

    def test_keep_filenames(self):
        a = os.path.join(self.dir, "acme-export.csv")
        b = os.path.join(self.dir, "x.CSV")
        write(a)
        write(b)
        out = os.path.join(self.dir, "out")
        mapping = os.path.join(self.dir, "map.csv")
        rc, err = self.main([a, b, "-o", out, "--salt-file", self.salt, "--keep-filenames",
                             "--mapping-out", mapping])
        self.assertEqual(rc, 0, err)
        self.assertEqual(sorted(os.listdir(out)), ["acme-export.sanitized.csv", "x.sanitized.csv"])
        self.assertEqual(self.filename_rows(mapping), [])

    def test_output_name_collision(self):
        for extra in ([], ["--keep-filenames"]):
            with self.subTest(extra=extra):
                base = tempfile.mkdtemp(dir=self.dir)
                a = os.path.join(base, "a", "same.csv")
                b = os.path.join(base, "b", "same.csv")
                for p in (a, b):
                    os.makedirs(os.path.dirname(p))
                    write(p)
                out = os.path.join(base, "out")
                saved = os.path.join(base, "saved.salt")
                mapping = os.path.join(base, "map.csv")
                rc, err = self.main([a, b, "-o", out, "--save-salt", saved,
                                     "--mapping-out", mapping] + extra)
                self.assertEqual(rc, 1)
                self.assertIn(a, err)
                self.assertIn(b, err)
                for p in (out, saved, mapping):
                    self.assertFalse(os.path.exists(p), p)



def fs_is_case_insensitive(directory):
    """Whether directory's filesystem folds case, via a probe file that is
    independent of the code under test."""
    p = os.path.join(directory, "CaseProbe")
    open(p, "w").close()
    try:
        return os.path.exists(os.path.join(directory, "caseprobe"))
    finally:
        os.remove(p)


class CollisionTests(unittest.TestCase):
    """Write-target collision checks, salt validation and CLI exit codes.
    Mirrors internal/sanitizer/collision_test.go so the two ports stay in step."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.src = os.path.join(self.dir, "jan.csv")
        write(self.src)
        with open(self.src, "rb") as f:
            self.src_bytes = f.read()
        self.out = os.path.join(self.dir, "out")
        self.saved = os.path.join(self.dir, "saved.salt")

    def tearDown(self):
        self.tmp.cleanup()

    def main(self, argv):
        err = io.StringIO()
        old = sys.stderr
        sys.stderr = err
        try:
            rc = sc.main(argv)
        finally:
            sys.stderr = old
        return rc, err.getvalue()

    def assert_rejected(self, argv, mention=(), absent=()):
        rc, err = self.main(argv)
        self.assertEqual(rc, 1, err)
        self.assertIn("error: ", err)
        for m in mention:
            self.assertIn(m, err)
        for p in absent:
            self.assertFalse(os.path.exists(p), "%s was written despite the error" % p)

    def assert_src_unchanged(self):
        with open(self.src, "rb") as f:
            self.assertEqual(f.read(), self.src_bytes)

    def write_salt(self, content, name="salt.hex"):
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(p, 0o600)
        return p

    def test_mapping_out_equals_input(self):
        self.assert_rejected(
            [self.src, "-o", self.out + os.sep, "--save-salt", self.saved, "--mapping-out", self.src],
            ["--mapping-out", self.src, "input"], [self.out, self.saved])
        self.assert_src_unchanged()

    def test_mapping_out_equals_output(self):
        shared = os.path.join(self.dir, "shared.csv")
        self.assert_rejected(
            [self.src, "-o", shared, "--save-salt", self.saved, "--mapping-out", shared],
            ["--mapping-out", shared, "output"], [shared, self.saved])
        # Derived output name inside a directory, reached by a different spelling.
        salt = self.write_salt(SALT_A.hex() + "\n")
        src2 = os.path.join(self.dir, "acme-export.csv")
        write(src2)
        name = "export-9e4ebd54df0c.sanitized.csv"
        alias = self.out + os.sep + "." + os.sep + name
        self.assert_rejected(
            [src2, "-o", self.out + os.sep, "--salt-file", salt, "--mapping-out", alias],
            ["--mapping-out", os.path.join(self.out + os.sep, name)], [self.out])

    def test_save_salt_equals_input(self):
        mapping = os.path.join(self.dir, "jan.mapping.csv")
        self.assert_rejected(
            [self.src, "-o", self.out + os.sep, "--save-salt", self.src, "--mapping-out", mapping],
            ["--save-salt", self.src, "input"], [self.out, mapping])
        self.assert_src_unchanged()

    def test_mapping_out_equals_save_salt(self):
        both = os.path.join(self.dir, "both.salt")
        self.assert_rejected(
            [self.src, "-o", self.out + os.sep, "--save-salt", both, "--mapping-out", both],
            ["--save-salt " + both, "--mapping-out " + both], [self.out, both])

    def test_case_only_collision(self):
        if not fs_is_case_insensitive(self.dir):
            self.skipTest("filesystem is case-sensitive")
        upper = os.path.join(self.dir, "JAN.csv")
        self.assert_rejected([self.src, "-o", upper, "--save-salt", self.saved],
                             [upper, "input"], [self.saved])
        self.assert_src_unchanged()
        a = os.path.join(self.dir, "a", "Jan.csv")
        b = os.path.join(self.dir, "b", "jan.csv")
        for p in (a, b):
            os.makedirs(os.path.dirname(p))
            write(p)
        self.assert_rejected([a, b, "-o", self.out, "--keep-filenames", "--save-salt", self.saved],
                             [a, b], [self.out, self.saved])
        x = os.path.join(self.dir, "x.csv")
        self.assert_rejected(
            [self.src, "-o", x, "--save-salt", self.saved, "--mapping-out", os.path.join(self.dir, "X.csv")],
            ["--mapping-out", x], [x, self.saved])

    def test_case_insensitive_fs_probe_agrees_with_os(self):
        r = os.path.realpath(self.dir)
        self.assertEqual(sc._case_insensitive_fs(os.path.join(r, "missing", "file.csv")),
                         fs_is_case_insensitive(self.dir))

    def test_load_salt_edge_cases(self):
        want16 = bytes.fromhex("00112233445566778899aabbccddeeff")
        cases = [
            ("short hex", "00112233445566778899aabbccddee\n", None),
            ("short raw", "not-hex-short\n", None),
            ("raw 16+ non-hex", "this is not hex at all!\n", b"this is not hex at all!"),
            ("whitespace between hex pairs", "0011 2233\t4455 6677\n8899 aabb ccdd eeff\n", want16),
            ("whitespace splitting a pair is raw", "001 122334455667788 99aabbccddeeff",
             b"001 122334455667788 99aabbccddeeff"),
            ("odd-length hex is raw", "00112233445566778899aabbccddeeff0",
             b"00112233445566778899aabbccddeeff0"),
            ("uppercase hex", "  00112233445566778899AABBCCDDEEFF  \n", want16),
            ("non-ascii raw", "s\u00e4lzchen-s\u00e4lzchen", "s\u00e4lzchen-s\u00e4lzchen".encode("utf-8")),
        ]
        for i, (name, content, want) in enumerate(cases):
            with self.subTest(name=name):
                p = self.write_salt(content, "salt%d" % i)
                if want is None:
                    with self.assertRaises(sc.SanitizeError) as cm:
                        sc.load_salt(p)
                    self.assertIn("at least 16 bytes", str(cm.exception))
                else:
                    self.assertEqual(sc.load_salt(p), want)

    def test_short_salt_rejected(self):
        salt = self.write_salt(bytes(8).hex(), "short.salt")
        self.assert_rejected([self.src, "-o", self.out + os.sep, "--salt-file", salt],
                             [salt, "at least 16 bytes"], [self.out])

    def test_save_salt_with_salt_file(self):
        salt = self.write_salt(SALT_A.hex() + "\n")
        self.assert_rejected(
            [self.src, "-o", self.out + os.sep, "--salt-file", salt, "--save-salt", self.saved],
            ["--save-salt is only valid"], [self.out, self.saved])

    def test_missing_required_args_exit_2(self):
        for argv, want in (
            ([self.src], "required: -o/--output"),
            (["-o", self.out], "required: INPUT.csv"),
            ([], "required: INPUT.csv, -o/--output"),
            ([self.src, "--no-such-flag", "-o", self.out], "no-such-flag"),
        ):
            with self.subTest(argv=argv):
                err = io.StringIO()
                old = sys.stderr
                sys.stderr = err
                try:
                    with self.assertRaises(SystemExit) as cm:
                        sc.main(argv)
                finally:
                    sys.stderr = old
                self.assertEqual(cm.exception.code, 2)
                self.assertIn(want, err.getvalue())
        self.assertFalse(os.path.exists(self.out))

if __name__ == "__main__":
    unittest.main()
