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
            rc = sc.main([src, "-o", out + os.sep, "--save-salt", salt, "--mapping-out", mapping])
            rc2 = sc.main([os.path.join(self.dir, "missing.csv"), "-o", out])
        finally:
            sys.stderr = old
        self.assertEqual(rc, 0)
        self.assertNotEqual(rc2, 0)
        self.assertTrue(os.path.exists(os.path.join(out, "x.sanitized.csv")))
        self.assertEqual(os.stat(salt).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(mapping).st_mode & 0o777, 0o600)
        self.assertIn("WARNING", err.getvalue())


if __name__ == "__main__":
    unittest.main()
