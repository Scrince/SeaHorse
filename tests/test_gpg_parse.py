from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from gpg_backend.manager import GpgError, GpgManager


COLON_LISTING = """
sec:u:256:22:A1B2C3D4E5F60718:1700000000:::u:::cESCA:::ed25519:0:
fpr:::::::::0123456789ABCDEF0123456789ABCDEF01234567:
uid:u::::1700000000::ABCDHASH::Alice Example <alice@example.com>:
ssb:u:256:18:1111222233334444:1700000000::::::e:::cv25519:0:
fpr:::::::::AAAABBBBCCCCDDDDEEEEFFFF0000111122223333:
pub:u:256:22:DEADBEEFDEADBEEF:1700000001:::u:::scESC:::ed25519:0:
fpr:::::::::FEDCBA9876543210FEDCBA9876543210FEDCBA98:
uid:u::::1700000001::EFGHHASH::Bob Other <bob@example.com>:
ssb:u:256:18:CAFEBABECAFEBABE:1700000001::::::e:::cv25519:0:
fpr:::::::::9999888877776666555544443333222211110000:
"""


class TestGpgColonParse(unittest.TestCase):
    def test_keeps_primary_fingerprint(self) -> None:
        mgr = GpgManager.__new__(GpgManager)
        keys = mgr._parse_colon_listing(COLON_LISTING, secret=True)
        self.assertEqual(len(keys), 2)
        self.assertEqual(keys[0].fingerprint, "0123456789ABCDEF0123456789ABCDEF01234567")
        self.assertEqual(keys[0].key_id, "A1B2C3D4E5F60718")
        self.assertEqual(keys[0].uids, ["Alice Example <alice@example.com>"])
        self.assertTrue(keys[0].is_secret)
        self.assertEqual(keys[1].fingerprint, "FEDCBA9876543210FEDCBA9876543210FEDCBA98")
        self.assertEqual(keys[1].uids, ["Bob Other <bob@example.com>"])

    def test_short_lines_do_not_crash(self) -> None:
        mgr = GpgManager.__new__(GpgManager)
        keys = mgr._parse_colon_listing("fpr:short\nsec:u:256\nuid:x\n", secret=False)
        self.assertEqual(keys, [])

    def test_sanitize_key_ref(self) -> None:
        mgr = GpgManager.__new__(GpgManager)
        self.assertEqual(
            mgr._sanitize_key_ref("0123456789ABCDEF0123456789ABCDEF01234567"),
            "0123456789ABCDEF0123456789ABCDEF01234567",
        )
        self.assertEqual(mgr._sanitize_key_ref("0xA1B2C3D4"), "0xA1B2C3D4")
        with self.assertRaises(GpgError):
            mgr._sanitize_key_ref("--delete-keys")
        with self.assertRaises(GpgError):
            mgr._sanitize_key_ref("not a key")
        with self.assertRaises(GpgError):
            mgr._sanitize_key_ref("")


if __name__ == "__main__":
    unittest.main()
