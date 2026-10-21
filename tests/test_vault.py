from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from crypto.vault import (
    InvalidPasswordError,
    SecretItem,
    SecretsVault,
    VaultError,
    _sanitize_kdf_params,
    parse_import_payload,
    KDF,
)


class TestSecretsVault(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.vault_path = Path(self._tmp.name) / "test.vault"
        self.vault = SecretsVault(self.vault_path)

    def tearDown(self) -> None:
        self.vault.lock()
        self._tmp.cleanup()

    def test_create_vault_roundtrip(self) -> None:
        password = "correct horse battery staple"
        self.vault.create(password)
        self.assertTrue(self.vault_path.exists())
        self.assertTrue(self.vault.unlocked)

        item = SecretItem(
            id="abc123",
            title="Example",
            username="user@example.com",
            password="s3cret",
            url="https://example.com",
            notes="hello",
            tags=["work", "shared"],
            folder="Work",
        )
        self.vault.add_item(item)
        self.vault.lock()
        self.assertFalse(self.vault.unlocked)
        self.assertEqual(self.vault.items, [])

        self.vault.unlock(password)
        self.assertTrue(self.vault.unlocked)
        self.assertEqual(len(self.vault.items), 1)
        loaded = self.vault.items[0]
        self.assertEqual(loaded.title, "Example")
        self.assertEqual(loaded.username, "user@example.com")
        self.assertEqual(loaded.password, "s3cret")
        self.assertEqual(loaded.url, "https://example.com")
        self.assertEqual(loaded.notes, "hello")
        self.assertEqual(loaded.tags, ["work", "shared"])
        self.assertEqual(loaded.folder, "Work")

    def test_wrong_password_fails(self) -> None:
        self.vault.create("right-password")
        self.vault.lock()
        with self.assertRaises(InvalidPasswordError):
            self.vault.unlock("wrong-password")
        self.assertFalse(self.vault.unlocked)

    def test_kdf_clamp(self) -> None:
        extreme = {
            "time_cost": 9999,
            "memory_cost": 99_000_000,
            "parallelism": 999,
            "type": "something-evil",
            "hash_len": 64,
            "extra": "ignored",
        }
        sanitized = _sanitize_kdf_params(extreme)
        self.assertEqual(sanitized["type"], "argon2id")
        self.assertEqual(sanitized["hash_len"], 32)
        self.assertLessEqual(sanitized["time_cost"], 10)
        self.assertGreaterEqual(sanitized["time_cost"], 1)
        self.assertLessEqual(sanitized["memory_cost"], 1_048_576)
        self.assertGreaterEqual(sanitized["memory_cost"], 8_192)
        self.assertLessEqual(sanitized["parallelism"], 8)
        self.assertGreaterEqual(sanitized["parallelism"], 1)
        self.assertNotIn("extra", sanitized)

        defaults = _sanitize_kdf_params(None)
        self.assertEqual(defaults["time_cost"], KDF["time_cost"])
        self.assertEqual(defaults["memory_cost"], KDF["memory_cost"])
        self.assertEqual(defaults["parallelism"], KDF["parallelism"])

        low = _sanitize_kdf_params({"time_cost": 0, "memory_cost": 1, "parallelism": 0})
        self.assertEqual(low["time_cost"], 1)
        self.assertEqual(low["memory_cost"], 8_192)
        self.assertEqual(low["parallelism"], 1)

    def test_add_update_delete_item(self) -> None:
        self.vault.create("pw")
        item = SecretItem(id="id1", title="One", password="a")
        self.vault.add_item(item)
        self.assertEqual(len(self.vault.items), 1)

        item.title = "One Updated"
        item.password = "b"
        item.folder = "Personal"
        item.tags = ["t1"]
        self.vault.update_item(item)
        self.assertEqual(self.vault.items[0].title, "One Updated")
        self.assertEqual(self.vault.items[0].password, "b")
        self.assertEqual(self.vault.items[0].folder, "Personal")

        self.vault.lock()
        self.vault.unlock("pw")
        self.assertEqual(self.vault.items[0].title, "One Updated")
        self.assertEqual(self.vault.items[0].folder, "Personal")

        self.vault.delete_item("id1")
        self.assertEqual(self.vault.items, [])
        self.vault.lock()
        self.vault.unlock("pw")
        self.assertEqual(self.vault.items, [])

        with self.assertRaises(VaultError):
            self.vault.update_item(SecretItem(id="missing", title="x"))
        with self.assertRaises(VaultError):
            self.vault.delete_item("missing")

    def test_batch_persist(self) -> None:
        self.vault.create("pw")
        self.vault.add_item(SecretItem(id="a", title="A", password="1"), persist=False)
        self.vault.add_item(SecretItem(id="b", title="B", password="2"), persist=False)
        self.vault.save()
        self.vault.lock()
        self.vault.unlock("pw")
        self.assertEqual({x.id for x in self.vault.items}, {"a", "b"})

    def test_change_password(self) -> None:
        self.vault.create("old-pass")
        self.vault.add_item(SecretItem(id="x", title="T", password="secret"))
        self.vault.change_password("old-pass", "new-pass")
        self.vault.lock()
        with self.assertRaises(InvalidPasswordError):
            self.vault.unlock("old-pass")
        self.vault.unlock("new-pass")
        self.assertEqual(self.vault.items[0].password, "secret")

        with self.assertRaises(InvalidPasswordError):
            self.vault.change_password("wrong", "another")

    def test_secret_item_folder_and_tags_serialization(self) -> None:
        item = SecretItem(
            id="z",
            title="Z",
            tags=["a", "b"],
            folder="F",
        )
        d = item.to_dict()
        self.assertEqual(d["folder"], "F")
        self.assertEqual(d["tags"], ["a", "b"])
        restored = SecretItem.from_dict(d)
        self.assertEqual(restored.folder, "F")
        self.assertEqual(restored.tags, ["a", "b"])

        from_str = SecretItem.from_dict({"title": "T", "tags": "x, y , z"})
        self.assertEqual(from_str.tags, ["x", "y", "z"])

        bare = SecretItem.from_dict({"title": "Bare"})
        self.assertEqual(bare.folder, "")

        invalid_tags = SecretItem.from_dict({"title": "T", "tags": 123})
        self.assertEqual(invalid_tags.tags, [])

        none_tags = SecretItem.from_dict({"title": "T", "tags": None})
        self.assertEqual(none_tags.tags, [])

    def test_vault_file_header_shape(self) -> None:
        self.vault.create("pw")
        raw = json.loads(self.vault_path.read_text(encoding="utf-8"))
        self.assertIn("header", raw)
        self.assertIn("payload", raw)
        self.assertEqual(raw["header"]["algorithm"], "AES-256-GCM")
        self.assertEqual(raw["header"]["kdf"]["type"], "argon2id")

    def test_unlock_unreadable_file(self) -> None:
        self.vault.create("pw")
        self.vault.lock()
        self.vault_path.write_bytes(b"\xff\xfe not json")
        with self.assertRaises(VaultError):
            self.vault.unlock("pw")

    def test_parse_import_payload(self) -> None:
        rows = parse_import_payload(
            {
                "format": "seahorse-secrets",
                "version": 1,
                "redacted": False,
                "items": [{"id": "1", "title": "A", "password": "x"}],
            }
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["title"], "A")

        listed = parse_import_payload([{"title": "B"}])
        self.assertEqual(listed[0]["title"], "B")

        with self.assertRaises(VaultError):
            parse_import_payload({"redacted": True, "items": [{"id": "1", "title": "A"}]})

        with self.assertRaises(VaultError):
            parse_import_payload([{"title": "A", "_redacted": True}])

        with self.assertRaises(VaultError):
            parse_import_payload("not-a-document")

        skipped = parse_import_payload([{"title": "ok"}, "skip-me", 3])
        self.assertEqual(len(skipped), 1)


class TestPasswordStrength(unittest.TestCase):
    def test_labels(self) -> None:
        from gui.main_window import password_strength

        self.assertEqual(password_strength(""), (0, "Empty"))
        score, label = password_strength("short")
        self.assertEqual(label, "Very weak")
        self.assertLess(score, 2)
        strong_score, strong_label = password_strength("Correct-Horse-Battery-Staple-99")
        self.assertGreaterEqual(strong_score, 3)
        self.assertIn(strong_label, {"Strong", "Very strong"})


if __name__ == "__main__":
    unittest.main()
