import os
import stat
import tempfile
import unittest
from pathlib import Path

from securevault import (
    KeyLoadError,
    fingerprint,
    generate_keypair,
    load_private_key,
    load_public_key,
    save_keypair,
)

PRIV, PUB = generate_keypair(2048)


class KeyTests(unittest.TestCase):
    def test_rejects_small_keys(self):
        with self.assertRaises(ValueError):
            generate_keypair(1024)

    def test_roundtrip_with_passphrase(self):
        with tempfile.TemporaryDirectory() as d:
            priv_p, pub_p = save_keypair(PRIV, d, "t", passphrase=b"correct horse")
            self.assertIn(b"ENCRYPTED", Path(priv_p).read_bytes())
            loaded = load_private_key(priv_p, b"correct horse")
            self.assertEqual(
                loaded.public_key().public_numbers(), PUB.public_numbers()
            )
            self.assertEqual(
                load_public_key(pub_p).public_numbers(), PUB.public_numbers()
            )

    def test_wrong_or_missing_passphrase(self):
        with tempfile.TemporaryDirectory() as d:
            priv_p, _ = save_keypair(PRIV, d, "t", passphrase=b"right")
            with self.assertRaises(KeyLoadError):
                load_private_key(priv_p, b"wrong")
            with self.assertRaises(KeyLoadError):
                load_private_key(priv_p)

    @unittest.skipIf(os.name == "nt", "POSIX permissions only")
    def test_private_key_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            priv_p, _ = save_keypair(PRIV, d, "t")
            mode = stat.S_IMODE(os.stat(priv_p).st_mode)
            self.assertEqual(mode, 0o600)

    def test_no_overwrite_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            save_keypair(PRIV, d, "t")
            with self.assertRaises(FileExistsError):
                save_keypair(PRIV, d, "t")
            save_keypair(PRIV, d, "t", overwrite=True)

    def test_fingerprint_format_and_stability(self):
        fp = fingerprint(PUB)
        self.assertEqual(len(fp.split(":")), 32)
        self.assertEqual(fp, fingerprint(PUB))


if __name__ == "__main__":
    unittest.main()
