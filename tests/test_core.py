import io
import os
import tempfile
import unittest
from pathlib import Path

from securevault import (
    DecryptionError,
    InvalidFormatError,
    decrypt_bytes,
    decrypt_file,
    encrypt_bytes,
    encrypt_file,
    generate_keypair,
)
from securevault.core import decrypt_stream, encrypt_stream

PRIV, PUB = generate_keypair(2048)
OTHER_PRIV, _ = generate_keypair(2048)
HEADER_LEN = 4 + 1 + 4 + 2 + 256 + 8  # RSA-2048 wrapped key = 256 bytes


def enc(data: bytes, chunk: int = 1024) -> bytes:
    out = io.BytesIO()
    encrypt_stream(io.BytesIO(data), out, PUB, chunk_size=chunk)
    return out.getvalue()


class RoundTripTests(unittest.TestCase):
    def test_various_sizes_including_chunk_boundaries(self):
        for size in (0, 1, 15, 16, 1023, 1024, 1025, 2048, 5000):
            data = os.urandom(size)
            blob = enc(data, 1024)
            out = io.BytesIO()
            n = decrypt_stream(io.BytesIO(blob), out, PRIV)
            self.assertEqual(out.getvalue(), data, f"size={size}")
            self.assertEqual(n, size)

    def test_bytes_api(self):
        data = b"hello world" * 1000
        self.assertEqual(decrypt_bytes(encrypt_bytes(data, PUB), PRIV), data)

    def test_ciphertext_differs_each_time(self):
        data = b"same input"
        self.assertNotEqual(encrypt_bytes(data, PUB), encrypt_bytes(data, PUB))

    def test_plaintext_not_visible_in_ciphertext(self):
        secret = b"TOP-SECRET-MARKER-12345"
        self.assertNotIn(secret, encrypt_bytes(secret * 10, PUB))

    def test_overhead_is_header_plus_tag_per_chunk(self):
        # Exact multiple of the chunk size: read-ahead marks the last full chunk as final,
        # so no extra empty chunk is written.
        blob = enc(b"x" * 2048, 1024)
        self.assertEqual(len(blob), HEADER_LEN + 2 * (1024 + 16))
        # A non-multiple adds one short final chunk.
        blob = enc(b"x" * 2050, 1024)
        self.assertEqual(len(blob), HEADER_LEN + 2 * (1024 + 16) + (2 + 16))


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.data = os.urandom(5000)
        self.blob = enc(self.data, 1024)

    def _expect_failure(self, blob):
        with self.assertRaises((DecryptionError, InvalidFormatError)):
            decrypt_bytes(blob, PRIV)

    def test_wrong_key_rejected(self):
        with self.assertRaises(DecryptionError):
            decrypt_bytes(self.blob, OTHER_PRIV)

    def test_bit_flip_in_every_region_detected(self):
        offsets = [0, 4, 5, 9, 11, 40, HEADER_LEN - 1, HEADER_LEN, HEADER_LEN + 500,
                   len(self.blob) - 1]
        for off in offsets:
            tampered = bytearray(self.blob)
            tampered[off] ^= 0x01
            self._expect_failure(bytes(tampered))

    def test_truncation_at_chunk_boundary_detected(self):
        cut = HEADER_LEN + 2 * (1024 + 16)
        self._expect_failure(self.blob[:cut])

    def test_truncation_mid_chunk_detected(self):
        self._expect_failure(self.blob[:-5])

    def test_truncated_to_header_only(self):
        self._expect_failure(self.blob[:HEADER_LEN])

    def test_chunk_reordering_detected(self):
        c = 1024 + 16
        body = self.blob[HEADER_LEN:]
        swapped = body[c:2 * c] + body[:c] + body[2 * c:]
        self._expect_failure(self.blob[:HEADER_LEN] + swapped)

    def test_appended_data_detected(self):
        self._expect_failure(self.blob + b"extra")

    def test_bad_magic_and_version(self):
        with self.assertRaises(InvalidFormatError):
            decrypt_bytes(b"NOPE" + self.blob[4:], PRIV)
        bad = bytearray(self.blob)
        bad[4] = 99
        with self.assertRaises(InvalidFormatError):
            decrypt_bytes(bytes(bad), PRIV)

    def test_empty_and_garbage_input(self):
        for junk in (b"", b"SVLT", os.urandom(64)):
            self._expect_failure(junk)


class FileTests(unittest.TestCase):
    def test_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            src, enc_p, dec_p = (Path(d) / n for n in ("a.bin", "a.svlt", "b.bin"))
            data = os.urandom(300_000)
            src.write_bytes(data)
            self.assertEqual(encrypt_file(src, enc_p, PUB), len(data))
            self.assertEqual(decrypt_file(enc_p, dec_p, PRIV), len(data))
            self.assertEqual(dec_p.read_bytes(), data)

    def test_no_partial_output_on_failure(self):
        with tempfile.TemporaryDirectory() as d:
            src, enc_p, dec_p = (Path(d) / n for n in ("a.bin", "a.svlt", "b.bin"))
            src.write_bytes(os.urandom(300_000))
            encrypt_file(src, enc_p, PUB, chunk_size=4096)
            raw = bytearray(enc_p.read_bytes())
            raw[-10] ^= 1  # corrupt the last chunk: earlier chunks are valid
            enc_p.write_bytes(bytes(raw))
            with self.assertRaises(DecryptionError):
                decrypt_file(enc_p, dec_p, PRIV)
            self.assertFalse(dec_p.exists())
            leftovers = [p.name for p in Path(d).iterdir() if p.name.startswith(".securevault-")]
            self.assertEqual(leftovers, [])

    def test_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            src, out = Path(d) / "a", Path(d) / "a.svlt"
            src.write_bytes(b"data")
            out.write_bytes(b"existing")
            with self.assertRaises(FileExistsError):
                encrypt_file(src, out, PUB)
            self.assertEqual(out.read_bytes(), b"existing")
            encrypt_file(src, out, PUB, overwrite=True)

    def test_invalid_chunk_size(self):
        with self.assertRaises(ValueError):
            encrypt_stream(io.BytesIO(b"x"), io.BytesIO(), PUB, chunk_size=0)


if __name__ == "__main__":
    unittest.main()
