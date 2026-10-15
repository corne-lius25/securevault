"""Minimal library usage: generate keys, encrypt/decrypt bytes and files."""

import tempfile
from pathlib import Path

from securevault import (
    DecryptionError,
    decrypt_bytes,
    decrypt_file,
    encrypt_bytes,
    encrypt_file,
    generate_keypair,
    save_keypair,
)

private_key, public_key = generate_keypair(3072)

# --- in-memory ---
blob = encrypt_bytes(b"attack at dawn", public_key)
print(decrypt_bytes(blob, private_key))  # b'attack at dawn'

# --- tamper detection ---
tampered = bytearray(blob)
tampered[-1] ^= 1
try:
    decrypt_bytes(bytes(tampered), private_key)
except DecryptionError as exc:
    print("detected:", exc)

# --- files + passphrase-protected key storage ---
with tempfile.TemporaryDirectory() as tmp:
    save_keypair(private_key, tmp, "demo", passphrase=b"correct horse battery staple")
    src = Path(tmp, "notes.txt")
    src.write_text("hello")
    encrypt_file(src, Path(tmp, "notes.txt.svlt"), public_key)
    decrypt_file(Path(tmp, "notes.txt.svlt"), Path(tmp, "notes.out"), private_key)
    print(Path(tmp, "notes.out").read_text())  # hello
