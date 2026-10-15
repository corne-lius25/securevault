"""Throughput benchmark for streaming encryption/decryption (file to file)."""

import os
import tempfile
import time
from pathlib import Path

from securevault import decrypt_file, encrypt_file, generate_keypair

SIZES_MB = [1, 10, 50, 200]

priv, pub = generate_keypair(3072)
print(f"{'Size':>8} | {'Encrypt':>10} | {'Decrypt':>10} | {'Enc MB/s':>9} | {'Dec MB/s':>9}")
print("-" * 58)
with tempfile.TemporaryDirectory() as tmp:
    src, enc, dec = (Path(tmp, n) for n in ("in.bin", "in.svlt", "out.bin"))
    for mb in SIZES_MB:
        src.write_bytes(os.urandom(mb * 1024 * 1024))
        t = time.perf_counter()
        encrypt_file(src, enc, pub, overwrite=True)
        te = time.perf_counter() - t
        t = time.perf_counter()
        decrypt_file(enc, dec, priv, overwrite=True)
        td = time.perf_counter() - t
        print(f"{mb:>6} MB | {te:>9.3f}s | {td:>9.3f}s | {mb / te:>9.1f} | {mb / td:>9.1f}")
