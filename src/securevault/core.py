"""Streaming hybrid encryption: AES-256-GCM (chunked) + RSA-OAEP key wrapping.

Container layout (see docs/FORMAT.md)::

    magic "SVLT" | version u8 | chunk_size u32 | wrapped_key_len u16
    | wrapped_key | nonce_prefix[8] | chunk 0 | chunk 1 | ... | final chunk

Each chunk is AES-256-GCM encrypted with nonce ``nonce_prefix || counter(u32)`` and
associated data ``header || final_flag``. Binding the header and a final-chunk flag into
every chunk's authentication tag prevents truncation, reordering, and header tampering.
"""

from __future__ import annotations

import io
import os
import struct
import tempfile
from pathlib import Path
from typing import BinaryIO, Callable, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import DecryptionError, InvalidFormatError

MAGIC = b"SVLT"
VERSION = 1
DEFAULT_CHUNK_SIZE = 64 * 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024
TAG_SIZE = 16
NONCE_PREFIX_SIZE = 8
MAX_CHUNKS = 2**32
_FIXED_HEADER = struct.Struct(">4sBIH")  # magic, version, chunk_size, wrapped_key_len

PathLike = Union[str, "os.PathLike[str]"]


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def _nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + counter.to_bytes(4, "big")


def _aad(header: bytes, final: bool) -> bytes:
    return header + (b"\x01" if final else b"\x00")


def _read_exact(stream: BinaryIO, n: int) -> bytes:
    data = stream.read(n)
    if len(data) != n:
        raise InvalidFormatError("unexpected end of file while reading header")
    return data


def encrypt_stream(
    reader: BinaryIO,
    writer: BinaryIO,
    public_key: rsa.RSAPublicKey,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> int:
    """Encrypt ``reader`` to ``writer``. Returns the number of plaintext bytes processed."""
    if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError(f"chunk_size must be between 1 and {MAX_CHUNK_SIZE}")

    session_key = AESGCM.generate_key(bit_length=256)
    nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
    wrapped = public_key.encrypt(session_key, _oaep())

    header = _FIXED_HEADER.pack(MAGIC, VERSION, chunk_size, len(wrapped)) + wrapped + nonce_prefix
    writer.write(header)

    aead = AESGCM(session_key)
    total = 0
    counter = 0
    current = reader.read(chunk_size)
    while True:
        nxt = reader.read(chunk_size) if len(current) == chunk_size else b""
        final = not nxt
        if counter >= MAX_CHUNKS:
            raise ValueError("input too large for a single container")
        writer.write(aead.encrypt(_nonce(nonce_prefix, counter), current, _aad(header, final)))
        total += len(current)
        counter += 1
        if final:
            break
        current = nxt
    return total


def decrypt_stream(reader: BinaryIO, writer: BinaryIO, private_key: rsa.RSAPrivateKey) -> int:
    """Decrypt ``reader`` to ``writer``. Returns the number of plaintext bytes written.

    Plaintext is written as chunks are verified; callers that need all-or-nothing
    behaviour should write to a temporary destination (``decrypt_file`` does this).
    """
    fixed = _read_exact(reader, _FIXED_HEADER.size)
    magic, version, chunk_size, wk_len = _FIXED_HEADER.unpack(fixed)
    if magic != MAGIC:
        raise InvalidFormatError("not a SecureVault file (bad magic bytes)")
    if version != VERSION:
        raise InvalidFormatError(f"unsupported format version {version}")
    if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
        raise InvalidFormatError("invalid chunk size in header")
    if wk_len == 0 or wk_len > 1024:
        raise InvalidFormatError("invalid wrapped key length in header")

    wrapped = _read_exact(reader, wk_len)
    nonce_prefix = _read_exact(reader, NONCE_PREFIX_SIZE)
    header = fixed + wrapped + nonce_prefix

    try:
        session_key = private_key.decrypt(wrapped, _oaep())
    except ValueError as exc:
        raise DecryptionError("cannot unwrap session key: wrong private key") from exc
    if len(session_key) != 32:
        raise DecryptionError("unwrapped session key has an unexpected length")

    aead = AESGCM(session_key)
    enc_size = chunk_size + TAG_SIZE
    total = 0
    counter = 0
    current = reader.read(enc_size)
    if len(current) < TAG_SIZE:
        raise DecryptionError("file is truncated: no encrypted data")
    while True:
        nxt = reader.read(enc_size) if len(current) == enc_size else b""
        final = not nxt
        try:
            plain = aead.decrypt(_nonce(nonce_prefix, counter), current, _aad(header, final))
        except InvalidTag as exc:
            raise DecryptionError(
                "authentication failed: data was modified, truncated, or the key is wrong"
            ) from exc
        writer.write(plain)
        total += len(plain)
        counter += 1
        if final:
            break
        current = nxt
    return total


def encrypt_bytes(data: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """Encrypt an in-memory byte string and return the container bytes."""
    out = io.BytesIO()
    encrypt_stream(io.BytesIO(data), out, public_key)
    return out.getvalue()


def decrypt_bytes(blob: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Decrypt container bytes. Nothing is returned unless every chunk authenticates."""
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(blob), out, private_key)
    return out.getvalue()


def _atomic_write(work: Callable[[BinaryIO], int], dst: Path, overwrite: bool) -> int:
    """Run ``work(tmp_file)`` and move the result to ``dst`` only on success."""
    if dst.exists() and not overwrite:
        raise FileExistsError(f"{dst} already exists (use overwrite=True)")
    fd, tmp_name = tempfile.mkstemp(dir=dst.resolve().parent, prefix=".securevault-", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            n = work(fh)
        os.replace(tmp, dst)
        return n
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def encrypt_file(
    src: PathLike,
    dst: PathLike,
    public_key: rsa.RSAPublicKey,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overwrite: bool = False,
) -> int:
    """Encrypt file ``src`` into ``dst``. Returns plaintext bytes processed."""
    with open(src, "rb") as reader:
        return _atomic_write(
            lambda w: encrypt_stream(reader, w, public_key, chunk_size), Path(dst), overwrite
        )


def decrypt_file(
    src: PathLike,
    dst: PathLike,
    private_key: rsa.RSAPrivateKey,
    overwrite: bool = False,
) -> int:
    """Decrypt file ``src`` into ``dst``.

    The output appears at ``dst`` only if the whole file authenticates; on any failure
    the partial output is deleted, so unauthenticated plaintext is never left behind.
    """
    with open(src, "rb") as reader:
        return _atomic_write(
            lambda w: decrypt_stream(reader, w, private_key), Path(dst), overwrite
        )
