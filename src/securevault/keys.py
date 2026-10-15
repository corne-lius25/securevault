"""RSA key generation, storage (passphrase-protected) and loading."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .exceptions import KeyLoadError

PathLike = Union[str, "os.PathLike[str]"]

MIN_KEY_SIZE = 2048
DEFAULT_KEY_SIZE = 3072


def generate_keypair(
    key_size: int = DEFAULT_KEY_SIZE,
) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate an RSA key pair. ``key_size`` must be at least 2048 bits."""
    if key_size < MIN_KEY_SIZE:
        raise ValueError(f"key_size must be >= {MIN_KEY_SIZE} bits, got {key_size}")
    private = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private, private.public_key()


def _encryption_algorithm(
    passphrase: Optional[bytes],
) -> serialization.KeySerializationEncryption:
    if passphrase:
        return serialization.BestAvailableEncryption(passphrase)
    return serialization.NoEncryption()


def save_keypair(
    private_key: rsa.RSAPrivateKey,
    directory: PathLike,
    name: str = "securevault",
    passphrase: Optional[bytes] = None,
    overwrite: bool = False,
) -> Tuple[Path, Path]:
    """Write ``<name>_private.pem`` (mode 0600) and ``<name>_public.pem``.

    The private key is stored as PKCS#8 and encrypted with ``passphrase`` when given.
    Existing files are never overwritten unless ``overwrite`` is True.
    """
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    priv_path = out / f"{name}_private.pem"
    pub_path = out / f"{name}_public.pem"
    if not overwrite:
        for p in (priv_path, pub_path):
            if p.exists():
                raise FileExistsError(f"{p} already exists (use overwrite=True)")

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=_encryption_algorithm(passphrase),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Create the private key file with restrictive permissions from the start.
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(priv_pem)
    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


def load_public_key(path: PathLike) -> rsa.RSAPublicKey:
    """Load an RSA public key from a PEM file."""
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise KeyLoadError(f"cannot load public key {path}: {exc}") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyLoadError("public key is not an RSA key")
    return key


def load_private_key(
    path: PathLike, passphrase: Optional[bytes] = None
) -> rsa.RSAPrivateKey:
    """Load an RSA private key from a PEM file, unlocking it with ``passphrase`` if needed."""
    try:
        key = serialization.load_pem_private_key(
            Path(path).read_bytes(), password=passphrase or None
        )
    except TypeError as exc:
        raise KeyLoadError("private key is encrypted: a passphrase is required") from exc
    except (OSError, ValueError) as exc:
        raise KeyLoadError(
            f"cannot load private key {path} (wrong passphrase or corrupt file)"
        ) from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyLoadError("private key is not an RSA key")
    return key


def fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """Return the SHA-256 fingerprint of a public key as colon-separated hex."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    raw = digest.finalize().hex()
    return ":".join(raw[i : i + 2] for i in range(0, len(raw), 2))
