"""SecureVault: hybrid file encryption (AES-256-GCM + RSA-OAEP) with a streaming format."""

from .core import decrypt_bytes, decrypt_file, encrypt_bytes, encrypt_file
from .exceptions import (
    DecryptionError,
    InvalidFormatError,
    KeyLoadError,
    SecureVaultError,
)
from .keys import (
    fingerprint,
    generate_keypair,
    load_private_key,
    load_public_key,
    save_keypair,
)

__version__ = "1.0.0"

__all__ = [
    "DecryptionError",
    "InvalidFormatError",
    "KeyLoadError",
    "SecureVaultError",
    "__version__",
    "decrypt_bytes",
    "decrypt_file",
    "encrypt_bytes",
    "encrypt_file",
    "fingerprint",
    "generate_keypair",
    "load_private_key",
    "load_public_key",
    "save_keypair",
]
