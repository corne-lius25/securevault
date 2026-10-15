"""Exception hierarchy for SecureVault."""


class SecureVaultError(Exception):
    """Base class for all SecureVault errors."""


class InvalidFormatError(SecureVaultError):
    """The input is not a valid SecureVault container (bad magic, version or header)."""


class DecryptionError(SecureVaultError):
    """Decryption failed: wrong key, or the data was modified, truncated or reordered."""


class KeyLoadError(SecureVaultError):
    """A key file could not be read, parsed or unlocked."""
