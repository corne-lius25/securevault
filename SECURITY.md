# Security

## Status

SecureVault is an educational / portfolio project. It composes standard primitives from the well-reviewed [`cryptography`](https://cryptography.io) library, but **the project itself has not had an independent security audit.** Do not rely on it as the only protection for high-value secrets.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's private
"Report a vulnerability" feature on the repository's *Security* tab (or email the maintainer at the address in `pyproject.toml`). Expect an initial response within a few days.

## Threat model

**In scope: protects against**

| Adversary capability | Protection |
|---|---|
| Reads encrypted files (disk theft, cloud provider, network) | AES-256-GCM confidentiality; session key only recoverable with the private key |
| Modifies, truncates, reorders or extends an encrypted file | Per-chunk GCM tags; header and final flag bound as AAD; output committed only after full verification |
| Steals an encrypted private key file | PKCS#8 encryption (passphrase-derived); file mode `0600` |
| Passive observation of many files | Fresh random key per file, so no cross-file nonce reuse |

**Out of scope: does *not* protect against**

- **Sender spoofing**: anyone with your public key can produce a valid file. Add signatures if authenticity matters.
- **Compromised endpoint**: malware, keyloggers, or memory scraping on the machine that holds the private key or plaintext. Python cannot reliably zero secrets in memory.
- **Metadata leakage**: approximate file size and chunk size are visible; file names are not encrypted (the name is yours to choose).
- **Weak passphrases**: the private key's strength at rest depends on its passphrase.
- **Public-key substitution**: verify recipients' key fingerprints (`securevault fingerprint`) over a trusted channel.
- **Quantum adversaries**: RSA is breakable by a large quantum computer ("harvest now, decrypt later").
- **Side channels** in the underlying libraries, which are delegated to `cryptography`/OpenSSL.

## Operational notes

- `SECUREVAULT_PASSPHRASE` is convenient for automation but is visible to other processes of the same user and may land in shell history or CI logs. Prefer the interactive prompt.
- If you create a key with an empty passphrase, the private key is stored **unencrypted**. The CLI warns you.
- Output files are created with owner-only permissions (`0600`) by default.
- **Never commit key files or encrypted data.** The provided `.gitignore` excludes `*.pem` and `*.svlt`.
