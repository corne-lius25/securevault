# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-16

### Added
- Hybrid encryption: AES-256-GCM chunked streaming + RSA-OAEP (SHA-256) key wrapping.
- Container format v1 with header-bound AAD and final-chunk flag (see `docs/FORMAT.md`).
- Passphrase-protected PKCS#8 key storage with `0600` permissions.
- All-or-nothing file output via temporary file and atomic rename.
- CLI: `keygen`, `encrypt`, `decrypt`, `fingerprint`.
- Test suite (27 tests), GitHub Actions CI, examples and docs.
