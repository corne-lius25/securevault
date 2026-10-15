# Contributing

Thanks for your interest! Bug reports, tests, docs and focused pull requests are welcome.

## Setup

```bash
git clone https://github.com/YOUR-USERNAME/securevault.git && cd securevault
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
ruff check .                 # lint
mypy                         # types
python -m pytest             # tests
```

- Add or update tests for any behaviour change. Security-relevant changes (format, AAD, key handling) need a test that demonstrates the failure mode being prevented.
- Do not change the on-disk format without bumping `VERSION` in `core.py`, updating `docs/FORMAT.md` and `CHANGELOG.md`.
- Keep the public API typed and documented.
- Never add your own cryptographic primitives; use `cryptography`.

## Commit style

Short imperative subject lines (`Add multi-recipient support`), with a body explaining *why* when it isn't obvious.
