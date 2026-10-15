"""Command-line interface: ``securevault keygen | encrypt | decrypt | fingerprint``."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .core import DEFAULT_CHUNK_SIZE, decrypt_file, encrypt_file
from .exceptions import SecureVaultError
from .keys import (
    DEFAULT_KEY_SIZE,
    fingerprint,
    generate_keypair,
    load_private_key,
    load_public_key,
    save_keypair,
)

ENV_PASSPHRASE = "SECUREVAULT_PASSPHRASE"  # noqa: S105
SUFFIX = ".svlt"


def _get_passphrase(confirm: bool = False) -> Optional[bytes]:
    env = os.environ.get(ENV_PASSPHRASE)
    if env is not None:
        return env.encode() or None
    if not sys.stdin.isatty():
        return None
    first = getpass.getpass("Passphrase (empty for none): ")
    if confirm and first:
        if getpass.getpass("Confirm passphrase: ") != first:
            raise SecureVaultError("passphrases do not match")
    return first.encode() or None


def _cmd_keygen(args: argparse.Namespace) -> int:
    print(f"Generating RSA-{args.bits} key pair ...")
    private, _ = generate_keypair(args.bits)
    passphrase = _get_passphrase(confirm=True)
    if passphrase is None:
        print("warning: private key will be stored UNENCRYPTED", file=sys.stderr)
    priv, pub = save_keypair(
        private, args.out_dir, args.name, passphrase, overwrite=args.force
    )
    print(f"private key : {priv}  (keep secret)")
    print(f"public key  : {pub}")
    print(f"fingerprint : {fingerprint(private.public_key())}")
    return 0


def _cmd_encrypt(args: argparse.Namespace) -> int:
    src = Path(args.input)
    dst = Path(args.output) if args.output else src.with_name(src.name + SUFFIX)
    n = encrypt_file(
        src, dst, load_public_key(args.key), args.chunk_size, overwrite=args.force
    )
    print(f"encrypted {n} bytes -> {dst}")
    return 0


def _cmd_decrypt(args: argparse.Namespace) -> int:
    src = Path(args.input)
    if args.output:
        dst = Path(args.output)
    elif src.suffix == SUFFIX:
        dst = src.with_suffix("")
    else:
        raise SecureVaultError("cannot infer output name; pass --output")
    key = load_private_key(args.key, _get_passphrase())
    n = decrypt_file(src, dst, key, overwrite=args.force)
    print(f"decrypted {n} bytes -> {dst}  (authentication OK)")
    return 0


def _cmd_fingerprint(args: argparse.Namespace) -> int:
    print(fingerprint(load_public_key(args.key)))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="securevault",
        description="Hybrid file encryption: AES-256-GCM + RSA-OAEP.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    k = sub.add_parser("keygen", help="generate an RSA key pair")
    k.add_argument("--bits", type=int, default=DEFAULT_KEY_SIZE, help="key size (>=2048)")
    k.add_argument("--out-dir", default=".", help="directory for key files")
    k.add_argument("--name", default="securevault", help="key file name prefix")
    k.add_argument("--force", action="store_true", help="overwrite existing key files")
    k.set_defaults(func=_cmd_keygen)

    e = sub.add_parser("encrypt", help="encrypt a file with a public key")
    e.add_argument("input")
    e.add_argument("-k", "--key", required=True, help="recipient public key (PEM)")
    e.add_argument("-o", "--output", help=f"output path (default: <input>{SUFFIX})")
    e.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, help="bytes per chunk")
    e.add_argument("--force", action="store_true", help="overwrite existing output")
    e.set_defaults(func=_cmd_encrypt)

    d = sub.add_parser("decrypt", help="decrypt a file with a private key")
    d.add_argument("input")
    d.add_argument("-k", "--key", required=True, help="private key (PEM)")
    d.add_argument("-o", "--output", help="output path (default: strip .svlt)")
    d.add_argument("--force", action="store_true", help="overwrite existing output")
    d.set_defaults(func=_cmd_decrypt)

    f = sub.add_parser("fingerprint", help="print a public key's SHA-256 fingerprint")
    f.add_argument("key", help="public key (PEM)")
    f.set_defaults(func=_cmd_fingerprint)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (SecureVaultError, FileExistsError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
