#!/usr/bin/env python3
"""Deterministic source identity embedded in Goodix debug builds."""

import hashlib
from pathlib import Path
import sys

FIXED_INPUTS = (
    "meson-integration.patch",
    "scripts/build-local.sh",
    "patches/libfprint/libfprint-update-result.patch",
    "patches/libfprint/libfprint-goodix53x5-usb-persist.patch",
    "patches/libfprint/libfprint-idle-suspend-notify.patch",
)


class SourceIdentityError(RuntimeError):
    pass


def source_identity(repo: Path) -> str:
    repo = repo.expanduser().resolve()
    root = repo / "drivers" / "goodix53x5"
    paths = sorted(path for path in root.rglob("*") if path.is_file())
    paths.extend(repo / name for name in FIXED_INPUTS)
    digest = hashlib.sha256()
    try:
        for path in paths:
            if not path.is_file():
                raise SourceIdentityError(f"build identity input is missing: {path}")
            digest.update(str(path.relative_to(repo)).encode("utf-8") + b"\0")
            digest.update(path.read_bytes())
    except OSError as error:
        raise SourceIdentityError(
            f"cannot calculate build identity: {error.strerror or error}") from error
    return digest.hexdigest()


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} REPOSITORY", file=sys.stderr)
        return 2
    try:
        print(source_identity(Path(sys.argv[1])))
    except SourceIdentityError as error:
        print(f"source-identity: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
