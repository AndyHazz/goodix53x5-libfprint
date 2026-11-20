#!/usr/bin/env python3
"""Reproduce four mathematical matcher fixtures; no imported-input interface."""

import argparse
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
DLL_SHA256 = "6673db3874fea66a58e2da29e371d797b890c767ba0491134d4a372c5b27e3b4"
CASES = ("bitmap-48", "bitmap-56", "order-1", "order-2")
ARTIFACTS = tuple(f"{case}-{phase}.bin" for case in CASES
                  for phase in ("probe", "gallery", "match", "observation"))
SOURCES = (
    "tests/test-goodix53x5-milan-native-match-inputs.c",
    "tests/test-goodix53x5-milan-native-match-format.h",
    "tests/test-goodix53x5-milan-state-support.c",
    "tests/test-goodix53x5-milan-state-support.h",
    "tests/test-goodix53x5-milan-state-study-fixtures.c",
    "tests/test-goodix53x5-milan-state-study-assertions.c",
    "tests/test-goodix53x5-milan-state-study-support.h",
    "tests/native-match/native.c",
    "tests/native-match/generate.py",
)


def identity(data):
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def run(*args, **kwargs):
    result = subprocess.run([str(arg) for arg in args], capture_output=True,
                            text=True, timeout=120, **kwargs)
    if result.returncode:
        raise ValueError(f"{args[0]} failed ({result.returncode}):\n"
                         f"{result.stdout}\n{result.stderr}")
    if result.stderr.strip():
        print(result.stderr.strip())
    return result.stdout.strip()


def compare(a, b, name):
    if len(a) != len(b):
        raise ValueError(f"{name}: lengths {len(a)} != {len(b)}")
    if a != b:
        offset = next(i for i, (x, y) in enumerate(zip(a, b)) if x != y)
        raise ValueError(f"{name}: first differing byte {offset:#x}")


def compressed(raw):
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0,
                       compresslevel=9) as stream:
        stream.write(raw)
    return output.getvalue()


def decompress(data, size):
    # One gzip member only, bounded output; reject CRC errors and trailing data.
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    raw = decoder.decompress(data, size + 1)
    if (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or len(raw) != size):
        raise ValueError("incomplete gzip, trailing data, or wrong raw length")
    return raw


def windows(path):
    return "Z:" + str(path.resolve()).replace("/", "\\")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dll", type=Path, required=True)
    parser.add_argument("--wine-prefix", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--output", type=Path, help="new output directory; never overwrite fixtures")
    args = parser.parse_args()
    dll, prefix = args.dll.resolve(), args.wine_prefix.resolve()
    if identity(dll.read_bytes())["sha256"] != DLL_SHA256:
        raise ValueError("DLL does not match the approved 2.0.310.900 identity")
    if not all((prefix / name).is_file() for name in ("system.reg", "user.reg")):
        raise ValueError("an existing initialized Wine prefix is required")
    if not (prefix / "drive_c").is_dir() or (prefix / "dosdevices/z:").resolve() != Path("/"):
        raise ValueError("existing prefix must have drive_c and Z: mapped to /")
    if args.output and (args.output.exists() or not args.output.parent.is_dir()):
        raise ValueError("output must be new and its parent must exist")

    source = ROOT / ".build/libfprint"
    driver_identity = hashlib.sha256()
    for path in sorted((ROOT / "drivers/goodix53x5").rglob("*")):
        if path.is_file():
            relative = path.relative_to(ROOT).as_posix()
            raw = path.read_bytes()
            compare(raw, (source / "libfprint" / relative).read_bytes(), relative)
            driver_identity.update(f"{relative}\0{identity(raw)['sha256']}\n".encode())
    for relative in SOURCES:
        if relative.startswith("tests/test-"):
            compare((ROOT / relative).read_bytes(), (source / relative).read_bytes(), relative)
    run("ninja", "-C", source / "builddir", "tests/goodix53x5-native-match-inputs")

    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "milan-parity"
    cache.mkdir(parents=True, exist_ok=True)
    lock_path = cache / ("wine-prefix-" + hashlib.sha256(str(prefix).encode()).hexdigest() + ".lock")
    with tempfile.TemporaryDirectory(prefix="native-match-", dir=ROOT / ".build") as temporary:
        work = Path(temporary)
        raw_dir, repeated, output = (work / name for name in ("raw", "repeated", "output"))
        for directory in (raw_dir, repeated, output):
            directory.mkdir()
        run(source / "builddir/tests/goodix53x5-native-match-inputs", raw_dir)
        executable = work / "native-match.exe"
        compiler = "x86_64-w64-mingw32-gcc"
        run(compiler, "-std=c17", "-O2", "-Wall", "-Wextra", "-Werror", "-municode",
            HERE / "native.c", "-o", executable)
        env = dict(os.environ, WINEPREFIX=str(prefix), WINEDEBUG="-all",
                   WINEDLLOVERRIDES="winemenubuilder.exe=d")
        observations = {}
        with lock_path.open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            wine_version = run("wine", "--version", env=env)
            for case in CASES:
                logs = []
                for destination in (raw_dir, repeated):
                    logs.append(run("wine", executable, windows(dll),
                                    windows(raw_dir / f"{case}-probe.bin"),
                                    windows(raw_dir / f"{case}-gallery.bin"),
                                    windows(destination / f"{case}-match.bin"),
                                    windows(destination / f"{case}-observation.bin"), env=env))
                if logs[0] != logs[1]:
                    raise ValueError(f"{case}: native logs changed on repetition")
                for phase in ("match", "observation"):
                    name = f"{case}-{phase}.bin"
                    compare((raw_dir / name).read_bytes(), (repeated / name).read_bytes(), name)
                words = struct.unpack("<36i", (raw_dir / f"{case}-observation.bin").read_bytes())
                observations[case] = {
                    "log": logs[0], "status": words[0], "score": words[1],
                    "winner": words[2], "relation_count": words[3],
                    "direct_affine": words[4:10], "routed_affine": words[10:16],
                    "queue_ranks": words[16:36],
                }
        artifacts = {}
        for name in ARTIFACTS:
            raw = (raw_dir / name).read_bytes()
            packed = compressed(raw)
            compare(raw, decompress(packed, len(raw)), name + " gzip roundtrip")
            (output / (name + ".gz")).write_bytes(packed)
            artifacts[name + ".gz"] = {"raw": identity(raw), "compressed": identity(packed)}
        provenance = {
            "schema": "goodix-synthetic-native-match/v1",
            "origin": "mathematical generators only; no biometric captures, seeds or derivatives",
            "scope": "four serialized type12/profile9 match-only calls; packed galleries and scoped decision/rank projection",
            "dll": {"sha256": DLL_SHA256, "package_version": "2.0.310.900"},
            "native": {"matcher_rva": "0x5edb0", "repetitions_per_case": 2,
                       "packer": ["templateGetPackedSize", "templatePack"],
                       "observations": observations},
            "storage": {"format": "single-member gzip", "mtime": 0, "filename": "",
                        "level": 9, "zlib": zlib.ZLIB_RUNTIME_VERSION},
            "wine": wine_version, "mingw": run(compiler, "-dumpfullversion"),
            "input_driver_source_sha256": driver_identity.hexdigest(),
            "sources": {name: identity((ROOT / name).read_bytes())["sha256"] for name in SOURCES},
            "artifacts": artifacts,
        }
        # JSON roundtrip also canonicalizes observation tuples for verification.
        provenance = json.loads(json.dumps(provenance))
        if args.verify:
            old = json.loads((HERE / "fixtures/provenance.json").read_text())
            if set(old["artifacts"]) != set(artifacts):
                raise ValueError("artifact inventory differs")
            for name, record in artifacts.items():
                original = (HERE / "fixtures" / name).read_bytes()
                if identity(original) != old["artifacts"][name]["compressed"]:
                    raise ValueError(f"{name}: original compressed identity differs")
                if record["raw"] != old["artifacts"][name]["raw"]:
                    raise ValueError(f"{name}: raw identity differs")
                compare((raw_dir / name.removesuffix(".gz")).read_bytes(),
                        decompress(original, record["raw"]["size"]), name)
            for key in ("schema", "origin", "scope", "dll", "native"):
                if old[key] != provenance[key]:
                    raise ValueError(f"provenance differs: {key}")
            for key in ("sources", "input_driver_source_sha256", "storage", "wine", "mingw"):
                if old[key] != provenance[key]:
                    print(f"provenance differs: {key} (original evidence retained)")
            print("Verified 16 gzip artifacts against raw inputs/native outputs; both native repetitions identical.")
        else:
            (output / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
            shutil.copytree(output, args.output)
            print(f"Generated 16 gzip artifacts with raw/compressed provenance in {args.output}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, zlib.error, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from error
