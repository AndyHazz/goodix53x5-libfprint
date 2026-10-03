#!/usr/bin/env python3
"""Reproduce fixed mathematical preprocessing fixtures with the approved DLL."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DLL_SHA256 = "6673db3874fea66a58e2da29e371d797b890c767ba0491134d4a372c5b27e3b4"
CASES = {"natural": (24, 38039), "temporal-800": (22, 38035), "temporal-0": (22, 38035)}
SOURCES = (HERE / "generate.py", HERE / "native.c",
           ROOT / "tests/test-goodix53x5-milan-native-preprocess-format.h")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args, **kwargs):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True,
                            timeout=120, **kwargs)
    if result.returncode:
        raise ValueError(f"{args[0]} failed ({result.returncode}):\n{result.stdout}\n{result.stderr}")
    if result.stderr.strip():
        print(result.stderr.strip())
    return result.stdout.strip()


def windows(path):
    return "Z:" + str(path.resolve()).replace("/", "\\")


def mathematical_input(case):
    """Fixed arithmetic only; never reads images, seeds, templates or captures."""
    setup, live = [], []
    for row in range(88):
        for column in range(108):
            if case == "natural":
                baseline = 0x700 + row * 3 + column * 2 + (((row * 7) ^ (column * 13)) & 63)
                delta = 300 if (column * 8 + row * 8) % 80 < 40 else 1200
                if ((column - 32) ** 2 + (row - 28) ** 2 < 36 or
                        (column - 72) ** 2 + (row - 55) ** 2 < 49):
                    delta = 1200
                value = baseline
                if abs(row - 44) <= 4 and abs(column - 54) <= 4:
                    value = baseline - delta + 800 + (4 - max(abs(row - 44), abs(column - 54))) * 80
                setup.append(value)
                live.append(baseline - delta)
            else:
                band = 800 if case == "temporal-800" else 0
                x = min(106, max(1, column))
                setup.append(3500 + 5095 + (x % 18) * 40 + (band if row >= 44 else 0))
                live.append(3500)
    final = [value - (600 if case == "natural" else 6395) for value in setup]
    data = b"".join(struct.pack("<9504H", *plane) for plane in (setup, live, final))
    return data + (b"" if case == "natural" else bytes([1]) * 9504)


def compare(actual, expected, name):
    a, e = actual.read_bytes(), expected.read_bytes()
    if len(a) != len(e):
        raise ValueError(f"{name}: size generated={len(a)} frozen={len(e)}")
    if a != e:
        offset = next(i for i, (x, y) in enumerate(zip(a, e)) if x != y)
        raise ValueError(f"{name}: first differing byte {offset:#x}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dll", type=Path, required=True)
    parser.add_argument("--wine-prefix", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--output", type=Path, help="create a new directory; never overwrite")
    args = parser.parse_args()
    dll, prefix = args.dll.resolve(), args.wine_prefix.resolve()
    if sha(dll) != DLL_SHA256:
        raise ValueError("DLL does not match approved 2.0.310.900 identity")
    if not all((prefix / name).is_file() for name in ("system.reg", "user.reg")):
        raise ValueError("an initialized existing Wine prefix is required")
    if not (prefix / "drive_c").is_dir() or (prefix / "dosdevices/z:").resolve() != Path("/"):
        raise ValueError("existing prefix requires drive_c and Z: mapped to /")
    if args.output and (args.output.exists() or not args.output.parent.is_dir()):
        raise ValueError("output must not exist and its parent must exist")
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "milan-parity"
    cache.mkdir(parents=True, exist_ok=True)
    lock_path = cache / ("wine-prefix-" + hashlib.sha256(str(prefix).encode()).hexdigest() + ".lock")
    env = dict(os.environ, WINEPREFIX=str(prefix), WINEDEBUG="-all",
               WINEDLLOVERRIDES="winemenubuilder.exe=d")
    (ROOT / ".build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="native-preprocess-", dir=ROOT / ".build") as temporary:
        work = Path(temporary)
        generated = work / "generated"
        generated.mkdir()
        executable = work / "native.exe"
        compiler = "x86_64-w64-mingw32-gcc"
        run(compiler, "-std=c17", "-O2", "-Wall", "-Wextra", "-Werror", "-municode",
            HERE / "native.c", "-o", executable)
        observations = {}
        with lock_path.open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            wine = run("wine", "--version", env=env)
            for case, (calls, size) in CASES.items():
                source = generated / f"{case}-input.bin"
                source.write_bytes(mathematical_input(case))
                output = generated / f"{case}-output.bin"
                repeated = work / f"{case}-repeat.bin"
                logs = [run("wine", executable, windows(dll), case, windows(source),
                            windows(destination), env=env) for destination in (output, repeated)]
                compare(output, repeated, case + " native repetition")
                if logs[0] != logs[1] or output.stat().st_size != calls * size:
                    raise ValueError(f"{case}: inconsistent observations or output length")
                observations[case] = logs[0].splitlines()
        artifacts = {path.name: {"size": path.stat().st_size, "sha256": sha(path)}
                     for path in sorted(generated.iterdir())}
        provenance = {
            "schema": "goodix-synthetic-native-preprocess/v1",
            "origin": "fixed mathematical arithmetic only; no biometric captures, seeds or derivatives",
            "dll": {"sha256": DLL_SHA256, "package_version": "2.0.310.900"},
            "native": {"profile": 9, "sensor_type": 12, "repetitions_per_case": 2,
                       "preprocessor_export": "preprocessor", "temporal_rva": "0x6b290",
                       "history_count_rva": "0x1dc9a4", "history_reference_rva": "0x1dc9b0",
                       "reference_age_rva": "0x1e62d0", "observations": observations},
            "scope": "complete per-call image/mask and observed history projection; not every calibration field",
            "sources": {str(path.relative_to(ROOT)): sha(path) for path in SOURCES},
            "wine": wine, "mingw": run(compiler, "-dumpfullversion"), "artifacts": artifacts,
        }
        (generated / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
        if args.verify:
            for name in artifacts:
                compare(generated / name, HERE / "fixtures" / name, name)
            old = json.loads((HERE / "fixtures/provenance.json").read_text())
            for key in ("schema", "dll", "native", "artifacts"):
                if old.get(key) != provenance[key]:
                    raise ValueError(f"provenance does not match native evidence: {key}")
            for key in ("sources", "wine", "mingw"):
                if old.get(key) != provenance[key]:
                    print(f"{key} differs; original provenance retained")
            print("Verified all 6 artifacts; 68 calls per repetition, complete native bytes identical.")
        else:
            shutil.copytree(generated, args.output)
            print(f"Generated six synthetic artifacts and provenance in {args.output}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from error
