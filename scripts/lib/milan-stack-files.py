#!/usr/bin/env python3
"""File bookkeeping for the manual Milan source installation.

The build stages a DESTDIR payload and records every file in inventory.json.
Installation copies that payload into the real filesystem and keeps the
inventory as the record of what is owned, so updates and removal only touch
files this installer put there.
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

FORMAT = 3
MANAGED_BY = "goodix53x5-milan-stack"
META = "/usr/share/goodix53x5-milan"
INVENTORY = META + "/inventory.json"
BUILD_ENV = META + "/build.env"
# User-editable files: never overwritten or removed once they differ.
CONFIG = {"/etc/fprintd.conf"}
# Old layout that must be uninstalled with its own script first.
OLD_LAYOUT = ("opt/goodix53x5-milan",
              "etc/systemd/system/fprintd.service.d/98-goodix53x5-milan-stack.conf")


def fail(message):
    raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_name(name):
    parts = PurePosixPath(name)
    if (str(parts) != name or ".." in parts.parts or any(c.isspace() for c in name)
            or not (name.startswith("/usr/") or name in CONFIG)):
        fail(f"unsafe inventory path: {name}")


def mapped(root, name):
    safe_name(name)
    return root / name.lstrip("/")


def entry(root, name):
    """Record describing the file at name below root, or None when absent."""
    path = mapped(root, name)
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(mode):
        return {"path": name, "target": os.readlink(path)}
    if stat.S_ISREG(mode):
        return {"path": name, "sha256": digest(path), "mode": stat.S_IMODE(mode)}
    return {"path": name, "type": "other"}


def check_staged(root, item):
    """A payload record must be a sane regular file or relative in-payload symlink."""
    name = item["path"]
    if "target" in item:
        target = item["target"]
        if os.path.isabs(target) or any(c.isspace() for c in target):
            fail(f"unsafe symlink: {name} -> {target}")
        resolved = mapped(root, name).resolve(strict=True)
        if not resolved.is_relative_to(root) or not resolved.is_file():
            fail(f"symlink leaves payload: {name}")
    elif "sha256" not in item or item["mode"] & 0o7022:
        fail(f"unsafe file type or permissions: {name}")


def scan(root):
    """Absolute names of every file and symlink below a payload root."""
    names = set()
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in list(dirs):
            if (Path(parent) / name).is_symlink():
                dirs.remove(name)
                files.append(name)
        names.update("/" + str((Path(parent) / name).relative_to(root)) for name in files)
    return names


def write_inventory(root, records):
    records = sorted(records, key=lambda item: item["path"])
    document = {"format": FORMAT, "managed_by": MANAGED_BY, "files": records}
    path = mapped(root, INVENTORY)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".json.tmp")
    temp.write_text(json.dumps(document, indent=2) + "\n")
    temp.chmod(0o644)
    os.replace(temp, path)  # never leave a torn inventory behind


def read_inventory(root):
    path = mapped(root, INVENTORY)
    if path.is_symlink() or not path.is_file():
        fail(f"missing inventory: {path}")
    document = json.loads(path.read_text())
    if document.get("format") != FORMAT or document.get("managed_by") != MANAGED_BY:
        fail(f"unsupported inventory: {path}")
    names = set()
    for item in document["files"]:
        safe_name(item["path"])
        if item["path"] in names or item["path"] == INVENTORY:
            fail(f"duplicate or reserved inventory path: {item['path']}")
        names.add(item["path"])
    return document["files"]


def inventory(payload):
    if payload.name != "payload":
        fail("inventory requires a bounded publication/payload directory")
    records = [entry(payload, name) for name in scan(payload) if name != INVENTORY]
    for item in records:
        check_staged(payload, item)
    write_inventory(payload, records)


def verify_build(payload):
    if payload.name != "payload":
        fail("build verification requires a bounded publication/payload directory")
    records = read_inventory(payload)
    names = {item["path"] for item in records}
    if BUILD_ENV not in names:
        fail("build.env is not inventoried")
    for item in records:
        check_staged(payload, item)
        if entry(payload, item["path"]) != item:
            fail(f"modified staged file: {item['path']}")
    if scan(payload) != names | {INVENTORY}:
        fail("payload contains unrecorded files")
    return records


def classify(root, records):
    """Split an installed inventory into unchanged, changed, and missing names."""
    unchanged, changed, missing = [], [], []
    for item in records:
        actual = entry(root, item["path"])
        if actual is None:
            missing.append(item["path"])
        elif actual == item:
            unchanged.append(item["path"])
        else:
            changed.append(item["path"])
    return unchanged, changed, missing


def report(label, names):
    for name in sorted(names):
        print(f"{label}: {name}", file=sys.stderr)


def package_conflicts(names):
    """Refuse destinations owned by a distribution package."""
    names = sorted(names)
    if shutil.which("pacman"):
        owned = subprocess.run(["pacman", "-Qo", "--", *names], capture_output=True,
                               text=True).stdout.splitlines()
    elif shutil.which("dpkg-query"):
        # dpkg may record the pre-merged-/usr alias of a path.
        aliases = [n[4:] for n in names if n.startswith(("/usr/lib", "/usr/bin/", "/usr/sbin/"))]
        owned = subprocess.run(["dpkg-query", "-S", *names, *aliases], capture_output=True,
                               text=True).stdout.splitlines()
    elif shutil.which("rpm"):
        owned = []
        for name in names:
            result = subprocess.run(["rpm", "-qf", "--", name], capture_output=True, text=True)
            if result.returncode == 0:
                owned.append(f"{result.stdout.strip()}: {name}")
    else:
        fail("no package ownership query available (pacman, dpkg-query, or rpm)")
    if owned:
        fail("package-owned destination files; remove these packages first:\n" + "\n".join(owned))


def preflight(payload, root):
    new = verify_build(payload)
    old = read_inventory(root) if mapped(root, INVENTORY).exists() else []
    old_names = {item["path"] for item in old} | ({INVENTORY} if old else set())
    new_names = {item["path"] for item in new} | {INVENTORY}
    package_conflicts(new_names | old_names)
    unmanaged = [name for name in sorted(new_names - old_names)
                 if mapped(root, name).exists() or mapped(root, name).is_symlink()]
    if unmanaged:
        fail("refusing unmanaged destinations; remove them first:\n" + "\n".join(unmanaged))
    for old_path in OLD_LAYOUT:
        if (root / old_path).exists() or (root / old_path).is_symlink():
            fail("the previous /opt installation is still present; remove it with its uninstall script first")
    return new, old


def copy_file(payload, root, name):
    """Copy one payload file into place; returns directories created."""
    src, dst = mapped(payload, name), mapped(root, name)
    created = [parent for parent in dst.parents if not parent.exists()]
    for parent in reversed(created):
        parent.mkdir()
    if dst.exists() or dst.is_symlink():
        dst.unlink()  # never overwrite in place: the old file may be mapped
    if src.is_symlink():
        dst.symlink_to(os.readlink(src))
    else:
        shutil.copyfile(src, dst)  # no xattrs: labels come from restorecon below
        dst.chmod(stat.S_IMODE(src.stat().st_mode))
    return created


def restore_labels(paths):
    if shutil.which("restorecon") and Path("/sys/fs/selinux/enforce").exists():
        subprocess.run(["restorecon", "--", *map(str, paths)], check=True)


def install(payload, root):
    """Copy the payload into root. The caller has already run preflight."""
    new = read_inventory(payload)
    old = read_inventory(root) if mapped(root, INVENTORY).exists() else []
    new_names = {item["path"] for item in new}
    kept = []
    for item in old:
        if item["path"] in new_names:
            continue
        actual = entry(root, item["path"])
        if actual is None:
            continue
        if actual != item and item["path"] in CONFIG:
            kept.append(item["path"])
            continue
        mapped(root, item["path"]).unlink()
    # Record ownership first so an interrupted install can be rerun or removed.
    write_inventory(root, new)
    labelled = {mapped(root, INVENTORY), mapped(root, META)}
    for item in new:
        current = entry(root, item["path"])
        if item["path"] in CONFIG and current is not None and current != item:
            kept.append(item["path"])
            continue
        labelled.update(copy_file(payload, root, item["path"]))
        labelled.add(mapped(root, item["path"]))
    restore_labels(labelled)
    report("kept modified configuration", kept)


def remove(root):
    records = read_inventory(root)
    unchanged, changed, _ = classify(root, records)
    for name in unchanged:
        mapped(root, name).unlink()
    if changed:
        write_inventory(root, [item for item in records if item["path"] in changed])
        report("kept modified file", changed)
        print("inventory retained for the kept files; delete them and rerun to finish",
              file=sys.stderr)
    else:
        mapped(root, INVENTORY).unlink()
        if not any(mapped(root, META).iterdir()):
            mapped(root, META).rmdir()
    # Shared directories and everything under /var/lib/fprint are left alone.


def verify_installed(root):
    records = read_inventory(root)
    if BUILD_ENV not in {item["path"] for item in records}:
        fail("installation is partially removed; delete the kept files and rerun uninstall")
    _, changed, missing = classify(root, records)
    report("modified configuration", [name for name in changed if name in CONFIG])
    problems = [name for name in changed if name not in CONFIG]
    report("modified file", problems)
    report("missing file", missing)
    if problems or missing:
        fail("installed files differ from the inventory")


def main(argv):
    action, root = argv[1], Path(argv[2]).resolve()
    if action == "inventory":
        inventory(root)
    elif action == "verify-build":
        verify_build(root)
    elif action == "verify-installed":
        verify_installed(root)
    elif action == "preflight":
        preflight(Path(argv[3]).resolve(), root)
    elif action == "install":
        install(Path(argv[3]).resolve(), root)
    elif action == "remove":
        remove(root)
    else:
        fail(f"unknown action: {action}")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (ValueError, OSError, KeyError, TypeError, IndexError,
            subprocess.CalledProcessError) as error:
        sys.exit(f"error: {error}")
