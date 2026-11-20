# Milan Source Installation

These scripts build the Milan driver with pinned, patched libfprint and fprintd,
then install the pair into the distribution's normal paths under `/usr`. The
installer only ever touches files it recorded itself; it does not install,
remove, or restore distribution packages.

## Layout

| Distribution family | libfprint directory | fprintd executable |
| --- | --- | --- |
| Arch | `/usr/lib` | `/usr/lib/fprintd` |
| Debian/Ubuntu | `/usr/lib/<multiarch>` | `/usr/libexec/fprintd` |
| Fedora/RPM-based | RPM's `%{_libdir}`, usually `/usr/lib64` | `/usr/libexec/fprintd` |

Other systemd distributions use `/usr/lib` and `/usr/libexec/fprintd`. The
installer needs `pacman`, `dpkg-query`, or `rpm` to confirm that no package
owns a destination file.

The payload is the full fprintd runtime (the `fprintd-*` commands, PAM module
under `<libdir>/security`, systemd unit, D-Bus and polkit files, translations,
manuals) plus libfprint built with the `goodix53x5` driver only. Enabling
fingerprint authentication in PAM is left to you and your distribution. Print
state and the imported Windows PSK stay under `/var/lib/fprint`.

The Milan udev rule starts fprintd when a supported sensor appears. The daemon
opens the sensor at enumeration and keeps it open across `Release` and client
exit, so the first unlock can skip cold initialization as well as later ones.
Installation restarts fprintd to prepare the sensor without a reboot. If eager
initialization fails, the next authorized `Claim` retries; an early claim waits
for initialization already in progress. The driver services the initialized
sensor in the background, including before the first claim. The paired libfprint
and fprintd patches are required together and support only this Goodix driver. See
the [fprintd overlay notes](../patches/fprintd/README.md#retained-hardware-session)
for the claim, sleep and shutdown behaviour.

`/usr/share/goodix53x5-milan/build.env` records the build (`LIBRARY_PATH`,
`DAEMON_PATH`, pinned revisions, debug flag and IDs) and `inventory.json` lists
every installed file with its hash. On SELinux systems the installer runs
`restorecon` over the files it wrote so they receive the policy's labels.

## Build And Install

Build as your normal user, then install as root:

```sh
./scripts/build-milan-stack-local.sh
./scripts/status-milan-stack-local.sh --build
sudo ./scripts/status-milan-stack-local.sh --preflight
sudo ./scripts/install-milan-stack-local.sh
./scripts/status-milan-stack-local.sh --installed
```

`./install.sh` runs the build and the install together; `./install.sh --debug`
(or `GOODIX53X5_DEBUG=1` for the builder) produces a diagnostic build with the
same matching and persistence behaviour. Installing that build automatically
enables the driver's GLib debug messages, timing logs, and one-line diagnostic
summaries in the `fprintd.service` journal. Follow them with
`sudo journalctl -fu fprintd.service -o cat`. Image and template capture remains
disabled and needs the separate private configuration in the developer
[debug capture guide](https://github.com/seaweeduk/goodix53x5-libfprint/blob/main/DEBUG-CAPTURE-GUIDE.md). Installing a later release
build removes the managed debug logging configuration automatically; independent
administrator overrides under `/etc/systemd/system` are not changed.

Builds live under `$XDG_STATE_HOME/goodix53x5-milan` (default
`~/.local/state/goodix53x5-milan`); `sudo` resolves the invoking user's home.
Override with `GOODIX_MILAN_STACK_ROOT`, which must be absolute and not under
`/tmp`, `/var/tmp`, or `/run`; package builds (`--package-root`) only use it as
scratch space and accept any absolute path. Pinned libfprint and fprintd checkouts are cloned
below `sources/` unless `GOODIX_MILAN_LIBFPRINT_SOURCE` or
`GOODIX_MILAN_FPRINTD_SOURCE` point at existing pristine checkouts.

Each build verifies the pinned patches, runs the libfprint and Milan test
suites, stages a `DESTDIR` payload, records its inventory, and publishes
`builds/current` only after verification. Building never changes the system.
A release source archive carries the pinned checkouts under `sources/`, which
the builder uses by default, and records its version in `release.env`.

Distribution packages use the same builder with `--package-root DIR`: the
verified release payload is copied into `DIR` without an inventory, libfprint
moves to the private `<libdir>/libfprint-goodix53x5` directory that only the
daemon loads, and libfprint's development files are dropped. See the
[packaging guide](../packaging/README.md).

Preflight refuses to continue when a destination is owned by a package or
already exists without being recorded by a previous source install. Remove the
conflicting packages first; it never overwrites them.

## Update And Remove

Update by checking out the wanted revision and repeating build and install. The
installer replaces its recorded files, removes files that the new build no
longer ships, and keeps a modified `/etc/fprintd.conf`. Ownership is recorded
before files are copied, so an interrupted install can simply be rerun.

```sh
./uninstall.sh
./scripts/status-milan-stack-local.sh --absent
```

Uninstall deletes recorded files whose contents are unchanged. Files you have
modified are listed and kept, together with the inventory; delete them and rerun
to finish. Shared directories, print state, and the PSK are never removed, and
no packages are reinstalled.

Both operations runtime-mask `fprintd.service` while files change so D-Bus
cannot activate a half-replaced pair, then unmask it. If an install or removal
fails part-way, fprintd stays masked and the script prints what to fix; rerun
it afterwards. A reboot also clears the runtime mask.
